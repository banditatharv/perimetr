#!/usr/bin/env python3
"""
Perimetr - unified CLI for the recon/scan pipeline.

Every stage stays a fully independent script (portScanning.py, serviceScanning.py,
nucleiCombined.py, etc.) - this is a thin dispatcher, not a rewrite. Each
subcommand just builds the right argv for the underlying script and runs it.
`run` chains the stages together for a full engagement, replacing the manual
copy-between-folders workflow with one command.

Usage:
  perimetr sweep -f subnets.txt -o scan_results
  perimetr pingsweep ips.txt -o ping_results
  perimetr portscan -i ips.txt -o portscan_out
  perimetr extract-ports -d portscan_out -s ips.txt -o ip_ports.txt
  perimetr servicescan -i ip_ports.txt -o servicescan_out
  perimetr service-report --scan-dir portscan_out --ips ips.txt -o report.xlsx
  perimetr nuclei --convert-port-scan ip_ports.txt --output-dir nuclei_out
  perimetr sshaudit --mode full --targets ip_ports.txt
  perimetr domaincheck domains.txt
  perimetr run --project acme --scope subnets.txt
"""

import argparse
import importlib
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path

import questionary
from rich import box
from rich.table import Table

import perimetrUI as ui

console = ui.console

Q_STYLE = questionary.Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan bold'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:cyan'),
    ('instruction', 'fg:#858585'),
])


class PerimetrError(Exception):
    """Raised instead of sys.exit() so the interactive menu can catch a failed
    stage and return to the menu instead of killing the whole session."""
    def __init__(self, message, returncode=1):
        super().__init__(message)
        self.returncode = returncode


class Cancelled(Exception):
    """Raised when a user backs out of an interactive prompt (Ctrl+C/Esc)."""

SCRIPT_DIR = Path(__file__).resolve().parent
PY = sys.executable

DEFAULT_STAGES_FROM_SCOPE = ['sweep', 'portscan', 'extract', 'servicescan', 'nuclei']
DEFAULT_STAGES_FROM_IPS = ['portscan', 'extract', 'servicescan', 'nuclei']

# Binaries/packages the various stages shell out to or import - surfaced in the
# environment check so a missing one shows up before a scan fails halfway through.
REQUIRED_BINARIES = ['nmap', 'tmux', 'nuclei', 'ssh-audit']
REQUIRED_MODULES = {
    'colorama': 'colorama', 'rich': 'rich', 'httpx': 'httpx',
    'bs4': 'beautifulsoup4', 'dns': 'dnspython',
    'xlsxwriter': 'xlsxwriter', 'openpyxl': 'openpyxl',
}


def script(name):
    return str(SCRIPT_DIR / name)


def run_step(cmd, label, cwd=None):
    ui.section(label)
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]\n")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        ui.error(f"{label} failed (exit {result.returncode})")
        raise PerimetrError(f"{label} failed", returncode=result.returncode)
    return result


def ip_sort_key(ip):
    try:
        return tuple(int(part) for part in ip.split('.'))
    except ValueError:
        return (999, ip)


def consolidate_ips(sweep_dir, dest):
    """Merge all *_ips_only.txt files from a sweep run into one deduped list."""
    ips = set()
    for f in sorted(Path(sweep_dir).glob('*_ips_only.txt')):
        for line in f.read_text().splitlines():
            line = line.strip()
            if line:
                ips.add(line)
    dest.write_text('\n'.join(sorted(ips, key=ip_sort_key)) + ('\n' if ips else ''))
    ui.success(f"Consolidated {len(ips)} unique IP(s) -> {dest}")


def consolidate_pingsweep_alive(pingsweep_dir, dest):
    """Merge ping_sweep's alive-host outputs into one deduped list for the
    downstream pipeline: plain IPs from responded_ping.txt plus the IPs from
    responded_nmap.txt (lines look like '<ip> - Ports: ...', so take the head).
    Returns the number of alive hosts written."""
    d = Path(pingsweep_dir)
    ips = set()
    ping_file = d / 'responded_ping.txt'
    if ping_file.exists():
        for line in ping_file.read_text().splitlines():
            line = line.strip()
            if line:
                ips.add(line)
    nmap_file = d / 'responded_nmap.txt'
    if nmap_file.exists():
        for line in nmap_file.read_text().splitlines():
            line = line.strip()
            if line:
                ip = line.split(' - ')[0].strip()
                if ip:
                    ips.add(ip)
    dest.write_text('\n'.join(sorted(ips, key=ip_sort_key)) + ('\n' if ips else ''))
    ui.success(f"Ping sweep: {len(ips)} alive host(s) -> {dest}")
    return len(ips)


# ── nmap_suite DB import (connective tissue) ───────────────────────────

SUITE_MODULES = SCRIPT_DIR / 'nmap_suite' / 'modules'


def _load_suite_import(db_path=None):
    """Lazily import the nmap_suite importer module. Returns the module, or
    None if nmap_suite isn't present / fails to load.

    database.py resolves its DB path at import time from NMAP_SUITE_DB, so the
    env var must be set *before* the first import of the importer module."""
    if not SUITE_MODULES.is_dir():
        ui.warn(f"nmap_suite not found at {SUITE_MODULES} - skipping DB import.")
        return None
    if db_path:
        os.environ['NMAP_SUITE_DB'] = str(Path(db_path).resolve())
    if str(SUITE_MODULES) not in sys.path:
        sys.path.insert(0, str(SUITE_MODULES))
    try:
        fi = importlib.import_module('findings_import')
    except Exception as e:
        ui.warn(f"Could not load nmap_suite importer ({e}) - skipping DB import.")
        return None
    fi.ensure_db()
    return fi


def db_import(project, db_path=None, nmap_dir=None, nuclei_dir=None, ssh_file=None):
    """Push stage outputs into the suite DB under a project of the given name.
    Each source is independent and best-effort: a failure on one is warned and
    skipped, never fatal (so a DB hiccup can't lose a completed scan run).
    Returns True if the importer was available."""
    fi = _load_suite_import(db_path)
    if fi is None:
        return False
    pid = fi.get_or_create_project(project)

    if nmap_dir and Path(nmap_dir).is_dir():
        ids = fi.import_multiple_nmap_files(str(nmap_dir), project_id=pid)
        ui.success(f"Imported {len(ids)} nmap host scan(s) -> project '{project}'")

    if nuclei_dir and Path(nuclei_dir).is_dir():
        try:
            sid, n = fi.import_nuclei_results(str(nuclei_dir), project_id=pid)
            ui.success(f"Imported {n} nuclei finding(s) (scan #{sid}) -> project '{project}'")
        except (FileNotFoundError, ValueError) as e:
            ui.warn(f"Nuclei import skipped: {e}")

    if ssh_file and Path(ssh_file).is_file():
        try:
            sid, n = fi.import_ssh_report(str(ssh_file), project_id=pid)
            ui.success(f"Imported {n} ssh finding(s) (scan #{sid}) -> project '{project}'")
        except (FileNotFoundError, ValueError) as e:
            ui.warn(f"SSH import skipped: {e}")

    return True


def safe_db_import(*args, **kwargs):
    """db_import wrapper for the run pipeline: never lets a DB error abort a run."""
    try:
        db_import(*args, **kwargs)
    except Exception as e:
        ui.warn(f"DB import failed ({e}) - scan outputs are still on disk.")


# ── Individual subcommands (thin wrappers) ─────────────────────────────

def cmd_sweep(args):
    cmd = [PY, script('advanced_subnet_sweep.py'), '-f', args.file, '-o', args.output, '-t', str(args.threads)]
    run_step(cmd, "Subnet Sweep")


def cmd_pingsweep(args):
    cmd = [PY, script('ping_sweep.py'), args.input, '-o', args.output,
           '-t', str(args.timeout), '-p', str(args.parallel)]
    if getattr(args, 'no_timestamp', False):
        cmd.append('--no-timestamp')
    run_step(cmd, "Ping Sweep (liveness)")


def cmd_portscan(args):
    cmd = [PY, script('portScanning.py'), '-i', args.input, '-o', args.output, '-t', str(args.threads)]
    run_step(cmd, "Full Port Scan")


def cmd_extract_ports(args):
    cmd = [PY, script('portExtractor.py'), '-d', args.scan_dir, '-s', args.scope, '-o', args.output]
    run_step(cmd, "Port Extraction")


def cmd_servicescan(args):
    cmd = [PY, script('serviceScanning.py'), '-o', args.output, '-t', str(args.threads)]
    if args.input:
        cmd += ['-i', args.input]
    elif args.ip and args.ports:
        cmd += ['--ip', args.ip, '--ports', args.ports]
    else:
        raise PerimetrError("servicescan requires --input or (--ip and --ports)")
    run_step(cmd, "Service/Version Scan")
    if getattr(args, 'project', None):
        safe_db_import(args.project, db_path=args.db, nmap_dir=args.output)


def cmd_service_report(args):
    ips_path = Path(args.ips).resolve()
    out_path = Path(args.output).resolve()
    scan_dir = Path(args.scan_dir).resolve()
    cmd = [PY, script('serviceExtractor.py'), '--ips', str(ips_path), '--out', str(out_path)]
    if args.csv_only:
        cmd.append('--csv-only')
    # serviceExtractor.py looks for <ip>.nmap in its cwd
    run_step(cmd, "Service Scan Report", cwd=str(scan_dir))


def cmd_nuclei(args):
    cmd = [PY, script('nucleiCombined.py')]
    if args.convert_port_scan:
        cmd += ['--convert-port-scan', args.convert_port_scan]
    elif args.input_file:
        cmd += ['--input-file', args.input_file]
    else:
        raise PerimetrError("nuclei requires --convert-port-scan or --input-file")
    cmd += ['--max-concurrent', str(args.max_concurrent)]
    cmd += ['--output-dir', args.output_dir, '--xlsx-output', args.xlsx_output]
    if args.severity:
        cmd += ['--severity', args.severity]
    if args.scan_only:
        cmd.append('--scan-only')
    if args.skip_report:
        cmd.append('--skip-report')
    run_step(cmd, "Nuclei Scan")
    if getattr(args, 'project', None):
        safe_db_import(args.project, db_path=args.db, nuclei_dir=args.output_dir)


def cmd_sshaudit(args):
    cmd = [PY, script('sshWeakCiphersAudit.py'), '--mode', args.mode]
    if args.targets:
        cmd += ['--targets', args.targets]
    if args.input:
        cmd += ['--input', args.input]
    if args.output:
        cmd += ['--output', args.output]
    cmd += ['--timeout', str(args.timeout)]
    run_step(cmd, "SSH Weak Algorithm Audit")


def cmd_domaincheck(args):
    cmd = [PY, script('domainCheckHttpx.py')]
    if args.input_file:
        cmd.append(args.input_file)
    ui.warn("domainCheckHttpx.py still prompts interactively for worker count.")
    subprocess.run(cmd)


def cmd_import(args):
    """Import existing scan/finding outputs into the nmap_suite DB under a
    project. Ad-hoc counterpart to run's auto-import."""
    if not (args.nmap_dir or args.nuclei_dir or args.ssh_file):
        raise PerimetrError("import needs at least one of --nmap-dir / --nuclei-dir / --ssh-file")
    ui.section(f"Import into project '{args.project}'")
    ok = db_import(args.project, db_path=args.db, nmap_dir=args.nmap_dir,
                   nuclei_dir=args.nuclei_dir, ssh_file=args.ssh_file)
    if not ok:
        raise PerimetrError("nmap_suite importer unavailable")


# ── Chained workflow ────────────────────────────────────────────────────

def cmd_run(args):
    if not args.scope and not args.ips:
        raise PerimetrError("run requires --scope <subnets file> or --ips <ip list file>")

    project_dir = Path(args.workdir) / args.project
    project_dir.mkdir(parents=True, exist_ok=True)

    default_stages = DEFAULT_STAGES_FROM_SCOPE if args.scope else DEFAULT_STAGES_FROM_IPS
    stages = args.stages.split(',') if args.stages else default_stages

    ui.banner(f"Perimetr Run: {args.project}", f"Stages: {', '.join(stages)}")
    ui.info(f"Project dir: {project_dir}")

    ips_file = project_dir / 'ips.txt'
    portscan_dir = project_dir / '02_portscan'
    ip_ports_file = project_dir / 'ip_ports.txt'
    servicescan_dir = project_dir / '03_servicescan'
    nuclei_dir = project_dir / '04_nuclei'

    if args.scope:
        if 'sweep' in stages:
            sweep_dir = project_dir / '01_sweep'
            run_step(
                [PY, script('advanced_subnet_sweep.py'), '-f', args.scope, '-o', str(sweep_dir), '-t', str(args.sweep_threads)],
                "Stage 1: Subnet Sweep"
            )
            consolidate_ips(sweep_dir, ips_file)
    else:
        shutil.copy(args.ips, ips_file)
        ui.success(f"Using provided IP list -> {ips_file}")

    if not ips_file.exists() or not ips_file.read_text().strip():
        raise PerimetrError(f"No IPs to scan ({ips_file}). Stopping.")

    # Optional liveness filter: prune dead hosts (and catch ICMP-blockers via
    # the nmap fallback) before the expensive full-port scan. Replaces the
    # working IP list for every downstream stage with only the alive hosts.
    if 'pingsweep' in stages:
        pingsweep_dir = project_dir / '01b_pingsweep'
        run_step(
            [PY, script('ping_sweep.py'), str(ips_file), '-o', str(pingsweep_dir),
             '--no-timestamp', '-t', str(args.pingsweep_timeout), '-p', str(args.pingsweep_threads)],
            "Stage 1b: Ping Sweep (liveness filter)"
        )
        alive_file = project_dir / 'alive_ips.txt'
        if not consolidate_pingsweep_alive(pingsweep_dir, alive_file):
            raise PerimetrError("Ping sweep found no alive hosts - stopping.")
        ips_file = alive_file

    if 'portscan' in stages:
        run_step(
            [PY, script('portScanning.py'), '-i', str(ips_file), '-o', str(portscan_dir), '-t', str(args.portscan_threads)],
            "Stage 2: Full Port Scan"
        )

    if 'extract' in stages:
        run_step(
            [PY, script('portExtractor.py'), '-d', str(portscan_dir), '-s', str(ips_file), '-o', str(ip_ports_file)],
            "Stage 3: Port Extraction"
        )

    if 'servicescan' in stages:
        if not ip_ports_file.exists():
            raise PerimetrError(f"{ip_ports_file} not found - run the 'extract' stage first")
        run_step(
            [PY, script('serviceScanning.py'), '-i', str(ip_ports_file), '-o', str(servicescan_dir), '-t', str(args.service_threads)],
            "Stage 4a: Service/Version Scan"
        )

    if 'nuclei' in stages:
        if not ip_ports_file.exists():
            raise PerimetrError(f"{ip_ports_file} not found - run the 'extract' stage first")
        xlsx = nuclei_dir / 'nuclei-report.xlsx'
        cmd = [
            PY, script('nucleiCombined.py'),
            '--convert-port-scan', str(ip_ports_file),
            '--max-concurrent', str(args.nuclei_concurrent),
            '--output-dir', str(nuclei_dir),
            '--xlsx-output', str(xlsx),
        ]
        if args.severity:
            cmd += ['--severity', args.severity]
        run_step(cmd, "Stage 4b: Nuclei Scan")

    # ── Auto-import into the nmap_suite DB so the engagement lands in the
    #    dashboard with no manual copy/import step. Uses the project name as
    #    the DB project. Best-effort: never aborts a completed run.
    if not args.no_db_import:
        nmap_src = servicescan_dir if ('servicescan' in stages and servicescan_dir.is_dir()) else None
        nuclei_src = nuclei_dir if ('nuclei' in stages and nuclei_dir.is_dir()) else None
        if nmap_src or nuclei_src:
            ui.section("Importing results into nmap_suite")
            safe_db_import(args.project, db_path=args.db,
                           nmap_dir=nmap_src, nuclei_dir=nuclei_src)

    ui.summary("Run Complete", [
        ("Project dir", project_dir),
        ("IPs", ips_file),
        ("Full port scan", f"{portscan_dir}/"),
        ("ip:ports list", ip_ports_file),
        ("Service scan", f"{servicescan_dir}/"),
        ("Nuclei results", f"{nuclei_dir}/"),
    ])


# ── Argument parser ──────────────────────────────────────────────────

def print_banner():
    ui.banner("P E R I M E T R", "Unified Recon & Scan Pipeline")


def check_environment():
    """Surface missing tools/packages up front instead of failing mid-scan."""
    table = Table(title="Environment Check", box=box.SIMPLE_HEAVY, header_style="bold white", title_justify="left")
    table.add_column("Dependency")
    table.add_column("Kind", style="dim")
    table.add_column("Status")

    missing = 0
    for binary in REQUIRED_BINARIES:
        path = shutil.which(binary)
        if path:
            table.add_row(binary, "binary", f"[bold green]OK[/bold green]  [dim]{path}[/dim]")
        else:
            missing += 1
            table.add_row(binary, "binary", "[bold red]MISSING[/bold red]")

    for module, pip_name in REQUIRED_MODULES.items():
        try:
            importlib.import_module(module)
            table.add_row(pip_name, "python pkg", "[bold green]OK[/bold green]")
        except ImportError:
            missing += 1
            table.add_row(pip_name, "python pkg", f"[bold red]MISSING[/bold red]  [dim]pip install {pip_name}[/dim]")

    console.print(table)
    if missing:
        console.print(f"[yellow]{missing} dependency issue(s) found - affected stages will fail until resolved.[/yellow]\n")
    else:
        console.print("[green]All dependencies present.[/green]\n")


def print_menu(sub_action):
    table = Table(title="Commands", box=box.SIMPLE_HEAVY, header_style="bold white", title_justify="left")
    table.add_column("Command", style="bold green")
    table.add_column("Description")
    for choice_action in sub_action._choices_actions:
        table.add_row(choice_action.dest, choice_action.help)
    console.print(table)
    console.print("\n[white]Run 'perimetr <command> -h' for command-specific options.[/white]")
    console.print("[white]Example: [bold]perimetr run --project acme --scope subnets.txt[/bold][/white]\n")


# ── Interactive menu ─────────────────────────────────────────────────

def ask(prompt):
    """questionary returns None on Ctrl+C/Esc - normalize that into a Cancelled."""
    result = prompt.ask()
    if result is None:
        raise Cancelled()
    return result


def prompt_sweep():
    file = ask(questionary.path("Subnets file:", style=Q_STYLE))
    output = ask(questionary.text("Output directory:", default="scan_results", style=Q_STYLE))
    threads = ask(questionary.text("Threads:", default="50", style=Q_STYLE))
    return types.SimpleNamespace(file=file, output=output, threads=int(threads))


def prompt_pingsweep():
    input_ = ask(questionary.path("IP list file:", style=Q_STYLE))
    output = ask(questionary.text("Output directory:", default="ping_results", style=Q_STYLE))
    timeout = ask(questionary.text("Ping timeout (s):", default="1", style=Q_STYLE))
    parallel = ask(questionary.text("Parallel pings:", default="10", style=Q_STYLE))
    return types.SimpleNamespace(input=input_, output=output,
                                 timeout=int(timeout), parallel=int(parallel),
                                 no_timestamp=False)


def prompt_portscan():
    input_ = ask(questionary.path("IP list file:", style=Q_STYLE))
    output = ask(questionary.text("Output directory:", default="portscan_out", style=Q_STYLE))
    threads = ask(questionary.text("Concurrent tmux sessions:", default="3", style=Q_STYLE))
    return types.SimpleNamespace(input=input_, output=output, threads=int(threads))


def prompt_extract_ports():
    scan_dir = ask(questionary.path("Scan directory (.gnmap files):", style=Q_STYLE))
    scope = ask(questionary.path("Scope file (IP list):", style=Q_STYLE))
    output = ask(questionary.text("Output file:", default="ip_ports.txt", style=Q_STYLE))
    return types.SimpleNamespace(scan_dir=scan_dir, scope=scope, output=output)


def prompt_servicescan():
    mode = ask(questionary.select("Target input:", choices=["ip:ports file", "single IP"], style=Q_STYLE))
    ns = types.SimpleNamespace(input=None, ip=None, ports=None, output=None, threads=3)
    if mode == "ip:ports file":
        ns.input = ask(questionary.path("ip:ports file:", style=Q_STYLE))
    else:
        ns.ip = ask(questionary.text("Target IP:", style=Q_STYLE))
        ns.ports = ask(questionary.text("Ports (comma separated):", style=Q_STYLE))
    ns.output = ask(questionary.text("Output directory:", default="servicescan_out", style=Q_STYLE))
    ns.threads = int(ask(questionary.text("Concurrent tmux sessions:", default="3", style=Q_STYLE)))
    return ns


def prompt_service_report():
    scan_dir = ask(questionary.path("Directory containing <ip>.nmap files:", style=Q_STYLE))
    ips = ask(questionary.path("IPs file:", style=Q_STYLE))
    output = ask(questionary.text("Output xlsx file:", default="nmap_report.xlsx", style=Q_STYLE))
    csv_only = ask(questionary.confirm("CSV only?", default=False, style=Q_STYLE))
    return types.SimpleNamespace(scan_dir=scan_dir, ips=ips, output=output, csv_only=csv_only)


def prompt_nuclei():
    mode = ask(questionary.select(
        "Target input:",
        choices=["Convert port-scan output (ip:port1,port2)", "Already nuclei-formatted (ip:port)"],
        style=Q_STYLE,
    ))
    ns = types.SimpleNamespace(convert_port_scan=None, input_file=None, max_concurrent=5,
                                output_dir="Nuclei-results", xlsx_output="nuclei-report.xlsx",
                                severity=None, scan_only=False, skip_report=False)
    if mode.startswith("Convert"):
        ns.convert_port_scan = ask(questionary.path("Port scan file:", style=Q_STYLE))
    else:
        ns.input_file = ask(questionary.path("Nuclei targets file:", style=Q_STYLE))
    ns.max_concurrent = int(ask(questionary.text("Max concurrent tmux sessions:", default="5", style=Q_STYLE)))
    ns.output_dir = ask(questionary.text("Nuclei results directory:", default="Nuclei-results", style=Q_STYLE))
    ns.xlsx_output = ask(questionary.text("XLSX report path:", default="nuclei-report.xlsx", style=Q_STYLE))
    sev = ask(questionary.text("Severity filter (comma-separated, blank = all):", default="", style=Q_STYLE))
    ns.severity = sev or None
    return ns


def prompt_sshaudit():
    mode = ask(questionary.select("Mode:", choices=["full (scan + parse)", "parse (existing output file)"], style=Q_STYLE))
    ns = types.SimpleNamespace(mode=None, targets=None, input=None, output=None, timeout=15)
    if mode.startswith("full"):
        ns.mode = "full"
        ns.targets = ask(questionary.path("Targets file:", style=Q_STYLE))
    else:
        ns.mode = "parse"
        ns.input = ask(questionary.path("Existing ssh-audit output file:", style=Q_STYLE))
    out = ask(questionary.text("Output report file (blank = auto timestamped):", default="", style=Q_STYLE))
    ns.output = out or None
    ns.timeout = int(ask(questionary.text("Timeout per target (s):", default="15", style=Q_STYLE)))
    return ns


def prompt_domaincheck():
    input_file = ask(questionary.text("Domains file (blank = prompt inside script):", default="", style=Q_STYLE))
    return types.SimpleNamespace(input_file=input_file or None)


STAGE_PROMPTS = {
    "sweep": (prompt_sweep, cmd_sweep),
    "pingsweep": (prompt_pingsweep, cmd_pingsweep),
    "portscan": (prompt_portscan, cmd_portscan),
    "extract-ports": (prompt_extract_ports, cmd_extract_ports),
    "servicescan": (prompt_servicescan, cmd_servicescan),
    "service-report": (prompt_service_report, cmd_service_report),
    "nuclei": (prompt_nuclei, cmd_nuclei),
    "sshaudit": (prompt_sshaudit, cmd_sshaudit),
    "domaincheck": (prompt_domaincheck, cmd_domaincheck),
}

PIPELINE_ORDER = ['sweep', 'pingsweep', 'portscan', 'extract', 'servicescan', 'nuclei']
PIPELINE_LABELS = {
    'sweep': 'Subnet Sweep',
    'pingsweep': 'Ping Sweep (liveness)',
    'portscan': 'Full Port Scan',
    'extract': 'Extract Ports',
    'servicescan': 'Service/Version Scan',
    'nuclei': 'Nuclei Scan',
}


def run_pipeline_wizard():
    """Pick a subset of the fixed pipeline order (e.g. skip sweep, start at
    portscan) and run it via the same cmd_run() the CLI 'run' command uses."""
    # sweep is the alternate starting point (subnets vs. an existing IP list);
    # pingsweep is an opt-in liveness filter - both start unticked.
    choices = [
        questionary.Choice(PIPELINE_LABELS[s], value=s, checked=(s not in ('sweep', 'pingsweep')))
        for s in PIPELINE_ORDER
    ]
    selected = ask(questionary.checkbox(
        "Select stages to run (fixed order, untick to skip a stage):",
        choices=choices, style=Q_STYLE,
    ))
    if not selected:
        ui.warn("No stages selected - cancelled.")
        return
    stages = [s for s in PIPELINE_ORDER if s in selected]

    project = ask(questionary.text("Project name:", style=Q_STYLE))
    workdir = ask(questionary.text("Working directory:", default=".", style=Q_STYLE))
    db_import_on = ask(questionary.confirm("Import results into the nmap_suite dashboard when done?",
                                           default=True, style=Q_STYLE))

    ns = types.SimpleNamespace(
        scope=None, ips=None, project=project, workdir=workdir, stages=','.join(stages),
        sweep_threads=50, pingsweep_threads=10, pingsweep_timeout=1,
        portscan_threads=3, service_threads=3, nuclei_concurrent=5, severity=None,
        no_db_import=(not db_import_on), db=None,
    )

    if 'sweep' in stages:
        ns.scope = ask(questionary.path("Subnets file:", style=Q_STYLE))
    else:
        ns.ips = ask(questionary.path("Existing IP list file:", style=Q_STYLE))

    if 'nuclei' in stages:
        sev = ask(questionary.text("Nuclei severity filter (blank = all):", default="", style=Q_STYLE))
        ns.severity = sev or None

    ui.info(f"Pipeline: {' -> '.join(PIPELINE_LABELS[s] for s in stages)}")
    cmd_run(ns)


MENU_ITEMS = [
    ("Run Pipeline (choose stages)", "pipeline"),
    ("Subnet Sweep", "sweep"),
    ("Ping Sweep (liveness)", "pingsweep"),
    ("Full Port Scan", "portscan"),
    ("Extract Ports", "extract-ports"),
    ("Service/Version Scan", "servicescan"),
    ("Service Scan Report", "service-report"),
    ("Nuclei Scan", "nuclei"),
    ("SSH Weak Algorithm Audit", "sshaudit"),
    ("Domain Check", "domaincheck"),
    ("Environment Check", "envcheck"),
    ("Exit", "exit"),
]


def interactive_menu():
    label_to_key = dict(MENU_ITEMS)
    while True:
        console.clear()
        print_banner()
        try:
            choice = ask(questionary.select(
                "Select an action:",
                choices=[label for label, _ in MENU_ITEMS],
                style=Q_STYLE,
                qmark=">",
            ))
        except Cancelled:
            break

        key = label_to_key[choice]
        if key == "exit":
            break

        console.print()
        try:
            if key == "envcheck":
                check_environment()
            elif key == "pipeline":
                run_pipeline_wizard()
            else:
                prompt_fn, cmd_fn = STAGE_PROMPTS[key]
                ns = prompt_fn()
                cmd_fn(ns)
        except Cancelled:
            ui.warn("Cancelled.")
        except PerimetrError as e:
            ui.error(str(e))

        questionary.press_any_key_to_continue("\nPress any key to return to the menu...").ask()


def build_parser():
    parser = argparse.ArgumentParser(prog='perimetr', description='Unified recon/scan pipeline CLI')
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('sweep', help='Discover alive hosts in subnets')
    p.add_argument('-f', '--file', required=True)
    p.add_argument('-o', '--output', default='scan_results')
    p.add_argument('-t', '--threads', type=int, default=50)
    p.set_defaults(func=cmd_sweep)

    p = sub.add_parser('pingsweep', help='ICMP ping sweep of an IP list (+ nmap fallback for hosts that block ICMP)')
    p.add_argument('input', help='File of IP addresses (one per line)')
    p.add_argument('-o', '--output', default='ping_results')
    p.add_argument('-t', '--timeout', type=int, default=1, help='Ping timeout in seconds (default: 1)')
    p.add_argument('-p', '--parallel', type=int, default=10, help='Parallel pings (default: 10)')
    p.add_argument('--no-timestamp', action='store_true',
                   help='Write directly to -o instead of a timestamped scan_<ts>/ subfolder')
    p.set_defaults(func=cmd_pingsweep)

    p = sub.add_parser('portscan', help='Full-port nmap scan via tmux')
    p.add_argument('-i', '--input', required=True)
    p.add_argument('-o', '--output', required=True)
    p.add_argument('-t', '--threads', type=int, default=3)
    p.set_defaults(func=cmd_portscan)

    p = sub.add_parser('extract-ports', help='Build ip:ports list from .gnmap output')
    p.add_argument('-d', '--scan-dir', required=True)
    p.add_argument('-s', '--scope', required=True)
    p.add_argument('-o', '--output', default='ip_ports.txt')
    p.set_defaults(func=cmd_extract_ports)

    p = sub.add_parser('servicescan', help='Targeted deep nmap scan on discovered ports')
    p.add_argument('-i', '--input', help='ip:ports file')
    p.add_argument('--ip', help='Single IP')
    p.add_argument('--ports', help='Ports for single IP (comma separated)')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('-t', '--threads', type=int, default=3)
    p.add_argument('--project', help='If set, auto-import the resulting .nmap files into the nmap_suite DB under this project')
    p.add_argument('--db', help='Path to nmap_suite DB (default: nmap_suite/data/suite.db)')
    p.set_defaults(func=cmd_servicescan)

    p = sub.add_parser('service-report', help='Parse .nmap files into an xlsx/csv report')
    p.add_argument('--scan-dir', required=True, help='Directory containing <ip>.nmap files')
    p.add_argument('--ips', required=True, help='File listing IPs to include')
    p.add_argument('-o', '--output', default='nmap_report.xlsx')
    p.add_argument('--csv-only', action='store_true')
    p.set_defaults(func=cmd_service_report)

    p = sub.add_parser('nuclei', help='Nuclei scan + xlsx findings report')
    p.add_argument('--convert-port-scan', help='ip:port1,port2 formatted file (e.g. portExtractor.py output)')
    p.add_argument('--input-file', help='Already nuclei-formatted ip:port targets file')
    p.add_argument('--max-concurrent', type=int, default=5)
    p.add_argument('--output-dir', default='Nuclei-results')
    p.add_argument('--xlsx-output', default='nuclei-report.xlsx')
    p.add_argument('--severity', help='Comma-separated severity filter, e.g. high,critical')
    p.add_argument('--scan-only', action='store_true')
    p.add_argument('--skip-report', action='store_true')
    p.add_argument('--project', help='If set, auto-import the nuclei .md findings into the nmap_suite DB under this project')
    p.add_argument('--db', help='Path to nmap_suite DB (default: nmap_suite/data/suite.db)')
    p.set_defaults(func=cmd_nuclei)

    p = sub.add_parser('sshaudit', help='ssh-audit weak algorithm scan/parse')
    p.add_argument('--mode', required=True, choices=['full', 'parse'])
    p.add_argument('--targets', help='Targets file (required for --mode full)')
    p.add_argument('--input', help='Existing ssh-audit output file (required for --mode parse)')
    p.add_argument('--output')
    p.add_argument('--timeout', type=int, default=15)
    p.set_defaults(func=cmd_sshaudit)

    p = sub.add_parser('domaincheck', help='Domain liveness + tech detection (interactive)')
    p.add_argument('input_file', nargs='?')
    p.set_defaults(func=cmd_domaincheck)

    p = sub.add_parser('run', help='Chain sweep -> [pingsweep] -> portscan -> extract -> servicescan -> nuclei')
    start = p.add_mutually_exclusive_group(required=False)
    start.add_argument('--scope', help='Subnets file (starts from the sweep stage)')
    start.add_argument('--ips', help='Existing IP list file (skips the sweep stage)')
    p.add_argument('--project', required=True, help='Project name; results go in <workdir>/<project>/')
    p.add_argument('--workdir', default='.', help='Base directory for project folders (default: current dir)')
    p.add_argument('--stages', help='Comma-separated stage subset, e.g. pingsweep,portscan,extract,servicescan (pingsweep is opt-in, not in the default chain)')
    p.add_argument('--sweep-threads', type=int, default=50)
    p.add_argument('--pingsweep-threads', type=int, default=10, help='Parallel pings for the optional pingsweep stage')
    p.add_argument('--pingsweep-timeout', type=int, default=1, help='Ping timeout (s) for the optional pingsweep stage')
    p.add_argument('--portscan-threads', type=int, default=3)
    p.add_argument('--service-threads', type=int, default=3)
    p.add_argument('--nuclei-concurrent', type=int, default=5)
    p.add_argument('--severity', help='Comma-separated nuclei severity filter')
    p.add_argument('--no-db-import', action='store_true', help='Skip auto-importing results into the nmap_suite DB')
    p.add_argument('--db', help='Path to nmap_suite DB (default: nmap_suite/data/suite.db)')
    p.set_defaults(func=cmd_run)

    p = sub.add_parser('import', help='Import existing scan/finding outputs into the nmap_suite DB')
    p.add_argument('--project', required=True, help='DB project name (created if absent)')
    p.add_argument('--nmap-dir', help='Directory of <ip>.nmap files (deep service scan output)')
    p.add_argument('--nuclei-dir', help='Directory of nuclei .md findings')
    p.add_argument('--ssh-file', help='Raw ssh-audit output file (the *_RAW.txt / --mode parse input)')
    p.add_argument('--db', help='Path to nmap_suite DB (default: nmap_suite/data/suite.db)')
    p.set_defaults(func=cmd_import)

    return parser, sub


def main():
    parser, sub = build_parser()

    if len(sys.argv) == 1:
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                interactive_menu()
            except Exception as e:
                ui.error(f"Interactive menu unavailable in this terminal ({e})")
                ui.info("Falling back to the static command reference.")
                print_banner()
                check_environment()
                print_menu(sub)
        else:
            print_banner()
            check_environment()
            print_menu(sub)
        sys.exit(0)

    if sys.argv[1] in ('-h', '--help'):
        print_banner()
        check_environment()
        print_menu(sub)
        sys.exit(0)

    args = parser.parse_args()
    try:
        args.func(args)
    except PerimetrError as e:
        ui.error(str(e))
        sys.exit(e.returncode)


if __name__ == '__main__':
    main()
