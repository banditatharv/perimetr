# Perimetr

**A unified recon & scanning toolkit for network/infrastructure penetration testing.**

Perimetr chains the day-to-day scanning steps of a subnet-based engagement into
a single pipeline — host discovery → full port scan → service/version scan →
vulnerability scan — and feeds every result into a self-hosted **nmap_suite**
web dashboard for tracking findings, ports, and notes across a project.

Each stage is also a fully standalone script, so you can run any single step on
its own or drive the whole chain with one command.

> ⚠️ **For authorized security testing only.** Only scan hosts and networks you
> have explicit written permission to test.

---

## Features

- **One pipeline, one command** — `perimetr run` takes a subnet list (or an IP
  list) and runs discovery, port scanning, service scanning, and nuclei end to
  end, dropping each stage's output into an organized project folder.
- **Every stage is standalone** — `sweep`, `portscan`, `extract-ports`,
  `servicescan`, `service-report`, `nuclei`, `sshaudit`, `domaincheck`.
- **Parallel scanning via tmux** — port and service scans fan out across
  concurrent tmux sessions.
- **Interactive menu** — run `perimetr` with no arguments for an arrow-key,
  guided menu (with an environment check that flags missing tools up front).
- **nmap_suite dashboard** — a Flask app that imports `.nmap` scans and tracks
  hosts, ports, an auto-fingerprint engine, manual findings, notes, and
  projects in SQLite.
- **Findings land in the dashboard automatically** — `perimetr run` imports its
  nmap, nuclei, and ssh-audit results into nmap_suite, so a finished run is
  already browsable per-project (no manual copy/import step).
- **Consistent, colored output** — every script shares one `rich`-based UI
  module (`perimetrUI.py`).

---

## The pipeline

```
 subnets.txt
     │  advanced_subnet_sweep.py        (sweep)
     ▼
 alive IPs ──► portScanning.py          (portscan)   full -p- nmap via tmux
     │
     │  portExtractor.py                (extract-ports)  .gnmap → ip:ports list
     ▼
 ip_ports.txt
     ├──► serviceScanning.py            (servicescan)  deep -sSCV -A scan
     │        └► serviceExtractor.py     (service-report) → xlsx/csv
     └──► nucleiCombined.py             (nuclei)       nuclei scan + xlsx report
                     │
                     ▼
              nmap_suite dashboard   (auto-import: nmap + nuclei + ssh findings)
```

Standalone, run as needed (not part of the subnet chain):
`domainCheckHttpx.py` (domain liveness + tech detection) and
`sshWeakCiphersAudit.py` (ssh-audit wrapper).

---

## Requirements

**Environment:** Linux / Kali / WSL. The scanners shell out to external tools
and use `tmux` + `sudo nmap`, so a POSIX shell is assumed (not Windows-native).

**External tools** (must be on `PATH`):

| Tool | Used by |
|------|---------|
| [`nmap`](https://nmap.org/) | portscan, servicescan |
| [`tmux`](https://github.com/tmux/tmux) | parallel port/service/nuclei scans |
| [`nuclei`](https://github.com/projectdiscovery/nuclei) | nuclei stage |
| [`ssh-audit`](https://github.com/jtesta/ssh-audit) | sshaudit stage |

**Python:** 3.8+. Install the packages with:

```bash
pip install -r requirements.txt
```

Running `perimetr` (or the interactive menu → *Environment Check*) prints a
table showing which of the above tools/packages are present or missing before
you start a scan.

---

## Usage

### Interactive menu

```bash
python3 perimetr.py
```

Launches a guided menu: pick a single stage (with prompts for each option),
run the **full pipeline** (choose which stages to include), or run the
environment check. In a non-interactive shell it prints a static command
reference instead.

### Full pipeline

```bash
# start from subnets (runs the sweep first)
python3 perimetr.py run --project acme --scope subnets.txt

# start from an existing IP list (skips the sweep)
python3 perimetr.py run --project acme --ips ips.txt

# only some stages
python3 perimetr.py run --project acme --ips ips.txt --stages portscan,extract,servicescan
```

Results are written to `./acme/` (`01_sweep/`, `ips.txt`, `02_portscan/`,
`ip_ports.txt`, `03_servicescan/`, `04_nuclei/`). At the end, the servicescan
and nuclei outputs are auto-imported into the nmap_suite DB under a project
named `acme`. Use `--no-db-import` to skip that, or `--db PATH` to point at a
specific database.

### Individual stages

```bash
python3 perimetr.py sweep          -f subnets.txt -o scan_results
python3 perimetr.py portscan       -i ips.txt -o portscan_out
python3 perimetr.py extract-ports  -d portscan_out -s ips.txt -o ip_ports.txt
python3 perimetr.py servicescan    -i ip_ports.txt -o servicescan_out
python3 perimetr.py service-report --scan-dir servicescan_out --ips ips.txt -o report.xlsx
python3 perimetr.py nuclei         --convert-port-scan ip_ports.txt --output-dir nuclei_out
python3 perimetr.py sshaudit       --mode full --targets ip_ports.txt
python3 perimetr.py domaincheck    domains.txt
```

Each subcommand maps to a standalone script — run `perimetr <command> -h` for
its full options.

### Importing results into the dashboard

`run` imports automatically, but you can also import existing output any time:

```bash
python3 perimetr.py import --project acme \
  --nmap-dir servicescan_out \
  --nuclei-dir nuclei_out \
  --ssh-file weak_algorithms_RAW.txt
```

---

## nmap_suite dashboard

A self-hosted Flask app for tracking an engagement's results.

```bash
cd nmap_suite
python3 app.py            # then open http://localhost:5000
```

It provides:

- **Scans / Hosts / Ports** — import `.nmap` files (upload or point at a folder).
- **Auto-findings** — a built-in fingerprint engine (plus custom rules you can
  add in the UI).
- **Nuclei & SSH Audit views** — imported findings, filterable and grouped per
  scan/project.
- **Manual findings & notes** — document vulns (severity, status, impact,
  evidence) and keep per-host/scan notes.
- **Projects & Service Map** — group scans and browse services across all hosts.

The SQLite database and imported scans are created under `nmap_suite/data/` and
`nmap_suite/scans/` at runtime (git-ignored).

---

## Repository layout

```
perimetr.py            Unified CLI entrypoint (subcommands, `run`, `import`, menu)
perimetrUI.py          Shared rich-based output module used by every script
advanced_subnet_sweep.py   Subnet → alive IPs (ICMP/TCP/ARP, no nmap needed)
portScanning.py        Full-port nmap scan via tmux
portExtractor.py       .gnmap → ip:ports list
serviceScanning.py     Targeted deep nmap (-sSCV -A) scan
serviceExtractor.py    Parse .nmap files → merged xlsx/csv report
nucleiCombined.py      Nuclei parallel scan + auto xlsx report
sshWeakCiphersAudit.py ssh-audit wrapper + weak-algorithm report
domainCheckHttpx.py    Domain liveness + tech/title fingerprinting
requirements.txt       Python dependencies

nmap_suite/            Flask dashboard (app + SQLite + Jinja templates)
files/                 Standalone nmap-based prototype scripts + docs (self-contained)
```

---

## Notes

- Service/port scans run `sudo nmap`; make sure the runtime user can `sudo`.
- Scan output, reports, the nmap_suite database, and secret keys are all
  git-ignored — the repo ships code only, not engagement data.
- `perimetr.py` and the underlying scripts are decoupled: every stage remains
  independently runnable, so you can drop into any single tool without the CLI.
