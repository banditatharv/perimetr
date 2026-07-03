#!/usr/bin/env python3
"""
Nuclei Parallel Scanner + XLSX Report Generator
Unified workflow: Scan targets concurrently via tmux, then auto-generate structured Excel report.
"""

import argparse
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from queue import Queue

# ─────────────────────────────────────────────────────────────
# Dependency Check
# ─────────────────────────────────────────────────────────────
import perimetrUI as ui

# Soft import: xlsxwriter is only needed for report generation (write_xlsx).
# Keeping it optional lets other tools reuse this module's parser functions
# (parse_nuclei_file, etc.) without xlsxwriter installed.
try:
    import xlsxwriter
except ImportError:
    xlsxwriter = None

# ─────────────────────────────────────────────────────────────
# Global Tracking & Signal Handling
# ─────────────────────────────────────────────────────────────
tmux_sessions = []

def cleanup_tmux_sessions(sig=None, frame=None):
    ui.warn("Scan interrupted! Cleaning up tmux sessions...")
    for session in tmux_sessions:
        subprocess.run(
            ["tmux", "kill-session", "-t", session],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        ui.info(f"Killed: {session}")
    sys.exit(1)

# Note: the SIGINT handler is registered inside main() rather than at import
# time. signal.signal() only works in the main thread, so registering it at
# module load would crash if this module is imported from a worker thread
# (e.g. a Flask request handler doing a findings import).

# ─────────────────────────────────────────────────────────────
# SCANNER FUNCTIONS (Original Logic Preserved)
# ─────────────────────────────────────────────────────────────

def convert_port_scan_to_nuclei(input_file):
    output_file = "nuclei_scope.txt"
    output_lines = []
    unique_ips = set()

    ui.info("Converting port scan output to nuclei format...")
    ui.info(f"Input file: {input_file}")

    try:
        with open(input_file, "r") as infile:
            for line in infile:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                ip, ports = line.split(":", 1)
                ports = ports.split(",")
                unique_ips.add(ip)
                for port in ports:
                    port = port.strip()
                    if port:
                        output_lines.append(f"{ip}:{port}")
    except FileNotFoundError:
        ui.error(f"File '{input_file}' not found.")
        return None

    with open(output_file, "w") as outfile:
        for line in output_lines:
            outfile.write(line + "\n")

    ui.success("Conversion complete!")
    ui.info(f"Original IPs: {len(unique_ips)}")
    ui.info(f"Total IP:Port combinations: {len(output_lines)}")
    ui.success(f"Saved to: {output_file}")
    return output_file


def read_targets_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
        return targets
    except FileNotFoundError:
        ui.error(f"File not found: {file_path}")
        sys.exit(1)


def sanitize_session_name(target):
    return target.replace(':', '-').replace('.', '-')


def create_tmux_session(session_name, target, log_file):
    try:
        subprocess.run(['tmux', 'new-session', '-d', '-s', session_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # send-keys types this line into the session's shell, so the (untrusted)
        # target is shell-quoted to keep it a single nuclei -u argument and
        # prevent command injection via a crafted target string.
        nuclei_command = f'nuclei -u {shlex.quote(target)} -v -me Nuclei-results && exit'
        subprocess.run(['tmux', 'send-keys', '-t', session_name, nuclei_command, 'C-m'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tmux_sessions.append(session_name)
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Started scan on {target} in tmux session {session_name}\n")
        ui.success(f"Started scan on {target} (session: {session_name})")
        return True
    except subprocess.CalledProcessError as e:
        ui.error(f"Failed to start session {session_name}: {e}")
        return False


def kill_tmux_session(session_name, log_file, target):
    try:
        subprocess.run(['tmux', 'kill-session', '-t', session_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if session_name in tmux_sessions:
            tmux_sessions.remove(session_name)
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Completed scan on {target} in tmux session {session_name}\n")
        ui.success(f"Completed scan on {target}")
    except subprocess.CalledProcessError:
        pass


def is_session_active(session_name):
    try:
        result = subprocess.run(['tmux', 'has-session', '-t', session_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False


def run_parallel_scan(targets, max_concurrent_sessions, log_file):
    target_queue = Queue()
    for target in targets:
        target_queue.put(target)

    running_sessions = {}
    completed_count = 0
    failed_count = 0

    ui.info(f"Starting parallel scan with {max_concurrent_sessions} concurrent sessions")
    ui.info(f"Total targets to scan: {len(targets)}")
    ui.success(f"Starting initial batch of {min(max_concurrent_sessions, len(targets))} sessions...")

    while not target_queue.empty() or running_sessions:
        while not target_queue.empty() and len(running_sessions) < max_concurrent_sessions:
            target = target_queue.get()
            session_name = sanitize_session_name(target)
            if create_tmux_session(session_name, target, log_file):
                running_sessions[session_name] = target
            else:
                failed_count += 1

        time.sleep(5)
        for session_name, target in list(running_sessions.items()):
            if not is_session_active(session_name):
                kill_tmux_session(session_name, log_file, target)
                del running_sessions[session_name]
                completed_count += 1

        total_processed = completed_count + failed_count
        percentage = (total_processed / len(targets) * 100) if targets else 0
        print(f"\r[*] Progress: {total_processed}/{len(targets)} "
              f"({percentage:.1f}%) | Active: {len(running_sessions)} | "
              f"Completed: {completed_count} | Failed: {failed_count}", end='', flush=True)

    print()
    return completed_count, failed_count


def print_summary(completed, failed, total_targets, log_file, start_time, end_time):
    success_rate = f"{completed/total_targets*100:.1f}%" if total_targets > 0 else "N/A"
    ui.summary("Scan Summary", [
        ("Total targets", total_targets),
        ("Successfully scanned", completed),
        ("Failed", failed),
        ("Success rate", success_rate),
        ("Duration", end_time - start_time),
        ("Log file", log_file),
    ])


# ─────────────────────────────────────────────────────────────
# REPORT GENERATOR FUNCTIONS (Original Logic Preserved)
# ─────────────────────────────────────────────────────────────

def extract_template_prefixes(filenames):
    prefixes = set()
    for fname in filenames:
        if not fname.endswith('.md'): continue
        name = fname[:-3]
        parts = name.split('-')
        prefixes.add('-'.join(parts[:2]) if len(parts) >= 2 else parts[0])
    return sorted(prefixes, key=len, reverse=True)


def match_template_prefix(filename, prefixes):
    name = Path(filename).stem
    for prefix in prefixes:
        if name.startswith(prefix + '-'): return prefix
    return None


def extract_domain(filename, template_prefix):
    name = Path(filename).stem
    remainder = name[len(template_prefix) + 1:] if name.startswith(template_prefix + '-') else name
    uuid_pattern = r'-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
    return re.sub(uuid_pattern, '', remainder, flags=re.IGNORECASE).strip('-')


def parse_metadata_table(content):
    metadata = {}
    lines = content.split('\n')
    in_table = False
    for line in lines:
        if '| Key | Value |' in line: in_table = True; continue
        if in_table:
            if line.strip() == '' or line.strip().startswith('**'): break
            match = re.match(r'\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                if key == 'Description': value = re.sub(r'<[^>]+>', '', value)
                metadata[key] = value
    return metadata


def extract_curl_command(content):
    curl_marker = '**CURL command**'
    if curl_marker not in content: return 'N/A'
    after = content[content.find(curl_marker) + len(curl_marker):]
    sh_block = re.search(r'```sh\s*\n(.*?)```', after, re.DOTALL)
    if sh_block: return sh_block.group(1).strip()
    any_block = re.search(r'```\s*\n(.*?)```', after, re.DOTALL)
    return any_block.group(1).strip() if any_block else 'N/A'


def parse_nuclei_file(filepath, template_prefixes):
    filename = os.path.basename(filepath)
    template = match_template_prefix(filename, template_prefixes)
    if not template:
        parts = Path(filename).stem.split('-')
        template = '-'.join(parts[:2]) if len(parts) >= 2 else parts[0]
        ui.warn(f"No prefix match for {filename}, using fallback: {template}")

    domain = extract_domain(filename, template)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        ui.error(f"Error reading {filepath}: {e}")
        return None
    
    metadata = parse_metadata_table(content)
    return {
        'template_name': template, 'target_domain': domain,
        'severity': metadata.get('Severity', 'N/A'), 'description': metadata.get('Description', 'N/A'),
        'tags': metadata.get('Tags', 'N/A'), 'cvss_score': metadata.get('CVSS-Score', 'N/A'),
        'cwe_id': metadata.get('CWE-ID', 'N/A'), 'curl_command': extract_curl_command(content),
        'source_file': filename
    }


def write_xlsx(rows, output_path):
    if xlsxwriter is None:
        ui.error("Missing dependency: xlsxwriter")
        ui.info("Install with: pip install -r requirements.txt")
        sys.exit(1)
    workbook = xlsxwriter.Workbook(output_path)
    worksheet = workbook.add_worksheet('Nuclei Findings')
    header_fmt = workbook.add_format({'bold': True, 'bg_color': '#4472C4', 'font_color': 'white', 'border': 1})
    cell_fmt = workbook.add_format({'border': 1, 'text_wrap': True})
    merge_fmt = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': True})
    
    headers = ['Template_Name', 'Target_Domain', 'Severity', 'Description', 'Tags', 'CVSS_Score', 'CWE_ID', 'Curl_Command', 'Source_File']
    worksheet.write_row(0, 0, headers, header_fmt)
    rows_sorted = sorted(rows, key=lambda x: (x['template_name'], x['target_domain']))
    
    row_idx = 1
    current_template = None
    merge_start_row = None
    
    for rd in rows_sorted:
        if rd['template_name'] != current_template:
            if merge_start_row is not None and merge_start_row < row_idx - 1:
                worksheet.merge_range(merge_start_row, 0, row_idx - 1, 0, rows_sorted[merge_start_row]['template_name'], merge_fmt)
            merge_start_row = row_idx
            current_template = rd['template_name']
        
        for i, col in enumerate([1,2,3,4,5,6,7,8], 1):
            worksheet.write(row_idx, col, rd[list(rd.keys())[col]], cell_fmt)
        row_idx += 1

    if merge_start_row is not None and merge_start_row < row_idx - 1:
        worksheet.merge_range(merge_start_row, 0, row_idx - 1, 0, rows_sorted[merge_start_row]['template_name'], merge_fmt)
    
    for i, w in enumerate([20,30,12,50,25,12,15,60,40]): worksheet.set_column(i, i, w)
    worksheet.freeze_panes(1, 0)
    worksheet.autofilter(0, 0, row_idx - 1, len(headers) - 1)
    workbook.close()
    ui.success(f"Report saved to: {output_path}")


def generate_report(input_dir, output_path, severity_filter=None):
    input_path = Path(input_dir)
    if not input_path.is_dir():
        ui.error(f"Input directory not found: {input_dir}")
        sys.exit(1)
    md_files = list(input_path.glob('*.md'))
    if not md_files:
        ui.warn(f"No .md files found in {input_dir}")
        return
    ui.info(f"Found {len(md_files)} .md files in {input_dir}")
    template_prefixes = extract_template_prefixes([f.name for f in md_files])
    ui.info(f"Identified {len(template_prefixes)} unique template prefixes")

    rows = []
    for f in md_files:
        r = parse_nuclei_file(str(f), template_prefixes)
        if r and (not severity_filter or r['severity'].lower() in [s.strip().lower() for s in severity_filter.split(',')]):
            rows.append(r)

    if not rows:
        ui.warn("No valid findings to export")
        return
    ui.info(f"Processed {len(rows)} findings")
    write_xlsx(rows, output_path)


# ─────────────────────────────────────────────────────────────
# INTERACTIVE INPUT RESOLVER
# ─────────────────────────────────────────────────────────────

def resolve_interactive_inputs(args):
    """Ask for missing inputs interactively. Respects CLI overrides."""
    # 1. Target file / conversion logic
    if args.input_file is None and args.convert_port_scan is None:
        if args.default:
            # --default mode: only 2 questions total
            convert = input("[?] Convert port scan output? (y/n, default: n): ").strip().lower() in ['y', 'yes']
            if convert:
                args.convert_port_scan = input("[?] Path to port scan file: ").strip()
            else:
                args.input_file = input("[?] Path to nuclei-formatted targets file: ").strip()
        else:
            # Full interactive mode
            convert = input("[?] Convert port scan output to nuclei format? (y/n, default: n): ").strip().lower() in ['y', 'yes']
            if convert:
                args.convert_port_scan = input("[?] Enter port scan file path: ").strip()
            else:
                args.input_file = input("[?] Enter nuclei-formatted targets file path: ").strip()

    # 2. Max concurrent sessions
    if args.max_concurrent is None:
        prompt = "[?] Max tmux sessions (default: 5, max: 20): " if not args.default else "[?] Max tmux sessions (default: 5): "
        val = input(prompt).strip()
        args.max_concurrent = int(val) if val else 5

    # Clamp to safe range
    args.max_concurrent = max(1, min(args.max_concurrent, 20))


# ─────────────────────────────────────────────────────────────
# MAIN / CLI
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Nuclei Parallel Scanner + XLSX Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Modes:
  (no flags)   Full interactive mode (asks for everything)
  --default    Quick mode: only asks for conversion & tmux sessions
  --scan-only  Run scanner only (skip report)
  --report-only Run report generator only (skip scanner)

Examples:
  python3 nuclei-tool.py
  python3 nuclei-tool.py --default
  python3 nuclei-tool.py --max-concurrent 10 --convert-port-scan out.txt
  python3 nuclei-tool.py --report-only -i Nuclei-results/ -o report.xlsx
        '''
    )
    
    # Scanner Args
    s = parser.add_argument_group('Scanner Options')
    s.add_argument('--scan-only', action='store_true', help='Run scanner only, skip report generation')
    s.add_argument('--convert-port-scan', type=str, default=None, help='Path to port scan output to convert')
    s.add_argument('--input-file', type=str, default=None, help='Path to nuclei-formatted targets file')
    s.add_argument('--max-concurrent', type=int, default=None, help='Max concurrent tmux sessions (1-20)')
    s.add_argument('--output-dir', type=str, default='Nuclei-results', help='Directory for Nuclei .md outputs')
    
    # Report Args
    r = parser.add_argument_group('Report Options')
    r.add_argument('--report-only', action='store_true', help='Run report generator only, skip scanner')
    r.add_argument('--skip-report', action='store_true', help='Skip report generation after scan')
    r.add_argument('--xlsx-output', type=str, default='nuclei-report.xlsx', help='Output Excel filename')
    r.add_argument('--severity', type=str, default=None, help='Comma-separated severity filter (e.g., high,critical)')
    r.add_argument('--default', action='store_true', help='Quick interactive mode: only asks for conversion & max sessions')

    args = parser.parse_args()

    # Register SIGINT handler here (main thread only) for tmux cleanup on Ctrl+C.
    signal.signal(signal.SIGINT, cleanup_tmux_sessions)

    # ── REPORT ONLY MODE ──
    if args.report_only:
        ui.info("Running in Report-Only mode...")
        generate_report(args.output_dir, args.xlsx_output, args.severity)
        return

    # ── RESOLVE MISSING INPUTS INTERACTIVELY ──
    resolve_interactive_inputs(args)

    # ── SCANNER MODE ──
    ui.banner("Nuclei Parallel Scanner", "Scans targets concurrently via tmux, then builds an xlsx findings report")

    target_file = None
    if args.convert_port_scan:
        target_file = convert_port_scan_to_nuclei(args.convert_port_scan)
        if target_file is None:
            ui.error("Conversion failed. Exiting.")
            sys.exit(1)
    else:
        target_file = args.input_file

    targets = read_targets_from_file(target_file)
    if not targets:
        ui.error("No targets found in file")
        sys.exit(1)
    ui.success(f"Loaded {len(targets)} targets from {target_file}")

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f"nuclei_scan_log_{timestamp}.txt"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    ui.info(f"Log file: {log_file}")
    ui.info(f"Results will be saved in: {output_dir}/")
    ui.info(f"Max concurrent sessions: {args.max_concurrent}")

    scan_start_time = datetime.now()
    with open(log_file, 'a') as f:
        f.write(f"\n{'='*80}\nNuclei Scan Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\nSource File: {target_file}\nTotal Targets: {len(targets)}\nMax Concurrent Sessions: {args.max_concurrent}\n{'='*80}\n\n")

    try:
        completed, failed = run_parallel_scan(targets, args.max_concurrent, log_file)
        scan_end_time = datetime.now()

        with open(log_file, 'a') as f:
            f.write(f"\n{'='*80}\nNuclei Scan Completed: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\nDuration: {scan_end_time - scan_start_time}\nCompleted: {completed}\nFailed: {failed}\n{'='*80}\n")

        print_summary(completed, failed, len(targets), log_file, scan_start_time, scan_end_time)
        ui.success("Scan complete!")
        ui.info(f"Results directory: {output_dir}/")

        # ── POST-SCAN REPORT GENERATION ──
        if not args.skip_report and not args.scan_only:
            ui.info("Generating Excel report from scan results...")
            generate_report(str(output_dir), args.xlsx_output, args.severity)

    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        tmux_sessions.clear()


if __name__ == '__main__':
    main()