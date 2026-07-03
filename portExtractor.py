#!/usr/bin/env python3
"""
Port Extractor
Reads <ip>.gnmap files produced by portScanning.py and builds an ip:port list
for the next pipeline stages (serviceScanning.py, nuclei conversion).

Replaces the manual one-liner:
  while read ip; do ... awk over "$ip.gnmap" ... ; done < scope.txt

Usage:
  python portExtractor.py -d <scan_dir> -s scope.txt
  python portExtractor.py -d <scan_dir> -s scope.txt -o ip_ports.txt
"""

import argparse
import os
import re
import sys

import perimetrUI as ui

OPEN_PORT_RE = re.compile(r'(\d+)/open/')


def extract_ports(gnmap_path):
    """Return a sorted list of open port numbers found in a .gnmap file."""
    ports = set()
    with open(gnmap_path, 'r', errors='ignore') as f:
        for line in f:
            if 'Host:' in line and 'Ports:' in line:
                ports.update(int(p) for p in OPEN_PORT_RE.findall(line))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description='Extract open ports per IP from portScanning.py .gnmap output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -d scan_results/ -s scope.txt
  %(prog)s -d scan_results/ -s scope.txt -o ip_ports.txt
        '''
    )
    parser.add_argument('-d', '--scan-dir', required=True, help='Directory containing <ip>.gnmap files')
    parser.add_argument('-s', '--scope', required=True, help='File listing target IPs, one per line')
    parser.add_argument('-o', '--output', default='ip_ports.txt', help='Output file for ip:ports list (default: ip_ports.txt)')
    args = parser.parse_args()

    ui.banner("Port Extractor", "Builds an ip:ports list from portScanning.py .gnmap output")

    if not os.path.isdir(args.scan_dir):
        ui.error(f"Scan directory not found: {args.scan_dir}")
        sys.exit(1)

    try:
        with open(args.scope, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        ui.error(f"Scope file not found: {args.scope}")
        sys.exit(1)

    if not ips:
        ui.error("No IPs found in scope file")
        sys.exit(1)

    with_ports = 0
    no_ports = 0
    missing = 0

    with open(args.output, 'w') as out:
        for ip in ips:
            gnmap_path = os.path.join(args.scan_dir, f"{ip}.gnmap")
            if not os.path.isfile(gnmap_path):
                ui.console.print(f"  [bold blue]{ip}[/bold blue]: [red]No file[/red]")
                missing += 1
                continue

            ports = extract_ports(gnmap_path)
            if not ports:
                ui.console.print(f"  [bold blue]{ip}[/bold blue]: [yellow]N/A[/yellow]")
                no_ports += 1
                continue

            port_str = ','.join(str(p) for p in ports)
            ui.console.print(f"  [bold blue]{ip}[/bold blue]: {port_str}")
            out.write(f"{ip}:{port_str}\n")
            with_ports += 1

    ui.summary("Port Extraction Complete", [
        ("With open ports", with_ports),
        ("With none", no_ports),
        ("Missing scan files", missing),
        ("Saved to", args.output),
    ])


if __name__ == '__main__':
    main()
