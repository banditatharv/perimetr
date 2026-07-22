#!/usr/bin/env python3

import argparse
import ipaddress
import os
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict
import csv
import json
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self, output_dir: str, timeout: int = 1, parallel: int = 10):
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.parallel = parallel
        self.results: Dict[str, dict] = {}
        
    def create_output_dir(self, timestamped: bool = True):
        """Create output directory (timestamped subfolder by default).

        Pass timestamped=False to write directly into the given output dir -
        used by the perimetr pipeline so it knows exactly where results land
        instead of having to hunt for the newest scan_<ts>/ folder."""
        if timestamped:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = self.output_dir / f"scan_{timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def check_nmap_installation(self):
        """Check if nmap is installed"""
        try:
            subprocess.run(['nmap', '--version'], capture_output=True)
            return True
        except FileNotFoundError:
            return False
        
    def ping(self, ip: str) -> dict:
        """Ping a single IP address and return results"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            command = ['ping', param, '1', timeout_param, str(self.timeout), ip]
            
            start_time = datetime.now()
            result = subprocess.run(command, capture_output=True, text=True)
            end_time = datetime.now()
            
            response_time = (end_time - start_time).total_seconds() * 1000
            is_alive = result.returncode == 0
            
            return {
                'ip': ip,
                'is_alive': is_alive,
                'response_time_ms': round(response_time, 2),
                'raw_output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'ip': ip,
                'is_alive': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def nmap_scan(self, ip: str) -> dict:
        """Perform fast nmap scan on an IP"""
        try:
            # -F: Fast scan (fewer ports)
            # -T4: Aggressive timing template
            # -n: No DNS resolution
            command = ['nmap', '-F', '-T4', '-n', ip]
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Parse nmap output for open ports
            open_ports = []
            for line in result.stdout.splitlines():
                if 'open' in line and 'filtered' not in line:
                    port = line.split('/')[0].strip()
                    open_ports.append(port)
            
            return {
                'has_open_ports': len(open_ports) > 0,
                'open_ports': open_ports,
                'raw_output': result.stdout
            }
        except Exception as e:
            return {
                'error': str(e),
                'has_open_ports': False,
                'open_ports': []
            }

    def process_ip_list(self, ips: List[str]):
        """Process a list of IPs using thread pool"""
        print("Phase 1: ICMP Ping Scan")
        print("------------------------")
        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            results = list(executor.map(self.ping, ips))
            for result in results:
                self.results[result['ip']] = result
                self._print_result(result)

        # Get non-responding IPs
        non_responding = [ip for ip, result in self.results.items() if not result['is_alive']]
        
        if non_responding and self.check_nmap_installation():
            print("\nPhase 2: Nmap Fast Scan on Non-responding IPs")
            print("--------------------------------------------")
            for ip in non_responding:
                print(f"Scanning {ip}...")
                nmap_result = self.nmap_scan(ip)
                self.results[ip]['nmap_scan'] = nmap_result
                if nmap_result['has_open_ports']:
                    print(f"✓ {ip} - Found open ports: {', '.join(nmap_result['open_ports'])}")
                else:
                    print(f"✗ {ip} - No open ports found")

    def _print_result(self, result: dict):
        """Print result in real-time"""
        status = "✓" if result['is_alive'] else "✗"
        if result['is_alive']:
            print(f"{status} {result['ip']} - Response time: {result['response_time_ms']}ms")
        else:
            print(f"{status} {result['ip']} - No response")

    def save_results(self):
        """Save results in multiple formats"""
        # Save full results as JSON
        with open(self.output_dir / 'full_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)

        # Save responding IPs (ping)
        with open(self.output_dir / 'responded_ping.txt', 'w') as f:
            for ip, result in self.results.items():
                if result['is_alive']:
                    f.write(f"{ip}\n")

        # Save responding IPs (nmap)
        with open(self.output_dir / 'responded_nmap.txt', 'w') as f:
            for ip, result in self.results.items():
                if not result['is_alive'] and 'nmap_scan' in result:
                    if result['nmap_scan'].get('has_open_ports', False):
                        f.write(f"{ip} - Ports: {', '.join(result['nmap_scan']['open_ports'])}\n")

        # Save non-responding IPs (both ping and nmap)
        with open(self.output_dir / 'not_responded.txt', 'w') as f:
            for ip, result in self.results.items():
                if not result['is_alive']:
                    if 'nmap_scan' not in result or not result['nmap_scan'].get('has_open_ports', False):
                        f.write(f"{ip}\n")

        # Save comprehensive CSV report
        with open(self.output_dir / 'scan_report.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Ping Status', 'Response Time (ms)', 'Open Ports', 'Timestamp'])
            for ip, result in self.results.items():
                open_ports = ''
                if not result['is_alive'] and 'nmap_scan' in result:
                    open_ports = ', '.join(result['nmap_scan'].get('open_ports', []))
                writer.writerow([
                    ip,
                    'Alive' if result['is_alive'] else 'Dead',
                    result.get('response_time_ms', 'N/A'),
                    open_ports,
                    result['timestamp']
                ])

    def print_summary(self):
        """Print scan summary"""
        total = len(self.results)
        responding_ping = sum(1 for r in self.results.values() if r['is_alive'])
        responding_nmap = sum(1 for r in self.results.values() 
                            if not r['is_alive'] and 'nmap_scan' in r 
                            and r['nmap_scan'].get('has_open_ports', False))
        not_responding = total - responding_ping - responding_nmap

        print("\n=== Scan Summary ===")
        print(f"Total IPs scanned: {total}")
        print(f"Responding to ping: {responding_ping}")
        print(f"Responding only to nmap: {responding_nmap}")
        print(f"Not responding to either: {not_responding}")
        print(f"Success rate: {((responding_ping + responding_nmap)/total)*100:.1f}%")
        print(f"\nResults saved in: {self.output_dir}")

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Scanner')
    parser.add_argument('input_file', help='File containing IP addresses (one per line)')
    parser.add_argument('-o', '--output', default='./scan_results', 
                       help='Output directory for results')
    parser.add_argument('-t', '--timeout', type=int, default=1,
                       help='Timeout in seconds for each ping (default: 1)')
    parser.add_argument('-p', '--parallel', type=int, default=10,
                       help='Number of parallel pings (default: 10)')
    parser.add_argument('--no-timestamp', action='store_true',
                       help='Write results directly into -o instead of a '
                            'timestamped scan_<ts>/ subfolder')

    args = parser.parse_args()

    # Validate input file
    if not os.path.exists(args.input_file):
        print(f"Error: Input file {args.input_file} not found!")
        sys.exit(1)

    # Check for nmap installation
    if not NetworkScanner(args.output).check_nmap_installation():
        print("Warning: nmap is not installed. Only ping scan will be performed.")
        print("To install nmap:")
        print("  Ubuntu/Debian: sudo apt-get install nmap")
        print("  CentOS/RHEL: sudo yum install nmap")
        print("  macOS: brew install nmap")
        print("  Windows: Download from https://nmap.org/download.html")

    # Read and validate IPs
    with open(args.input_file) as f:
        ips = [line.strip() for line in f if line.strip()]
    
    valid_ips = [ip for ip in ips if validate_ip(ip)]
    if len(valid_ips) == 0:
        print("Error: No valid IP addresses found in input file!")
        sys.exit(1)

    # Initialize and run scanner
    scanner = NetworkScanner(args.output, args.timeout, args.parallel)
    scanner.create_output_dir(timestamped=not args.no_timestamp)

    print(f"Starting scan of {len(valid_ips)} IP addresses...")
    scanner.process_ip_list(valid_ips)
    scanner.save_results()
    scanner.print_summary()

if __name__ == "__main__":
    main()
