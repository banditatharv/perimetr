#!/usr/bin/env python3
"""
Advanced Subnet Sweep Script
Detects alive hosts using multiple techniques when ICMP ping might be blocked
Saves results in subnet-wise text files for categorization
"""

import ipaddress
import subprocess
import concurrent.futures
import argparse
import os
from datetime import datetime
import socket
import sys

import perimetrUI as ui

class SubnetScanner:
    def __init__(self, subnets_file, output_dir="scan_results", threads=50):
        self.subnets_file = subnets_file
        self.output_dir = output_dir
        self.threads = threads
        self.common_ports = [80, 443, 22, 445, 139, 3389, 21, 23, 25, 53, 135, 3306, 5900, 8080]
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def check_icmp_ping(self, ip):
        """Check if host responds to ICMP ping"""
        try:
            # Use -c 1 for Linux/Mac, -n 1 for Windows
            param = '-n' if sys.platform.lower() == 'win32' else '-c'
            command = ['ping', param, '1', '-W', '1', str(ip)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def check_tcp_connect(self, ip, port, timeout=1):
        """Check if TCP port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_arp(self, ip):
        """Check ARP table for host (works only on local network)"""
        try:
            if sys.platform.lower() == 'win32':
                command = ['arp', '-a', str(ip)]
            else:
                command = ['arp', '-n', str(ip)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return str(ip) in result.stdout.decode()
        except:
            return False
    
    def check_host_alive(self, ip):
        """
        Comprehensive check using multiple methods to determine if host is alive
        Returns: (is_alive, detection_methods)
        """
        detection_methods = []
        
        # Method 1: ICMP Ping
        if self.check_icmp_ping(ip):
            detection_methods.append("ICMP")
        
        # Method 2: TCP port scanning (common ports)
        open_ports = []
        for port in self.common_ports:
            if self.check_tcp_connect(ip, port, timeout=0.5):
                open_ports.append(port)
                if "TCP" not in detection_methods:
                    detection_methods.append(f"TCP")
        
        if open_ports:
            detection_methods.append(f"Ports:{','.join(map(str, open_ports))}")
        
        # Method 3: ARP (for local network)
        if self.check_arp(ip):
            detection_methods.append("ARP")
        
        is_alive = len(detection_methods) > 0
        return is_alive, detection_methods
    
    def scan_ip(self, ip):
        """Scan a single IP address"""
        is_alive, methods = self.check_host_alive(ip)
        if is_alive:
            methods_str = ", ".join(methods)
            ui.success(f"{ip} is ALIVE - Detected via: {methods_str}")
            return (str(ip), methods_str)
        return None
    
    def scan_subnet(self, subnet):
        """Scan all IPs in a subnet"""
        ui.info(f"Scanning subnet: {subnet}")
        network = ipaddress.ip_network(subnet, strict=False)
        alive_hosts = []
        
        # Get all IPs in subnet (exclude network and broadcast for /24 and larger)
        if network.prefixlen < 31:
            hosts = list(network.hosts())
        else:
            hosts = list(network)
        
        total_hosts = len(hosts)
        ui.info(f"Total hosts to scan: {total_hosts}")
        
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_ip, ip): ip for ip in hosts}
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    ui.info(f"Progress: {completed}/{total_hosts} hosts scanned")
                
                result = future.result()
                if result:
                    alive_hosts.append(result)
        
        return alive_hosts
    
    def save_results(self, subnet, alive_hosts):
        """Save results to subnet-specific file"""
        # Create safe filename from subnet
        subnet_name = str(subnet).replace('/', '_').replace(':', '-')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/{subnet_name}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(f"Subnet Scan Results\n")
            f.write(f"{'='*60}\n")
            f.write(f"Subnet: {subnet}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Alive Hosts: {len(alive_hosts)}\n")
            f.write(f"{'='*60}\n\n")
            
            f.write("IP Address\t\tDetection Methods\n")
            f.write(f"{'-'*60}\n")
            
            for ip, methods in alive_hosts:
                f.write(f"{ip}\t\t{methods}\n")
        
        # Also create a simple IP-only file for easy import
        ip_only_filename = f"{self.output_dir}/{subnet_name}_{timestamp}_ips_only.txt"
        with open(ip_only_filename, 'w') as f:
            for ip, _ in alive_hosts:
                f.write(f"{ip}\n")
        
        ui.info(f"Results saved to: {filename}")
        ui.info(f"IP-only list: {ip_only_filename}")
        
        return filename
    
    def run(self):
        """Main execution method"""
        ui.banner("Advanced Subnet Sweep Scanner", "ICMP Ping + TCP Port Scan + ARP Table Check")

        # Read subnets from file
        try:
            with open(self.subnets_file, 'r') as f:
                subnets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            ui.error(f"Subnets file '{self.subnets_file}' not found")
            return

        if not subnets:
            ui.error("No subnets found in file")
            return

        ui.info(f"Loaded {len(subnets)} subnet(s) to scan")
        ui.info(f"Using {self.threads} threads")
        ui.info(f"Output directory: {self.output_dir}")

        # Scan each subnet
        total_alive = 0
        for subnet in subnets:
            try:
                alive_hosts = self.scan_subnet(subnet)

                if alive_hosts:
                    total_alive += len(alive_hosts)
                    ui.success(f"Found {len(alive_hosts)} alive host(s) in {subnet}")
                    self.save_results(subnet, alive_hosts)
                else:
                    ui.warn(f"No alive hosts found in {subnet}")

            except ValueError as e:
                ui.error(f"Invalid subnet format: {subnet} - {e}")
            except Exception as e:
                ui.error(f"Error scanning {subnet}: {e}")

        ui.summary("Scan Complete", [
            ("Total alive hosts discovered", total_alive),
            ("Results directory", f"{self.output_dir}/"),
        ])


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Subnet Sweep - Detect alive hosts using multiple techniques',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 advanced_subnet_sweep.py -f subnets.txt
  python3 advanced_subnet_sweep.py -f subnets.txt -o results -t 100
  
Subnets file format (one subnet per line):
  192.168.1.0/24
  10.0.0.0/16
  172.16.0.0/12
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing list of subnets (one per line)')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory for results (default: scan_results)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    
    args = parser.parse_args()
    
    scanner = SubnetScanner(args.file, args.output, args.threads)
    scanner.run()


if __name__ == "__main__":
    main()
