#!/usr/bin/env python3
"""
Domain Connectivity Checker
Author: Security Assessment Tool
Description: Checks connectivity and status of multiple domains concurrently
             Now with httpx for title and technology detection
"""

import requests
import socket
import dns.resolver
import concurrent.futures
import csv
import sys
import time
import re
from datetime import datetime
from urllib.parse import urlparse
import urllib3
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
import httpx

# Disable SSL warnings for initial discovery
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class DomainChecker:
    def __init__(self, timeout=10, max_workers=10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []
        self.session_timeout = 30

    def print_banner(self):
        """Print tool banner"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}          Domain Connectivity Checker v2.0")
        print(f"{Fore.CYAN}          Enhanced with httpx + Tech Detection")
        print(f"{Fore.CYAN}{'='*70}\n")

    def clean_domain(self, domain):
        """Clean and normalize domain name"""
        domain = domain.strip()
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        # Remove trailing slash
        domain = domain.rstrip('/')
        # Remove www. if present for consistency
        return domain

    def check_dns(self, domain):
        """Check if domain resolves via DNS"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip_addresses = [str(rdata) for rdata in answers]
            return True, ip_addresses[0] if ip_addresses else "N/A"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return False, "No DNS Record"
        except Exception as e:
            return False, f"DNS Error: {str(e)[:50]}"

    def extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.title.string if soup.title else "No Title"
            # Clean up title
            title = ' '.join(title.split())
            return title[:100]  # Limit to 100 characters
        except Exception:
            return "Failed to extract"

    def detect_technologies(self, response_headers, html_content):
        """Detect technologies from headers and HTML content"""
        technologies = []

        # Check headers for common technologies
        headers = response_headers
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Server detection
        if 'server' in headers_lower:
            server = headers_lower['server'].lower()
            if 'nginx' in server:
                technologies.append('Nginx')
            if 'apache' in server:
                technologies.append('Apache')
            if 'iis' in server or 'microsoft-iis' in server:
                technologies.append('IIS')
            if 'cloudflare' in server:
                technologies.append('Cloudflare')
            if 'gunicorn' in server:
                technologies.append('Gunicorn')
            if 'uwsgi' in server:
                technologies.append('uWSGI')

        # X-Powered-By detection
        if 'x-powered-by' in headers_lower:
            powered_by = headers_lower['x-powered-by'].lower()
            if 'express' in powered_by:
                technologies.append('Express.js')
            if 'php' in powered_by:
                technologies.append('PHP')
            if 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            if 'next.js' in powered_by:
                technologies.append('Next.js')
            if 'nuxt.js' in powered_by:
                technologies.append('Nuxt.js')

        # X-AspNet-Version detection
        if 'x-aspnet-version' in headers_lower:
            technologies.append('ASP.NET')

        # Set-Cookie detection
        if 'set-cookie' in headers_lower:
            cookies = headers_lower['set-cookie'].lower()
            if 'phpsessid' in cookies:
                technologies.append('PHP')
            if 'jsessionid' in cookies:
                technologies.append('Java/JSP')
            if 'asp.net_sessionid' in cookies:
                technologies.append('ASP.NET')
            if 'laravel' in cookies or 'xSRF-TOKEN' in cookies:
                technologies.append('Laravel')
            if 'csrf' in cookies:
                technologies.append('CSRF Protection')

        # HTML content detection
        try:
            soup = BeautifulSoup(html_content, 'html.parser')

            # Meta generator
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                generator = meta_generator['content'].lower()
                if 'wordpress' in generator:
                    technologies.append('WordPress')
                if 'joomla' in generator:
                    technologies.append('Joomla')
                if 'drupal' in generator:
                    technologies.append('Drupal')
                if 'wix' in generator:
                    technologies.append('Wix')
                if 'squarespace' in generator:
                    technologies.append('Squarespace')

            # Script tag detection
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src'].lower()
                if 'jquery' in src:
                    technologies.append('jQuery')
                if 'react' in src:
                    technologies.append('React')
                if 'vue' in src:
                    technologies.append('Vue.js')
                if 'angular' in src:
                    technologies.append('Angular')
                if 'bootstrap' in src:
                    technologies.append('Bootstrap')
                if 'tailwind' in src:
                    technologies.append('Tailwind CSS')
                if 'next' in src:
                    technologies.append('Next.js')
                if 'nuxt' in src:
                    technologies.append('Nuxt.js')
                if 'gatsby' in src:
                    technologies.append('Gatsby')

            # Link tag detection (CSS frameworks)
            links = soup.find_all('link', rel='stylesheet')
            for link in links:
                href = link.get('href', '').lower()
                if 'bootstrap' in href:
                    technologies.append('Bootstrap')
                if 'tailwind' in href:
                    technologies.append('Tailwind CSS')
                if 'bulma' in href:
                    technologies.append('Bulma')

        except Exception:
            pass

        # Remove duplicates and return
        return list(set(technologies))

    def check_http(self, domain, protocol='https'):
        """Check HTTP/HTTPS connectivity using httpx"""
        url = f"{protocol}://{domain}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Security Assessment Tool) Domain Connectivity Checker'
        }

        try:
            # Use httpx for better request handling
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                response = client.get(url, headers=headers)

                final_url = str(response.url)
                redirect_info = f"→ {final_url}" if final_url != url else ""

                # Extract title and technologies
                title = self.extract_title(response.text)
                technologies = self.detect_technologies(dict(response.headers), response.text)

                return {
                    'status': 'LIVE',
                    'status_code': response.status_code,
                    'protocol': protocol.upper(),
                    'response_time': round(response.elapsed.total_seconds(), 2),
                    'redirect': redirect_info,
                    'content_length': len(response.content),
                    'title': title,
                    'technologies': ', '.join(technologies) if technologies else 'None detected',
                    'tech_count': len(technologies)
                }
        except httpx.ConnectError:
            if protocol == 'https':
                # Try HTTP if HTTPS fails
                return self.check_http(domain, 'http')
            return {
                'status': 'NO_RESPONSE',
                'status_code': 0,
                'protocol': 'HTTP',
                'response_time': 0,
                'redirect': '',
                'content_length': 0,
                'title': 'N/A',
                'technologies': 'N/A',
                'tech_count': 0
            }
        except httpx.TimeoutException:
            return {
                'status': 'TIMEOUT',
                'status_code': 0,
                'protocol': protocol.upper(),
                'response_time': self.timeout,
                'redirect': '',
                'content_length': 0,
                'title': 'N/A',
                'technologies': 'N/A',
                'tech_count': 0
            }
        except httpx.SSLError:
            if protocol == 'https':
                # Try HTTP if HTTPS fails
                return self.check_http(domain, 'http')
            return {
                'status': 'SSL_ERROR',
                'status_code': 0,
                'protocol': 'HTTPS',
                'response_time': 0,
                'redirect': '',
                'content_length': 0,
                'title': 'N/A',
                'technologies': 'N/A',
                'tech_count': 0
            }
        except Exception as e:
            return {
                'status': 'ERROR',
                'status_code': 0,
                'protocol': protocol.upper(),
                'response_time': 0,
                'redirect': str(e)[:100],
                'content_length': 0,
                'title': 'N/A',
                'technologies': 'N/A',
                'tech_count': 0
            }

    def check_domain(self, domain):
        """Main function to check a single domain"""
        domain = self.clean_domain(domain)

        print(f"{Fore.YELLOW}[*] Checking: {domain}")

        # Step 1: DNS Check
        dns_resolved, ip_address = self.check_dns(domain)

        if not dns_resolved:
            result = {
                'domain': domain,
                'status': 'DNS_FAILED',
                'ip_address': ip_address,
                'status_code': 0,
                'protocol': 'N/A',
                'response_time': 0,
                'redirect': '',
                'content_length': 0,
                'title': 'N/A',
                'technologies': 'N/A',
                'tech_count': 0,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            print(f"{Fore.RED}[✗] {domain} - DNS Failed")
            return result

        # Step 2: HTTP/HTTPS Check
        http_result = self.check_http(domain)

        result = {
            'domain': domain,
            'status': http_result['status'],
            'ip_address': ip_address,
            'status_code': http_result['status_code'],
            'protocol': http_result['protocol'],
            'response_time': http_result['response_time'],
            'redirect': http_result['redirect'],
            'content_length': http_result['content_length'],
            'title': http_result['title'],
            'technologies': http_result['technologies'],
            'tech_count': http_result['tech_count'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Color-coded output based on status
        if result['status'] == 'LIVE':
            status_color = Fore.GREEN
            symbol = "✓"
        elif result['status'] in ['TIMEOUT', 'NO_RESPONSE']:
            status_color = Fore.RED
            symbol = "✗"
        else:
            status_color = Fore.YELLOW
            symbol = "⚠"

        tech_info = f" | Tech: {result['technologies']}" if result['technologies'] != 'N/A' else ""
        title_info = f" | Title: {result['title'][:50]}" if result['title'] != 'N/A' else ""

        print(f"{status_color}[{symbol}] {domain} - {result['status']} "
              f"[{result['status_code']}] {result['protocol']} "
              f"({result['response_time']}s){title_info}{tech_info}")

        return result

    def process_domains(self, domains):
        """Process multiple domains concurrently"""
        print(f"\n{Fore.CYAN}[i] Starting concurrent processing with {self.max_workers} workers")
        print(f"{Fore.CYAN}[i] Total domains to check: {len(domains)}\n")

        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_domain = {executor.submit(self.check_domain, domain): domain for domain in domains}

            # Process completed tasks
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    print(f"{Fore.RED}[!] Exception for {domain}: {str(e)}")
                    self.results.append({
                        'domain': domain,
                        'status': 'EXCEPTION',
                        'ip_address': 'N/A',
                        'status_code': 0,
                        'protocol': 'N/A',
                        'response_time': 0,
                        'redirect': str(e)[:100],
                        'content_length': 0,
                        'title': 'N/A',
                        'technologies': 'N/A',
                        'tech_count': 0,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })

        elapsed_time = time.time() - start_time
        print(f"\n{Fore.CYAN}[i] Completed in {elapsed_time:.2f} seconds")

    def save_csv(self, filename):
        """Save results to CSV file"""
        if not self.results:
            print(f"{Fore.RED}[!] No results to save")
            return

        fieldnames = ['domain', 'status', 'ip_address', 'status_code', 'protocol',
                      'response_time', 'redirect', 'content_length', 'title', 'technologies',
                      'tech_count', 'timestamp']

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)

        print(f"{Fore.GREEN}[✓] CSV results saved to: {filename}")

    def save_grepable(self, filename):
        """Save results in grepable format"""
        if not self.results:
            print(f"{Fore.RED}[!] No results to save")
            return

        with open(filename, 'w', encoding='utf-8') as f:
            for result in self.results:
                line = (f"{result['domain']}|{result['status']}|{result['ip_address']}|"
                       f"{result['status_code']}|{result['protocol']}|{result['response_time']}|"
                       f"{result['redirect']}|{result['content_length']}|"
                       f"{result['title']}|{result['technologies']}|"
                       f"{result['tech_count']}|{result['timestamp']}\n")
                f.write(line)

        print(f"{Fore.GREEN}[✓] Grepable results saved to: {filename}")

    def print_summary(self):
        """Print summary statistics"""
        if not self.results:
            return

        total = len(self.results)
        live = sum(1 for r in self.results if r['status'] == 'LIVE')
        dns_failed = sum(1 for r in self.results if r['status'] == 'DNS_FAILED')
        timeout = sum(1 for r in self.results if r['status'] == 'TIMEOUT')
        no_response = sum(1 for r in self.results if r['status'] == 'NO_RESPONSE')
        errors = sum(1 for r in self.results if r['status'] in ['ERROR', 'SSL_ERROR', 'EXCEPTION'])

        # Technology statistics
        total_tech = sum(r['tech_count'] for r in self.results)
        domains_with_tech = sum(1 for r in self.results if r['tech_count'] > 0)

        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}                         SUMMARY")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.WHITE}Total Domains:       {total}")
        print(f"{Fore.GREEN}Live:                {live} ({live/total*100:.1f}%)")
        print(f"{Fore.RED}DNS Failed:          {dns_failed} ({dns_failed/total*100:.1f}%)")
        print(f"{Fore.YELLOW}Timeout:             {timeout} ({timeout/total*100:.1f}%)")
        print(f"{Fore.RED}No Response:         {no_response} ({no_response/total*100:.1f}%)")
        print(f"{Fore.YELLOW}Errors:              {errors} ({errors/total*100:.1f}%)")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.MAGENTA}Technology Detection:")
        print(f"{Fore.MAGENTA}  Domains with tech: {domains_with_tech}")
        print(f"{Fore.MAGENTA}  Total technologies: {total_tech}")
        print(f"{Fore.CYAN}{'='*70}\n")

    def print_top_domains_with_tech(self, top_n=10):
        """Print top domains with most technologies detected"""
        if not self.results:
            return

        live_with_tech = [r for r in self.results if r['status'] == 'LIVE' and r['tech_count'] > 0]
        live_with_tech.sort(key=lambda x: x['tech_count'], reverse=True)

        if not live_with_tech:
            return

        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}         TOP {min(top_n, len(live_with_tech))} DOMAINS BY TECHNOLOGY COUNT")
        print(f"{Fore.CYAN}{'='*70}")

        for i, result in enumerate(live_with_tech[:top_n], 1):
            print(f"{Fore.WHITE}{i}. {result['domain']}")
            print(f"   {Fore.CYAN}Title: {result['title']}")
            print(f"   {Fore.GREEN}Technologies ({result['tech_count']}): {result['technologies']}")
            print()

        print(f"{Fore.CYAN}{'='*70}\n")


def main():
    """Main function"""
    checker = DomainChecker()
    checker.print_banner()

    # Get input file
    if len(sys.argv) < 2:
        input_file = input(f"{Fore.CYAN}[?] Enter input file path: ").strip()
    else:
        input_file = sys.argv[1]

    # Get concurrent workers
    try:
        max_workers = int(input(f"{Fore.CYAN}[?] Enter number of concurrent workers (default 10, max 50): ").strip() or "10")
        if max_workers > 50:
            print(f"{Fore.YELLOW}[!] Limited to 50 workers for safety")
            max_workers = 50
    except ValueError:
        max_workers = 10
        print(f"{Fore.YELLOW}[!] Invalid input, using default: 10 workers")

    checker.max_workers = max_workers

    # Read domains from file
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading file: {str(e)}")
        sys.exit(1)

    if not domains:
        print(f"{Fore.RED}[!] No domains found in file")
        sys.exit(1)

    # Process domains
    checker.process_domains(domains)

    # Generate output filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_filename = f"domain_check_results_{timestamp}.csv"
    grep_filename = f"domain_check_results_{timestamp}.grep"

    # Save results
    checker.save_csv(csv_filename)
    checker.save_grepable(grep_filename)

    # Print summary
    checker.print_summary()

    # Print top domains with most technologies
    checker.print_top_domains_with_tech(top_n=10)

    print(f"{Fore.CYAN}[i] Assessment complete!\n")


if __name__ == "__main__":
    main()