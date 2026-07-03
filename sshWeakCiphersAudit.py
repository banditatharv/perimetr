#!/usr/bin/env python3
"""
SSH Weak Algorithm Auditor v2
Scans targets with ssh-audit and extracts weak/deprecated algorithms.

Modes:
  full  : Run ssh-audit scan + parse results
  parse : Parse existing ssh-audit output file

Usage:
  python ssh_weak_audit.py --mode full --targets targets.txt --timeout 15
  python ssh_weak_audit.py --mode parse --input output.sshAudit
  python ssh_weak_audit.py -h
"""

import argparse
import subprocess
import re
import sys
import os
from datetime import datetime
from collections import defaultdict

try:
    from colorama import init, Fore, Style, Back
    init(strip=not sys.stdout.isatty())
    COLORS = True
except ImportError:
    COLORS = False
    print(f"{Fore.YELLOW if COLORS else ''}Warning: colorama not installed. Install with: pip install colorama{Style.RESET_ALL if COLORS else ''}")

# Severity color mapping
SEVERITY_COLORS = {
    'fail': Fore.RED + Style.BRIGHT,
    'warn': Fore.YELLOW + Style.BRIGHT,
    'info': Fore.CYAN,
    'rec_remove': Fore.MAGENTA,
    'rec_add': Fore.GREEN,
    'target': Fore.BLUE + Style.BRIGHT,
    'section': Fore.WHITE + Style.BRIGHT,
}

# Algorithm type labels
ALGO_TYPES = {
    'kex': 'Key Exchange',
    'key': 'Host Key',
    'enc': 'Encryption',
    'mac': 'MAC',
    'rec': 'Recommendation',
}

def colorize(text, severity):
    """Apply color based on severity if colorama is available."""
    if not COLORS:
        return text
    color = SEVERITY_COLORS.get(severity, Style.RESET_ALL)
    return f"{color}{text}{Style.RESET_ALL}"

def extract_weak_algorithms(results):
    """
    Extract just the algorithm names (no reasons) from parsed results.
    Returns: {target: [algo1, algo2, ...]}
    """
    weak_algos = defaultdict(list)
    
    for target, severities in results.items():
        seen = set()
        for severity in ['fail', 'warn', 'rec_remove']:  # Focus on actionable items
            if severity not in severities:
                continue
            for algo_type, algos in severities[severity].items():
                for algo in algos:
                    name = algo['name'].lstrip('+-')  # Remove +/- prefix from recs
                    if name not in seen:
                        seen.add(name)
                        weak_algos[target].append(name)
    
    return dict(weak_algos)

def parse_ssh_audit_output(content):
    """
    Parse ssh-audit output and extract weak algorithms.
    Returns dict: {target: {severity: {algo_type: [algorithms]}}}
    """
    results = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    
    # Split by target separator
    target_blocks = re.split(r'-{80,}', content)
    
    for block in target_blocks:
        block = block.strip()
        if not block:
            continue
            
        # Extract target IP:port
        target_match = re.search(r'\(gen\)\s+target:\s+([^\s]+)', block)
        if not target_match:
            continue
        target = target_match.group(1)
        
        # Parse algorithm lines with [fail] or [warn]
        # Pattern: (type) algorithm_name -- [severity] message
        algo_pattern = r'\((kex|key|enc|mac)\)\s+([^\s]+(?:\s+\([^)]+\))?)\s+--\s+\[(fail|warn)\]\s+([^\n]+)'
        for match in re.finditer(algo_pattern, block):
            algo_type, algo_name, severity, reason = match.groups()
            algo_name = algo_name.strip()
            reason = reason.strip().rstrip('\\').strip()
            results[target][severity][algo_type].append({
                'name': algo_name,
                'reason': reason
            })
        
        # Parse recommendations section: (rec) -algo_name -- type to remove/add
        rec_pattern = r'\(rec\)\s+([+-])([^\s]+)\s+--\s+(.+?)\s+to\s+(remove|append)'
        for match in re.finditer(rec_pattern, block):
            action, algo_name, algo_category, directive = match.groups()
            severity_key = 'rec_remove' if action == '-' and directive == 'remove' else 'rec_add'
            algo_type_map = {
                'kex algorithm': 'kex',
                'key algorithm': 'key', 
                'enc algorithm': 'enc',
                'mac algorithm': 'mac',
            }
            algo_type = algo_type_map.get(algo_category.strip(), 'rec')
            results[target][severity_key][algo_type].append({
                'name': algo_name.strip(),
                'reason': f"{algo_category.strip()} to {directive}"
            })
    
    return dict(results)

def run_ssh_audit(targets_file, timeout):
    """Run ssh-audit command against targets file."""
    if not os.path.exists(targets_file):
        print(f"{colorize('Error', 'fail')}: Targets file '{targets_file}' not found")
        sys.exit(1)
    
    cmd = ['ssh-audit', '--targets', targets_file]
    print(f"{colorize('[*]', 'info')} Running: {' '.join(cmd)}")
    print(f"{colorize('[*]', 'info')} Timeout per target: {timeout}s\n")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * 10,  # Buffer for multiple targets
            check=False
        )
        if result.returncode != 0 and not result.stdout:
            print(f"{colorize('Error', 'fail')}: ssh-audit failed: {result.stderr.strip()}")
            sys.exit(1)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"{colorize('Error', 'fail')}: Scan timed out after {timeout * 10}s")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{colorize('Error', 'fail')}: ssh-audit command not found. Install from: https://github.com/jtesta/ssh-audit")
        sys.exit(1)

def print_summary_formats(weak_algos_by_target):
    """Print the requested summary formats to terminal."""
    print(f"\n{colorize('='*70, 'section')}")
    print(f"{colorize('SUMMARY FORMATS', 'target')}")
    print(f"{colorize('='*70, 'section')}\n")
    
    # Format 1: Per-target comma-separated
    print(f"{colorize('📋 Per-Target Weak Algorithms:', 'section')}")
    for target in sorted(weak_algos_by_target.keys()):
        algos = weak_algos_by_target[target]
        algo_str = ', '.join(algos) if algos else 'none'
        print(f"{colorize(target, 'target')}: {colorize(algo_str, 'warn' if algos else 'info')}")
    
    # Format 2: Global unique list
    all_unique = sorted(set(algo for algos in weak_algos_by_target.values() for algo in algos))
    print(f"\n{colorize('🌐 All Unique Weak Algorithms (Global):', 'section')}")
    if all_unique:
        print(colorize(', '.join(all_unique), 'warn'))
    else:
        print(colorize('None found', 'info'))
    print()

def write_summary_formats(weak_algos_by_target, f):
    """Write the summary formats to the report file."""
    f.write(f"\n{'='*70}\n")
    f.write(f"SUMMARY FORMATS\n")
    f.write(f"{'='*70}\n\n")
    
    # Format 1: Per-target
    f.write("Per-Target Weak Algorithms:\n")
    for target in sorted(weak_algos_by_target.keys()):
        algos = weak_algos_by_target[target]
        algo_str = ', '.join(algos) if algos else 'none'
        f.write(f"{target}: {algo_str}\n")
    
    # Format 2: Global unique
    all_unique = sorted(set(algo for algos in weak_algos_by_target.values() for algo in algos))
    f.write(f"\nAll Unique Weak Algorithms (Global):\n")
    f.write(', '.join(all_unique) if all_unique else 'None found')
    f.write("\n")

def print_results(results, weak_algos_by_target):
    """Print colored results to terminal."""
    if not results:
        print(f"{colorize('[!] No weak algorithms found or no targets parsed.', 'warn')}")
        return
    
    print(f"\n{colorize('='*70, 'section')}")
    print(f"{colorize('SSH WEAK ALGORITHMS REPORT', 'target')}")
    print(f"{colorize('='*70, 'section')}\n")
    
    total_issues = 0
    
    for target, severities in results.items():
        print(f"{colorize(f'🎯 Target: {target}', 'target')}")
        print(f"{colorize('-'*50, 'section')}")
        
        target_issues = 0
        # Order: fail > warn > rec_remove > rec_add
        for severity in ['fail', 'warn', 'rec_remove', 'rec_add']:
            if severity not in severities:
                continue
            for algo_type, algos in severities[severity].items():
                if not algos:
                    continue
                type_label = ALGO_TYPES.get(algo_type, algo_type.upper())
                print(f"\n  {colorize(f'[{severity.upper()}] {type_label} Algorithms:', severity)}")
                for algo in algos:
                    total_issues += 1
                    target_issues += 1
                    name = algo['name']
                    reason = algo['reason']
                    print(f"    • {colorize(name, severity)}")
                    if reason:
                        print(f"      {colorize('↳', severity)} {colorize(reason, 'info')}")
        
        if target_issues == 0:
            print(f"  {colorize('✓ No weak algorithms detected', 'info')}")
        else:
            print(f"\n  {colorize(f'⚠ Total issues: {target_issues}', 'warn')}")
        print()
    
    # Print summary formats
    print_summary_formats(weak_algos_by_target)

def write_report(results, weak_algos_by_target, output_file, raw_output=None):
    """Write formatted text report to file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"SSH WEAK ALGORITHMS REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*70}\n\n")
        
        if not results:
            f.write("No weak algorithms found or no targets parsed.\n")
            return
        
        for target, severities in results.items():
            f.write(f"Target: {target}\n")
            f.write(f"{'-'*50}\n")
            
            for severity in ['fail', 'warn', 'rec_remove', 'rec_add']:
                if severity not in severities:
                    continue
                for algo_type, algos in severities[severity].items():
                    if not algos:
                        continue
                    type_label = ALGO_TYPES.get(algo_type, algo_type.upper())
                    f.write(f"\n[{severity.upper()}] {type_label} Algorithms:\n")
                    for algo in algos:
                        f.write(f"  • {algo['name']}\n")
                        if algo['reason']:
                            f.write(f"    → {algo['reason']}\n")
            f.write("\n" + "="*70 + "\n\n")
        
        # Add summary formats
        write_summary_formats(weak_algos_by_target, f)
        
        # Add note about raw output file
        if raw_output:
            f.write(f"\n{'='*70}\n")
            f.write(f"NOTE: Raw ssh-audit output saved to: {raw_output}\n")
    
    print(f"{colorize('[+]', 'info')} Report saved: {output_file}")

def save_raw_output(content, base_output_file):
    """Save the raw ssh-audit output to a separate file."""
    # Generate filename based on the main output file
    base_name = os.path.splitext(base_output_file)[0]
    raw_file = f"{base_name}_RAW.txt"
    
    with open(raw_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"{colorize('[+]', 'info')} Raw ssh-audit output saved: {raw_file}")
    return raw_file

def main():
    parser = argparse.ArgumentParser(
        description='SSH Weak Algorithm Auditor - Parse ssh-audit output for weak algorithms',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Full workflow: scan targets + parse results
  python ssh_weak_audit.py --mode full --targets targets.txt --timeout 15
  
  # Parse existing output file
  python ssh_weak_audit.py --mode parse --input output.sshAudit
  
  # Custom output file
  python ssh_weak_audit.py --mode full --targets targets.txt --output weak_report.txt
        '''
    )
    
    parser.add_argument('--mode', required=True, choices=['full', 'parse'],
                        help='Execution mode: "full" (scan+parse) or "parse" (existing file)')
    parser.add_argument('--targets', help='Path to targets file (one IP[:PORT] per line) - required for --mode full')
    parser.add_argument('--input', dest='input_file', help='Path to existing ssh-audit output file - required for --mode parse')
    parser.add_argument('--output', default=f"weak_algorithms_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        help='Output report filename (default: weak_algorithms_YYYYMMDD_HHMMSS.txt)')
    parser.add_argument('--timeout', type=int, default=15,
                        help='Timeout in seconds per target for ssh-audit (default: 15)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.mode == 'full' and not args.targets:
        parser.error("--mode full requires --targets <file>")
    if args.mode == 'parse' and not args.input_file:
        parser.error("--mode parse requires --input <file>")
    
    print(f"{colorize('[*]', 'info')} SSH Weak Algorithm Auditor v2")
    print(f"{colorize('[*]', 'info')} Mode: {args.mode}")
    
    # Get output content
    raw_content = None
    if args.mode == 'full':
        raw_content = run_ssh_audit(args.targets, args.timeout)
        output_content = raw_content
    else:
        if not os.path.exists(args.input_file):
            print(f"{colorize('Error', 'fail')}: Input file '{args.input_file}' not found")
            sys.exit(1)
        with open(args.input_file, 'r', encoding='utf-8') as f:
            output_content = f.read()
        print(f"{colorize('[*]', 'info')} Reading from: {args.input_file}")
    
    # Parse and process
    print(f"{colorize('[*]', 'info')} Parsing results...")
    results = parse_ssh_audit_output(output_content)
    weak_algos_by_target = extract_weak_algorithms(results)
    
    # Save raw output if in full mode
    raw_file_saved = None
    if args.mode == 'full' and raw_content:
        raw_file_saved = save_raw_output(raw_content, args.output)
    
    # Output
    print_results(results, weak_algos_by_target)
    write_report(results, weak_algos_by_target, args.output, raw_file_saved)
    
    # Summary
    total_targets = len(results)
    total_issues = sum(
        len(algos) 
        for severities in results.values() 
        for algo_types in severities.values() 
        for algos in algo_types.values()
    )
    total_unique_weak = len(set(algo for algos in weak_algos_by_target.values() for algo in algos))
    
    print(f"\n{colorize('='*70, 'section')}")
    print(f"{colorize('FINAL SUMMARY', 'target')}")
    print(f"{colorize('='*70, 'section')}")
    print(f"Targets analyzed: {total_targets}")
    print(f"Total detailed findings: {total_issues}")
    print(f"Unique weak algorithms: {total_unique_weak}")
    if total_unique_weak > 0:
        print(f"\n{colorize('⚠ Review the report and prioritize remediation!', 'warn')}")
    else:
        print(f"\n{colorize('✓ All scanned targets appear to use strong algorithms.', 'info')}")

if __name__ == '__main__':
    main()
