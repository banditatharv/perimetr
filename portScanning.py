import os
import sys
import time
import argparse
import subprocess
import shlex
import signal
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from datetime import datetime
from threading import Thread, Lock

import perimetrUI as ui

start_time = datetime.now()
tmux_sessions = []  # global list to track sessions
console = ui.console
lock = Lock()

def cleanup_tmux_sessions(sig, frame):
    console.print("\n[bold red]Scan interrupted! Cleaning up tmux sessions...[/]")
    for session in tmux_sessions:
        subprocess.run(["tmux", "kill-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sys.exit(1)

# Register signal handler for Ctrl+C
signal.signal(signal.SIGINT, cleanup_tmux_sessions)


def run_tmux_nmap(ip, output_dir, session_name, progress):
    start_time = datetime.now()
    with lock:
        progress.console.print(f"[green][+] Started scanning {ip} at {start_time.strftime('%H:%M:%S')}[/]")

    output_path = os.path.join(output_dir, ip)
    os.makedirs(output_dir, exist_ok=True)

    tmux_sessions.append(session_name)

    # tmux runs this inner string via `sh -c`; shell-quote every value taken
    # from the (untrusted) IP list to prevent command injection. The tmux call
    # itself is list-form (no outer shell).
    inner_cmd = (
        f"nmap -v -p- -Pn -T4 {shlex.quote(ip)} -oA {shlex.quote(output_path)}; "
        f"tmux kill-session -t {shlex.quote(session_name)}"
    )
    subprocess.run(["tmux", "new-session", "-d", "-s", session_name, inner_cmd])

def worker(ip_list, output_dir, max_parallel):
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn()
    )
    task = progress.add_task("Scanning IPs...", total=len(ip_list))

    active_sessions = []
    ip_index = 0

    with progress:
        while ip_index < len(ip_list) or active_sessions:
        # Clean up completed tmux sessions
            for session in active_sessions[:]:
                result = subprocess.run(["tmux", "has-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode != 0:
                    active_sessions.remove(session)
                    progress.advance(task)
                    end_time = datetime.now()
                    progress.console.print(f"[cyan][✔] Completed scanning {session.replace('_', '.')} at {end_time.strftime('%H:%M:%S')}[/]")

            # Start new scans if slots are available
            while ip_index < len(ip_list) and len(active_sessions) < max_parallel:
                ip = ip_list[ip_index]
                session_name = ip.replace('.', '_')
                run_tmux_nmap(ip, output_dir, session_name, progress)
                active_sessions.append(session_name)
                ip_index += 1

            time.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel Nmap Scanner with Tmux and Rich")
    parser.add_argument("-i", "--input", required=True, help="Path to file with IP list (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Directory to save Nmap output")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Number of concurrent scans")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        ui.error(f"Input file {args.input} not found.")
        sys.exit(1)

    with open(args.input, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    ui.banner("Full Port Scan", "Parallel nmap -p- via tmux")
    ui.info(f"Scan started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    worker(ips, args.output, args.threads)
    end_time = datetime.now()
    ui.summary("Scan Complete", [
        ("Started", start_time.strftime('%Y-%m-%d %H:%M:%S')),
        ("Completed", end_time.strftime('%Y-%m-%d %H:%M:%S')),
        ("Total duration", str(end_time - start_time)),
    ])