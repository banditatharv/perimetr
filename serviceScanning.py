import os
import sys
import argparse
import subprocess
import shlex
import signal
import time
from datetime import datetime
from threading import Thread, Lock
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

import perimetrUI as ui

start_time = datetime.now()
tmux_sessions = []  # Track active tmux sessions for cleanup
console = ui.console
lock = Lock()

# Handle graceful exit + tmux session cleanup on Ctrl+C. Uses list-form
# subprocess calls (no shell) and finds sessions via `tmux list-sessions` so it
# cleans up every svcscan_ session, not just ones we managed to track.
def cleanup_tmux_sessions(sig, frame):
    console.print("\n[bold red]Scan interrupted! Cleaning up tmux sessions...[/]")
    result = subprocess.run(["tmux", "list-sessions", "-F", "#S"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    for session in result.stdout.decode().splitlines():
        if session.startswith("svcscan_"):
            subprocess.run(["tmux", "kill-session", "-t", session],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sys.exit(1)

signal.signal(signal.SIGINT, cleanup_tmux_sessions)


def run_tmux_nmap(ip, ports, output_dir, session_name, progress):
    start_time = datetime.now()
    with lock:
        progress.console.line()
        progress.console.print(f"[green][+] Started scanning {ip}:{ports} at {start_time.strftime('%H:%M:%S')}[/]")



    output_path = os.path.join(output_dir, ip)
    os.makedirs(output_dir, exist_ok=True)
    tmux_sessions.append(session_name)
    # tmux runs this inner string via `sh -c`, so every value interpolated from
    # the (untrusted) target file is shell-quoted to prevent command injection
    # (e.g. an ip like `1.2.3.4'; rm -rf ~; '`). The tmux invocation itself is a
    # list (no outer shell) so session_name/inner_cmd pass as literal argv.
    inner_cmd = (
        f"sudo nmap -v -p {shlex.quote(ports)} {shlex.quote(ip)} -Pn -sSCV -A "
        f"-oA {shlex.quote(output_path)}; "
        f"tmux kill-session -t {shlex.quote(session_name)}"
    )
    subprocess.run(["tmux", "new-session", "-d", "-s", session_name, inner_cmd])


def parse_input_file(path):
    ip_port_list = []
    with open(path, 'r') as f:
        for line in f:
            if ':' in line:
                ip, port_str = line.strip().split(':', 1)
                ip = ip.strip()
                ports = port_str.strip().replace(' ', '')
                ip_port_list.append((ip, ports))
    return ip_port_list


def worker(ip_port_list, output_dir, max_parallel):
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn()
    )
    task = progress.add_task("Scanning IPs...", total=len(ip_port_list))

    active_sessions = []
    ip_index = 0

    start_script_time = datetime.now()
    ui.info(f"Started at {start_script_time.strftime('%H:%M:%S')}")

    with progress:
        while ip_index < len(ip_port_list) or active_sessions:
            for session in active_sessions[:]:
                result = subprocess.run(["tmux", "has-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode != 0:
                    active_sessions.remove(session)
                    progress.advance(task)
                    with lock:
                        progress.console.line()
                        progress.console.print(f"[cyan][✔] Completed scanning {session.replace('svcscan_', '').replace('_', ':')}[/]")


            while ip_index < len(ip_port_list) and len(active_sessions) < max_parallel:
                ip, ports = ip_port_list[ip_index]
                session_name = f"svcscan_{ip.replace('.', '_')}_{ports.replace(',', '_')}"
                run_tmux_nmap(ip, ports, output_dir, session_name,progress)
                active_sessions.append(session_name)
                ip_index += 1

            time.sleep(1)

    end_script_time = datetime.now()
    ui.summary("Service/Version Scan Complete", [
        ("Started", start_script_time.strftime('%H:%M:%S')),
        ("Completed", end_script_time.strftime('%H:%M:%S')),
        ("Duration", str(end_script_time - start_script_time)),
    ])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Service & Version Nmap Scanner with Tmux and Rich")
    parser.add_argument("-i", "--input", help="Path to file with ip:port list (one per line)")
    parser.add_argument("--ip", help="Single IP address")
    parser.add_argument("--ports", help="Ports for single IP (comma separated)")
    parser.add_argument("-o", "--output", required=True, help="Directory to save Nmap output")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Number of concurrent scans")
    args = parser.parse_args()

    ip_port_list = []

    if args.input:
        if not os.path.exists(args.input):
            ui.error(f"Input file {args.input} not found.")
            sys.exit(1)
        ip_port_list = parse_input_file(args.input)
    elif args.ip and args.ports:
        ip_port_list = [(args.ip, args.ports)]
    else:
        ui.error("Either --input or both --ip and --ports must be provided.")
        sys.exit(1)

    ui.banner("Service/Version Scan", "Targeted nmap -sSCV -A via tmux")
    worker(ip_port_list, args.output, args.threads)