#!/usr/bin/env python3
"""
nmap_parser.py v2 - Nmap scan parser with service fingerprint analysis & service-grouped views
Usage:
  python3 nmap_parser.py <ip1> <ip2> ...
  python3 nmap_parser.py --all
  python3 nmap_parser.py --all --dir /path/to/scans --out /reports/run1
"""

import re, sys, os, json, argparse, csv
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════
#  ANSI COLORS
# ══════════════════════════════════════════════════════════════════
class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"
    BLUE="\033[34m"; MAGENTA="\033[35m"; CYAN="\033[36m"; WHITE="\033[37m"
    BRIGHT_RED="\033[91m"; BRIGHT_GREEN="\033[92m"; BRIGHT_YELLOW="\033[93m"
    BRIGHT_BLUE="\033[94m"; BRIGHT_MAGENTA="\033[95m"; BRIGHT_CYAN="\033[96m"
    BRIGHT_WHITE="\033[97m"; BG_RED="\033[41m"; BG_YELLOW="\033[43m"

def col(text, *codes): return "".join(codes) + str(text) + C.RESET

# ══════════════════════════════════════════════════════════════════
#  FINGERPRINT / INTELLIGENCE DATABASE
# ══════════════════════════════════════════════════════════════════

# Each rule: (id, severity, name, match_fn, description, detail, recommendation)
# severity: CRITICAL / HIGH / MEDIUM / INFO

FINGERPRINT_RULES = [

    # ── CRITICAL ────────────────────────────────────────────────
    ("FP-001", "CRITICAL",
     "JBoss Management Interface Exposed",
     lambda host: any(p["port"] == "4447" and "open" in p["state"] for p in host["ports"]),
     "JBoss Remoting port 4447 is publicly accessible.",
     "Port 4447 exposes the JBoss management interface. Unauthenticated RCE has been demonstrated "
     "against JBoss (CVE-2017-12149, CVE-2015-7501). Attackers can deploy malicious WAR files via "
     "JMX invoker or HTTP invoker endpoints.",
     "Restrict 4447 to management networks only via firewall rules. Disable HTTP invoker if unused. "
     "Upgrade to a supported EAP/WildFly version."),

    ("FP-002", "CRITICAL",
     "Unauthenticated Prometheus Metrics Endpoint",
     lambda host: any(
         int(p["port"]) in range(3239, 3254) and "open" in p["state"]
         and ("text/plain" in p["version"].lower() or "jvm_memory" in p["version"].lower() or p["version"] == "")
         for p in host["ports"]
     ),
     "Prometheus JVM metrics are exposed without authentication on ports 3239–3253.",
     "These endpoints leak detailed JVM internals: heap usage, GC behaviour, thread counts, "
     "class loading, and custom application metrics. Attackers can map the internal application "
     "stack, identify memory pressure, and enumerate running services without any credentials.",
     "Place metrics endpoints behind a reverse proxy with HTTP basic auth or mTLS. "
     "Restrict access to monitoring subnets only. Consider using a push-based metrics model."),

    ("FP-003", "CRITICAL",
     "SMB Direct Port Exposed",
     lambda host: any(p["port"] == "5445" and "open" in p["state"] for p in host["ports"]),
     "SMBDirect (port 5445) is open and accessible.",
     "SMBDirect (RDMA over SMB) on 5445 is rarely needed externally. SMB services have a long "
     "history of critical RCE (EternalBlue/MS17-010, PrintNightmare). Exposure increases attack surface "
     "significantly especially combined with other open services on this host.",
     "Block port 5445 at the firewall unless RDMA is explicitly required. Ensure SMB signing is enforced."),

    ("FP-004", "CRITICAL",
     "Dual SSH Ports (Possible Backdoor or Misconfiguration)",
     lambda host: (
         sum(1 for p in host["ports"] if p["service"] == "ssh" and "open" in p["state"]) >= 2
     ),
     "SSH is listening on multiple ports (22 and 222 detected).",
     "Running SSH on a non-standard port alongside the standard port can indicate a misconfiguration "
     "or a deliberately hidden access path. Port 222 SSH shares identical host keys to port 22, "
     "suggesting it is the same daemon — possibly left as an administrative backdoor.",
     "Audit why SSH runs on port 222. If not required, close it. Ensure both ports are covered "
     "by the same access controls and fail2ban/IPS rules."),

    # ── HIGH ────────────────────────────────────────────────────
    ("FP-005", "HIGH",
     "Apache Tomcat HTTP Interface Exposed",
     lambda host: any(
         p["service"] in ("http", "https") and "tomcat" in p["version"].lower() and "open" in p["state"]
         for p in host["ports"]
     ),
     "Apache Tomcat is serving HTTP on one or more ports.",
     "Tomcat instances (7480, 7570, 8082 detected) expose JSP/servlet execution. Common attack vectors: "
     "Ghostcat (CVE-2020-1938, AJP connector), deserialization via manager app, default credentials "
     "on /manager/html, and PUT method file upload (CVE-2017-12617).",
     "Disable the AJP connector if not needed (port 8009). Remove or password-protect /manager. "
     "Apply latest Tomcat security patches. Restrict PUT/DELETE methods."),

    ("FP-006", "HIGH",
     "RPC Bind Exposed",
     lambda host: any(p["port"] == "111" and "open" in p["state"] for p in host["ports"]),
     "RPC portmapper (port 111) is open.",
     "RPC portmapper allows enumeration of all registered RPC services. Attackers can use rpcinfo "
     "to map the full RPC service landscape. Combined with NFS or NIS exposure this can lead to "
     "unauthenticated data access.",
     "Block port 111 at perimeter firewall. If RPC is required internally, restrict by IP. "
     "Audit which RPC services are registered."),

    ("FP-007", "HIGH",
     "Large Number of Unidentified Open Ports (> 15)",
     lambda host: sum(1 for p in host["ports"] if "open" in p["state"]) > 15,
     "This host has more than 15 open ports — unusually high attack surface.",
     "A large open port count increases attack surface and suggests either a multi-service "
     "application server or inadequate firewall controls. Each open port is a potential entry point. "
     "Combined with weak auth or unpatched services, this significantly raises risk.",
     "Audit each open port. Close anything not required. Apply firewall allowlisting rather than "
     "blocklisting. Document the purpose of every listening service."),

    ("FP-008", "HIGH",
     "Zabbix Agent Port Exposed",
     lambda host: any(p["port"] == "10050" and "open" in p["state"] for p in host["ports"]),
     "Zabbix agent port 10050 is accessible.",
     "The Zabbix agent allows the Zabbix server to execute arbitrary commands on the monitored host. "
     "If the agent is in active mode or misconfigured, an attacker who can reach port 10050 may be "
     "able to execute OS commands (CVE-2019-15132, CVE-2022-23134).",
     "Restrict port 10050 to the Zabbix server IP only. Ensure 'EnableRemoteCommands=0' in "
     "zabbix_agentd.conf unless required. Keep Zabbix agent updated."),

    # ── MEDIUM ──────────────────────────────────────────────────
    ("FP-009", "MEDIUM",
     "Filtered Ports Detected (Potential Firewall Bypass Opportunity)",
     lambda host: any("filtered" in p["state"] for p in host["ports"]),
     "Some ports are in 'filtered' state rather than closed.",
     "Filtered ports indicate a firewall is dropping packets rather than rejecting them. While "
     "this provides some protection, filtered ports may be reachable from different network segments "
     "or via pivoting from compromised internal hosts.",
     "Confirm all filtered ports are intentionally firewalled. Validate rules apply to all "
     "network paths including internal/lateral movement scenarios."),

    ("FP-010", "MEDIUM",
     "JBoss + Tomcat Combo (Potential Shared Classpath Attack Surface)",
     lambda host: (
         any(p["port"] == "4447" and "open" in p["state"] for p in host["ports"]) and
         any("tomcat" in p["version"].lower() and "open" in p["state"] for p in host["ports"])
     ),
     "Both JBoss Remoting and Apache Tomcat are running on the same host.",
     "Co-location of JBoss and Tomcat on a single host multiplies the attack surface. A compromise "
     "via either service provides lateral access to the other. Shared JVM or classpath components "
     "may expose additional deserialization or class injection paths.",
     "Isolate application servers into separate VMs/containers. Apply least-privilege to service "
     "accounts so a Tomcat compromise does not allow JBoss access and vice versa."),

    ("FP-011", "MEDIUM",
     "APC / Power Management Port Open",
     lambda host: any(p["port"] == "5455" and "open" in p["state"] for p in host["ports"]),
     "Port 5455 (APC power management) is open.",
     "APC network management ports have historically had weak default credentials and "
     "unauthenticated access vulnerabilities. If this is an APC UPS or PDU management interface, "
     "an attacker could cut power to the system or pivot into the management network.",
     "Verify what service is running on 5455. If APC, change default credentials, restrict access "
     "to management VLAN, and check for firmware updates."),

    # ── INFO ────────────────────────────────────────────────────
    ("FP-012", "INFO",
     "SSH Version Identified: OpenSSH 8.0",
     lambda host: any(
         "openssh 8.0" in p["version"].lower() and "open" in p["state"]
         for p in host["ports"]
     ),
     "OpenSSH 8.0 is in use — relatively old, check for known CVEs.",
     "OpenSSH 8.0 was released in 2019. While not critically vulnerable, several CVEs have been "
     "published since (CVE-2023-38408 ssh-agent RCE, CVE-2021-41617 privilege escalation). "
     "Current stable is 9.x.",
     "Upgrade OpenSSH to latest stable. Ensure MaxAuthTries is set low and key-based auth is enforced."),

    ("FP-013", "INFO",
     "Prometheus Metrics Leaking JVM Version Information",
     lambda host: any(
         int(p["port"]) in range(3239, 3254) and "open" in p["state"]
         for p in host["ports"]
     ),
     "JVM pool names in Prometheus output reveal GC type and memory layout.",
     "CMS/G1/ParNew/PS collector names visible in metrics help attackers fingerprint the exact "
     "JVM version and GC configuration, narrowing exploit selection for deserialization attacks.",
     "Even if metrics are auth-protected, review what labels/dimensions are exposed. "
     "Avoid exposing JVM internal pool names externally."),
]


SERVICE_CATEGORIES = {
    "Remote Access":     ["ssh", "telnet", "rdp", "vnc", "rlogin"],
    "Web / App Server":  ["http", "https", "tomcat", "jboss", "weblogic", "websphere", "glassfish"],
    "File Transfer":     ["ftp", "sftp", "ftps", "tftp", "nfs", "smb", "smbdirect"],
    "Database":          ["mysql", "postgres", "mssql", "oracle", "redis", "mongodb", "cassandra", "db2"],
    "Monitoring":        ["zabbix", "prometheus", "nagios", "graphite", "influx"],
    "Messaging / RPC":   ["jboss-remoting", "rpcbind", "amqp", "mqtt", "activemq", "rabbitmq"],
    "Mail":              ["smtp", "imap", "pop3", "sendmail", "postfix"],
    "Directory":         ["ldap", "ldaps", "kerberos", "radius"],
    "Infrastructure":    ["dns", "ntp", "snmp", "dhcp", "bgp"],
    "Unknown / Wrapped": ["tcpwrapped", "unknown"],
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
SEVERITY_COLOR = {
    "CRITICAL": (C.BG_RED, C.BRIGHT_WHITE, C.BOLD),
    "HIGH":     (C.BRIGHT_RED, C.BOLD),
    "MEDIUM":   (C.BRIGHT_YELLOW,),
    "INFO":     (C.CYAN,),
}
SEVERITY_HTML_CLASS = {
    "CRITICAL": "sev-critical",
    "HIGH":     "sev-high",
    "MEDIUM":   "sev-medium",
    "INFO":     "sev-info",
}

# ══════════════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════

def run_fingerprints(host):
    """Run all fingerprint rules against a host, return matching findings."""
    findings = []
    for rule in FINGERPRINT_RULES:
        fid, severity, name, match_fn, desc, detail, rec = rule
        try:
            if match_fn(host):
                findings.append({
                    "id": fid, "severity": severity, "name": name,
                    "description": desc, "detail": detail, "recommendation": rec
                })
        except Exception:
            pass
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings

def categorise_service(service_name):
    s = service_name.lower()
    for cat, keywords in SERVICE_CATEGORIES.items():
        for kw in keywords:
            if kw in s:
                return cat
    return "Other"

def build_service_map(all_data):
    """
    Returns dict: { category -> [ {ip, hostname, port, state, service, version} ] }
    """
    smap = defaultdict(list)
    for host in all_data:
        for p in host["ports"]:
            if "open" not in p["state"]:
                continue
            cat = categorise_service(p["service"])
            smap[cat].append({
                "ip":       host["host"] or "",
                "hostname": host["hostname"] or "",
                "port":     p["port"],
                "protocol": p["protocol"],
                "state":    p["state"],
                "service":  p["service"],
                "version":  p["version"],
            })
    return dict(smap)

# ══════════════════════════════════════════════════════════════════
#  PARSER
# ══════════════════════════════════════════════════════════════════

def parse_nmap_file(filepath):
    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    result = {"file": str(filepath), "host": None, "hostname": None,
              "status": "unknown", "scan_time": None, "ports": [], "findings": []}

    m = re.search(r"scan initiated (.+?) as:", content)
    if m: result["scan_time"] = m.group(1).strip()

    m = re.search(r"Host is (up|down)", content, re.IGNORECASE)
    if m: result["status"] = m.group(1).lower()

    m = re.search(r"Nmap scan report for (.+)", content)
    if m:
        raw = m.group(1).strip()
        ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", raw)
        if ip_match:
            result["host"] = ip_match.group(1)
            result["hostname"] = raw.split("(")[0].strip()
        else:
            result["host"] = raw
            result["hostname"] = raw

    m = re.search(r"Service Info:.*Host:\s*(\S+)", content)
    if m: result["hostname"] = m.group(1).rstrip(";,")

    port_pattern = re.compile(
        r"^(\d+)/(\w+)\s+(open|closed|filtered|open\|filtered)\s+(\S+)(.*)$", re.MULTILINE)
    for pm in port_pattern.finditer(content):
        version = pm.group(5).strip()
        if len(version) > 90: version = version[:87] + "..."
        result["ports"].append({
            "port": pm.group(1), "protocol": pm.group(2),
            "state": pm.group(3), "service": pm.group(4), "version": version,
        })

    result["findings"] = run_fingerprints(result)
    return result


def find_nmap_files(ips, search_dir="."):
    found = {}
    search_path = Path(search_dir)
    if not ips:
        for f in search_path.glob("*.nmap"):
            found[f.stem] = f
        return found
    for ip in ips:
        candidates = list(search_path.glob(f"{ip}*.nmap")) + list(search_path.glob(f"*{ip}*.nmap"))
        found[ip] = candidates[0] if candidates else None
    return found

# ══════════════════════════════════════════════════════════════════
#  TERMINAL OUTPUT
# ══════════════════════════════════════════════════════════════════

def state_color(state):
    if "open" in state:   return col(state, C.BRIGHT_GREEN, C.BOLD)
    if "filtered" in state: return col(state, C.BRIGHT_YELLOW)
    if "closed" in state: return col(state, C.RED)
    return state

def service_color(service):
    risky = ["ssh","ftp","telnet","http","https","smb","rdp","vnc","mysql","postgres",
             "mssql","oracle","redis","mongodb","jboss","tomcat","rpcbind","nfs","zabbix"]
    s = service.lower()
    for r in risky:
        if r in s: return col(service, C.BRIGHT_YELLOW, C.BOLD)
    return col(service, C.CYAN)

def sev_label(severity):
    colors = SEVERITY_COLOR[severity]
    pad = f" {severity:<8} "
    return col(pad, *colors)

def print_banner():
    banner = r"""
  ███╗   ██╗███╗   ███╗ █████╗ ██████╗     ██████╗  █████╗ ██████╗ ███████╗███████╗██████╗
  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
  ██╔██╗ ██║██╔████╔██║███████║██████╔╝    ██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝
  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝     ██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗
  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║         ██║     ██║  ██║██║  ██║███████║███████╗██║  ██║
  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
"""
    print(col(banner, C.BRIGHT_CYAN))
    print(col(f"  v2 — Fingerprint Engine + Service Intelligence  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", C.DIM))
    print(col("  " + "─"*92, C.DIM)); print()

def print_host_header(data):
    status_str = col("● UP", C.BRIGHT_GREEN, C.BOLD) if data["status"]=="up" else col("● DOWN", C.BRIGHT_RED, C.BOLD)
    host_str   = col(data["host"] or "unknown", C.BRIGHT_WHITE, C.BOLD)
    hn_str     = col(f"({data['hostname']})", C.DIM) if data["hostname"] and data["hostname"] != data["host"] else ""
    print(col("  ┌─── HOST ", C.BLUE) + host_str + "  " + hn_str + "  " + status_str)
    if data["scan_time"]:
        print(col("  │     Scanned: ", C.DIM) + col(data["scan_time"], C.DIM))
    print(col("  │", C.BLUE))

def print_ports_table(ports):
    if not ports:
        print(col("  │  No ports found.", C.DIM)); print(); return
    W = {"port":10,"proto":6,"state":16,"service":22,"version":58}
    def hdr(t,w): return col(t.ljust(w), C.BOLD, C.BRIGHT_WHITE)
    print("  │  " + hdr("PORT",W["port"]) + hdr("PROTO",W["proto"]) +
          hdr("STATE",W["state"]) + hdr("SERVICE",W["service"]) + hdr("VERSION / INFO",W["version"]))
    print(col("  │  " + "─"*(sum(W.values())+4), C.DIM))
    for p in ports:
        print(f"  │  "
              f"{col(f'{p['port']}/{p['protocol']}'.ljust(W['port']), C.BRIGHT_MAGENTA)}"
              f"{col(p['protocol'].ljust(W['proto']), C.DIM)}"
              f"{state_color(p['state']).ljust(W['state']+10)}"
              f"{service_color(p['service']).ljust(W['service']+10)}"
              f"{col(p['version'][:W['version']], C.WHITE)}")
    print(col("  └"+"─"*96, C.BLUE)); print()

def print_findings(findings):
    if not findings:
        print(col("  ✓  No fingerprint matches for this host.", C.BRIGHT_GREEN)); print(); return
    print(col("  ┌─── FINGERPRINT FINDINGS ─────────────────────────────────", C.BRIGHT_RED, C.BOLD))
    for f in findings:
        print(col("  │", C.BRIGHT_RED))
        print(f"  │  {sev_label(f['severity'])}  {col(f['name'], C.BRIGHT_WHITE, C.BOLD)}  {col(f['id'], C.DIM)}")
        print(f"  │  {col('  ▸ ', C.DIM)}{col(f['description'], C.WHITE)}")
        # wrap detail at 90 chars
        detail_words = f["detail"].split()
        line, lines = [], []
        for w in detail_words:
            if sum(len(x)+1 for x in line) + len(w) > 88:
                lines.append(" ".join(line)); line = [w]
            else: line.append(w)
        if line: lines.append(" ".join(line))
        for l in lines:
            print(f"  │    {col(l, C.DIM)}")
        print(f"  │  {col('  ✎ ', C.BRIGHT_YELLOW)}{col('Recommendation: ', C.BRIGHT_YELLOW, C.BOLD)}{col(f['recommendation'][:90], C.YELLOW)}")
    print(col("  └"+"─"*96, C.BRIGHT_RED)); print()

def print_service_map(smap):
    print(col("\n  ╔══════════════════════ SERVICE INTELLIGENCE MAP ═══════════════════════╗", C.BRIGHT_MAGENTA, C.BOLD))
    for cat, entries in sorted(smap.items()):
        print(col(f"\n  ║  📂 {cat}", C.BRIGHT_MAGENTA, C.BOLD) + col(f"  ({len(entries)} port{'s' if len(entries)!=1 else ''})", C.DIM))
        print(col("  ║  " + "─"*68, C.DIM))
        # unique IPs for this category
        ips_in_cat = sorted(set(e["ip"] for e in entries))
        for ip in ips_in_cat:
            ip_entries = [e for e in entries if e["ip"]==ip]
            hn = ip_entries[0]["hostname"] if ip_entries[0]["hostname"] != ip else ""
            hn_str = col(f" ({hn})", C.DIM) if hn else ""
            print(f"  ║    {col(ip, C.BRIGHT_MAGENTA, C.BOLD)}{hn_str}")
            for e in ip_entries:
                ver = f"  — {e['version'][:50]}" if e["version"] else ""
                print(f"  ║       {col(f'{e['port']}/{e['protocol']}', C.CYAN):<18}"
                      f"{service_color(e['service']):<30}{col(ver, C.DIM)}")
    print(col("\n  ╚"+"═"*72+"╝\n", C.BRIGHT_MAGENTA, C.BOLD))

def print_summary(all_data):
    total   = len(all_data)
    up      = sum(1 for d in all_data if d["status"]=="up")
    op      = sum(len([p for p in d["ports"] if "open" in p["state"]]) for d in all_data)
    crit    = sum(len([f for f in d["findings"] if f["severity"]=="CRITICAL"]) for d in all_data)
    high    = sum(len([f for f in d["findings"] if f["severity"]=="HIGH"])     for d in all_data)
    med     = sum(len([f for f in d["findings"] if f["severity"]=="MEDIUM"])   for d in all_data)
    info    = sum(len([f for f in d["findings"] if f["severity"]=="INFO"])     for d in all_data)

    print(col("\n  ╔══════════════════════════════ SCAN SUMMARY ══════════════════════════════╗", C.BRIGHT_CYAN, C.BOLD))
    print(col(f"  ║  Hosts: {total}  Up: {up}  Down: {total-up}   │  Open ports: {op}", C.BRIGHT_CYAN))
    print(col(f"  ║  Findings ──  ", C.BRIGHT_CYAN) +
          col(f"CRITICAL: {crit} ", C.BRIGHT_RED, C.BOLD) +
          col(f"│ HIGH: {high} ", C.BRIGHT_RED) +
          col(f"│ MEDIUM: {med} ", C.BRIGHT_YELLOW) +
          col(f"│ INFO: {info}", C.CYAN))
    print(col("  ╚"+"═"*76+"╝\n", C.BRIGHT_CYAN, C.BOLD))

    W = [18, 20, 7, 6, 9, 5, 6, 5]
    hdrs = ["IP","HOSTNAME","STATUS","OPEN","CRITICAL","HIGH","MED","INFO"]
    print("  " + "  ".join(col(h.ljust(w), C.BOLD, C.BRIGHT_WHITE) for h,w in zip(hdrs,W)))
    print(col("  "+"─"*90, C.DIM))
    for d in all_data:
        fc   = len([f for f in d["findings"] if f["severity"]=="CRITICAL"])
        fh   = len([f for f in d["findings"] if f["severity"]=="HIGH"])
        fm   = len([f for f in d["findings"] if f["severity"]=="MEDIUM"])
        fi   = len([f for f in d["findings"] if f["severity"]=="INFO"])
        opc  = len([p for p in d["ports"] if "open" in p["state"]])
        ip   = (d["host"] or "?").ljust(W[0])
        hn   = (d["hostname"] or "")[:W[1]].ljust(W[1])
        st   = (col("UP",C.BRIGHT_GREEN,C.BOLD) if d["status"]=="up" else col("DOWN",C.RED,C.BOLD)).ljust(W[2]+10)
        print(f"  {col(ip,C.BRIGHT_MAGENTA)}  {col(hn,C.DIM)}  {st}  "
              f"{col(str(opc).ljust(W[3]),C.BRIGHT_YELLOW)}  "
              f"{col(str(fc).ljust(W[4]),C.BRIGHT_RED,C.BOLD) if fc else col(str(fc).ljust(W[4]),C.DIM)}  "
              f"{col(str(fh).ljust(W[5]),C.BRIGHT_RED) if fh else col(str(fh).ljust(W[5]),C.DIM)}  "
              f"{col(str(fm).ljust(W[6]),C.BRIGHT_YELLOW) if fm else col(str(fm).ljust(W[6]),C.DIM)}  "
              f"{col(str(fi).ljust(W[7]),C.CYAN) if fi else col(str(fi).ljust(W[7]),C.DIM)}")
    print()

# ══════════════════════════════════════════════════════════════════
#  HTML REPORT
# ══════════════════════════════════════════════════════════════════

def generate_html(all_data, smap, output_path):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── counts ──
    total  = len(all_data)
    up     = sum(1 for d in all_data if d["status"]=="up")
    op     = sum(len([p for p in d["ports"] if "open" in p["state"]]) for d in all_data)
    crit   = sum(len([f for f in d["findings"] if f["severity"]=="CRITICAL"]) for d in all_data)
    high   = sum(len([f for f in d["findings"] if f["severity"]=="HIGH"])     for d in all_data)
    med    = sum(len([f for f in d["findings"] if f["severity"]=="MEDIUM"])   for d in all_data)
    totalF = sum(len(d["findings"]) for d in all_data)

    # ── port rows ──
    port_rows = ""
    for d in all_data:
        fc = len([f for f in d["findings"] if f["severity"]=="CRITICAL"])
        fh = len([f for f in d["findings"] if f["severity"]=="HIGH"])
        risk_badge = ""
        if fc: risk_badge += f'<span class="badge sev-critical">CRIT:{fc}</span> '
        if fh: risk_badge += f'<span class="badge sev-high">HIGH:{fh}</span>'
        for p in d["ports"]:
            sc = "open" if "open" in p["state"] else ("filtered" if "filtered" in p["state"] else "closed")
            cat = categorise_service(p["service"])
            port_rows += f"""<tr data-state="{sc}" data-cat="{cat}">
  <td class="ip">{d['host'] or ''}</td>
  <td class="dim">{d['hostname'] or ''}</td>
  <td class="{'status-up' if d['status']=='up' else 'status-down'}">{d['status'].upper()}</td>
  <td class="port">{p['port']}/{p['protocol']}</td>
  <td class="{sc} fw">{p['state'].upper()}</td>
  <td class="service">{p['service']}</td>
  <td><span class="cat-badge">{cat}</span></td>
  <td class="dim small">{p['version']}</td>
  <td>{risk_badge}</td>
</tr>"""

    # ── findings rows ──
    findings_rows = ""
    for d in all_data:
        for f in d["findings"]:
            findings_rows += f"""<tr class="finding-row" data-sev="{f['severity']}">
  <td><span class="badge {SEVERITY_HTML_CLASS[f['severity']]}">{f['severity']}</span></td>
  <td class="dim small">{f['id']}</td>
  <td class="ip">{d['host'] or ''}</td>
  <td class="dim small">{d['hostname'] or ''}</td>
  <td class="fw">{f['name']}</td>
  <td class="dim small">{f['description']}</td>
  <td class="dim small rec">{f['recommendation']}</td>
</tr>"""

    # ── service map cards ──
    smap_html = ""
    cat_icons = {
        "Remote Access":"🔐","Web / App Server":"🌐","File Transfer":"📁",
        "Database":"🗄️","Monitoring":"📊","Messaging / RPC":"📨",
        "Mail":"✉️","Directory":"📒","Infrastructure":"⚙️",
        "Unknown / Wrapped":"❓","Other":"📦"
    }
    for cat in sorted(smap.keys()):
        entries = smap[cat]
        icon = cat_icons.get(cat,"📦")
        ip_groups = defaultdict(list)
        for e in entries: ip_groups[e["ip"]].append(e)

        ip_html = ""
        for ip, elist in sorted(ip_groups.items()):
            hn = elist[0]["hostname"] if elist[0]["hostname"] != ip else ""
            hn_tag = f'<span class="dim small"> ({hn})</span>' if hn else ""
            port_tags = ""
            for e in elist:
                ver = f'<span class="ver"> — {e["version"][:55]}</span>' if e["version"] else ""
                port_tags += f'<div class="smap-port"><span class="port">{e["port"]}/{e["protocol"]}</span> <span class="service">{e["service"]}</span>{ver}</div>'
            ip_html += f'<div class="smap-ip"><div class="smap-ip-header"><span class="ip">{ip}</span>{hn_tag}</div>{port_tags}</div>'

        smap_html += f"""<div class="smap-card">
  <div class="smap-cat-header">{icon} {cat} <span class="badge-count">{len(entries)}</span></div>
  <div class="smap-ips">{ip_html}</div>
</div>"""

    # ── inline summary cards for findings ──
    top_findings = sorted(
        [(d["host"], f) for d in all_data for f in d["findings"] if f["severity"] in ("CRITICAL","HIGH")],
        key=lambda x: SEVERITY_ORDER[x[1]["severity"]]
    )[:6]
    alert_cards = ""
    for ip, f in top_findings:
        alert_cards += f"""<div class="alert-card {SEVERITY_HTML_CLASS[f['severity']]}">
  <div class="alert-sev">{f['severity']}</div>
  <div class="alert-ip">{ip}</div>
  <div class="alert-name">{f['name']}</div>
  <div class="alert-rec">{f['recommendation'][:120]}...</div>
</div>"""
    if not alert_cards:
        alert_cards = '<div class="no-findings">✓ No critical or high severity findings</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nmap Report — {now}</title>
<style>
:root {{
  --bg:#0d1117; --bg2:#161b22; --bg3:#21262d; --border:#30363d;
  --text:#c9d1d9; --dim:#8b949e;
  --green:#3fb950; --yellow:#e3b341; --red:#f85149; --orange:#f0883e;
  --blue:#58a6ff; --purple:#bc8cff; --cyan:#39d353; --accent:#1f6feb;
  --crit-bg:#3d1c1c; --crit-fg:#ff6b6b;
  --high-bg:#3d2a0e; --high-fg:#f0883e;
  --med-bg:#2d2d0e;  --med-fg:#e3b341;
  --info-bg:#0e2035; --info-fg:#58a6ff;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:0}}

/* NAV */
.nav{{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 2rem;display:flex;align-items:center;gap:0;position:sticky;top:0;z-index:100}}
.nav-brand{{color:var(--blue);font-weight:700;font-size:1rem;padding:1rem 1.5rem 1rem 0;border-right:1px solid var(--border);margin-right:1rem}}
.nav-tab{{padding:.85rem 1.2rem;color:var(--dim);font-size:.85rem;cursor:pointer;border-bottom:2px solid transparent;transition:.15s;user-select:none;white-space:nowrap}}
.nav-tab:hover{{color:var(--text)}}
.nav-tab.active{{color:var(--blue);border-bottom-color:var(--blue)}}
.nav-right{{margin-left:auto;color:var(--dim);font-size:.75rem;padding:.85rem 0}}

/* PAGES */
.page{{display:none;padding:2rem;max-width:1600px;margin:0 auto}}
.page.active{{display:block}}

/* STAT CARDS */
.stats{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1rem 1.5rem;min-width:120px}}
.stat .lbl{{color:var(--dim);font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;margin-bottom:.3rem}}
.stat .val{{font-size:1.9rem;font-weight:700}}
.stat.crit .val{{color:var(--crit-fg)}} .stat.high .val{{color:var(--high-fg)}}
.stat.med  .val{{color:var(--med-fg)}}  .stat.up   .val{{color:var(--green)}}
.stat.ports .val{{color:var(--blue)}}

/* ALERT CARDS */
.alerts{{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem;margin-bottom:2rem}}
.alert-card{{border-radius:10px;padding:1rem 1.2rem;border-left:4px solid}}
.alert-card.sev-critical{{background:var(--crit-bg);border-color:var(--crit-fg)}}
.alert-card.sev-high{{background:var(--high-bg);border-color:var(--high-fg)}}
.alert-sev{{font-size:.7rem;font-weight:700;letter-spacing:.1em;margin-bottom:.25rem}}
.alert-card.sev-critical .alert-sev{{color:var(--crit-fg)}}
.alert-card.sev-high     .alert-sev{{color:var(--high-fg)}}
.alert-ip{{color:var(--purple);font-family:monospace;font-size:.85rem;margin-bottom:.2rem}}
.alert-name{{color:var(--text);font-weight:600;font-size:.9rem;margin-bottom:.4rem}}
.alert-rec{{color:var(--dim);font-size:.78rem;line-height:1.5}}
.no-findings{{color:var(--green);padding:1rem;background:var(--bg2);border-radius:8px;border:1px solid var(--border)}}

/* TABLES */
.filter-bar{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center}}
.filter-bar input,.filter-bar select{{background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:.4rem .8rem;border-radius:6px;font-size:.85rem;outline:none}}
.filter-bar input:focus{{border-color:var(--accent)}}
.filter-bar label{{color:var(--dim);font-size:.8rem}}
.tbl-wrap{{overflow-x:auto;border-radius:10px;border:1px solid var(--border)}}
table{{width:100%;border-collapse:collapse;background:var(--bg2)}}
thead{{background:var(--bg3)}}
th{{padding:.65rem 1rem;text-align:left;color:var(--dim);font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{color:var(--blue)}}
td{{padding:.5rem 1rem;font-size:.83rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover{{background:var(--bg3)}}
.ip{{color:var(--purple);font-family:monospace;font-weight:700}}
.port{{color:var(--cyan);font-family:monospace}}
.service{{color:var(--yellow);font-weight:500}}
.dim{{color:var(--dim)}}
.small{{font-size:.78rem}}
.fw{{font-weight:600}}
.ver{{color:var(--dim);font-size:.76rem}}
.open{{color:var(--green)}} .filtered{{color:var(--yellow)}} .closed{{color:var(--red)}}
.status-up{{color:var(--green);font-weight:700}} .status-down{{color:var(--red);font-weight:700}}
.rec{{max-width:280px;line-height:1.5}}

/* BADGES */
.badge{{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.7rem;font-weight:700;margin-right:.2rem}}
.sev-critical{{background:var(--crit-bg);color:var(--crit-fg)}}
.sev-high{{background:var(--high-bg);color:var(--high-fg)}}
.sev-medium{{background:var(--med-bg);color:var(--med-fg)}}
.sev-info{{background:var(--info-bg);color:var(--info-fg)}}
.cat-badge{{background:var(--bg3);color:var(--blue);border:1px solid var(--border);padding:.1rem .45rem;border-radius:6px;font-size:.72rem}}
.badge-count{{background:var(--bg3);color:var(--dim);border:1px solid var(--border);padding:.05rem .4rem;border-radius:999px;font-size:.72rem;margin-left:.4rem}}

/* SERVICE MAP */
.smap-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1rem}}
.smap-card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
.smap-cat-header{{background:var(--bg3);padding:.75rem 1rem;font-weight:700;font-size:.9rem;color:var(--blue);border-bottom:1px solid var(--border)}}
.smap-ips{{padding:.75rem 1rem}}
.smap-ip{{margin-bottom:.75rem;padding-bottom:.75rem;border-bottom:1px solid var(--border)}}
.smap-ip:last-child{{margin-bottom:0;padding-bottom:0;border-bottom:none}}
.smap-ip-header{{margin-bottom:.35rem}}
.smap-port{{font-size:.82rem;padding:.15rem 0;display:flex;align-items:baseline;gap:.4rem}}
.smap-port .port{{min-width:90px}}

/* FINDINGS PAGE */
.findings-filter{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
.sev-btn{{padding:.35rem .9rem;border-radius:6px;border:1px solid var(--border);font-size:.78rem;cursor:pointer;background:var(--bg2);color:var(--dim);transition:.15s}}
.sev-btn:hover{{color:var(--text)}}
.sev-btn.active-crit{{background:var(--crit-bg);color:var(--crit-fg);border-color:var(--crit-fg)}}
.sev-btn.active-high{{background:var(--high-bg);color:var(--high-fg);border-color:var(--high-fg)}}
.sev-btn.active-med {{background:var(--med-bg); color:var(--med-fg); border-color:var(--med-fg)}}
.sev-btn.active-info{{background:var(--info-bg);color:var(--info-fg);border-color:var(--info-fg)}}

h2{{color:var(--text);font-size:1.1rem;margin-bottom:1rem;font-weight:600}}
.section-desc{{color:var(--dim);font-size:.83rem;margin-bottom:1.2rem;line-height:1.6}}
footer{{padding:2rem;text-align:center;color:var(--dim);font-size:.75rem;border-top:1px solid var(--border)}}
</style>
</head>
<body>

<nav class="nav">
  <div class="nav-brand">🔍 NMAP PARSER</div>
  <div class="nav-tab active" onclick="showPage('overview',this)">Overview</div>
  <div class="nav-tab" onclick="showPage('ports',this)">Port Table</div>
  <div class="nav-tab" onclick="showPage('findings',this)">Findings <span class="badge sev-critical" style="font-size:.65rem">{crit}</span> <span class="badge sev-high">{high}</span></div>
  <div class="nav-tab" onclick="showPage('services',this)">Service Map</div>
  <div class="nav-right">{now}</div>
</nav>

<!-- ═══════════════ OVERVIEW PAGE ═══════════════ -->
<div id="page-overview" class="page active">
  <h2>Scan Overview</h2>
  <div class="stats">
    <div class="stat up"><div class="lbl">Hosts Up</div><div class="val">{up}/{total}</div></div>
    <div class="stat ports"><div class="lbl">Open Ports</div><div class="val">{op}</div></div>
    <div class="stat crit"><div class="lbl">Critical</div><div class="val">{crit}</div></div>
    <div class="stat high"><div class="lbl">High</div><div class="val">{high}</div></div>
    <div class="stat med"><div class="lbl">Medium</div><div class="val">{med}</div></div>
    <div class="stat"><div class="lbl">Total Findings</div><div class="val" style="color:var(--blue)">{totalF}</div></div>
  </div>

  <h2 style="margin-bottom:.6rem">⚠️ Critical &amp; High Findings</h2>
  <div class="section-desc">Top priority issues identified across all scanned hosts. Address CRITICAL findings immediately.</div>
  <div class="alerts">{alert_cards}</div>

  <h2 style="margin-bottom:.6rem">Host Summary</h2>
  <div class="tbl-wrap">
  <table>
    <thead><tr>
      <th onclick="sortTable('hostTbl',0)">IP ↕</th>
      <th onclick="sortTable('hostTbl',1)">Hostname ↕</th>
      <th onclick="sortTable('hostTbl',2)">Status ↕</th>
      <th onclick="sortTable('hostTbl',3)">Open ↕</th>
      <th>Critical</th><th>High</th><th>Medium</th><th>Info</th>
      <th>Top Services</th>
    </tr></thead>
    <tbody id="hostTbl">
    {''.join(f"""<tr>
      <td class="ip">{d['host'] or ''}</td>
      <td class="dim small">{d['hostname'] or ''}</td>
      <td class="{'status-up' if d['status']=='up' else 'status-down'}">{d['status'].upper()}</td>
      <td class="fw" style="color:var(--blue)">{len([p for p in d['ports'] if 'open' in p['state']])}</td>
      <td>{"<span class='badge sev-critical'>" + str(len([f for f in d['findings'] if f['severity']=='CRITICAL'])) + "</span>" if any(f['severity']=='CRITICAL' for f in d['findings']) else '<span class="dim">—</span>'}</td>
      <td>{"<span class='badge sev-high'>"     + str(len([f for f in d['findings'] if f['severity']=='HIGH']))     + "</span>" if any(f['severity']=='HIGH'     for f in d['findings']) else '<span class="dim">—</span>'}</td>
      <td>{"<span class='badge sev-medium'>"   + str(len([f for f in d['findings'] if f['severity']=='MEDIUM']))   + "</span>" if any(f['severity']=='MEDIUM'   for f in d['findings']) else '<span class="dim">—</span>'}</td>
      <td>{"<span class='badge sev-info'>"     + str(len([f for f in d['findings'] if f['severity']=='INFO']))     + "</span>" if any(f['severity']=='INFO'     for f in d['findings']) else '<span class="dim">—</span>'}</td>
      <td class="dim small">{', '.join(sorted(set(p['service'] for p in d['ports'] if 'open' in p['state']))[:5])}</td>
    </tr>""" for d in all_data)}
    </tbody>
  </table></div>
</div>

<!-- ═══════════════ PORTS PAGE ═══════════════ -->
<div id="page-ports" class="page">
  <h2>Port Table</h2>
  <div class="filter-bar">
    <input type="text" id="portSearch" placeholder="🔎 Search IP, service, version..." oninput="filterPorts()" style="width:300px"/>
    <select id="portState" onchange="filterPorts()">
      <option value="">All States</option>
      <option value="open">Open</option>
      <option value="filtered">Filtered</option>
      <option value="closed">Closed</option>
    </select>
    <select id="portCat" onchange="filterPorts()">
      <option value="">All Categories</option>
      {''.join(f'<option value="{c}">{c}</option>' for c in sorted(smap.keys()))}
    </select>
  </div>
  <div class="tbl-wrap">
  <table>
    <thead><tr>
      <th onclick="sortTable('portTbl',0)">IP ↕</th>
      <th onclick="sortTable('portTbl',1)">Hostname</th>
      <th onclick="sortTable('portTbl',2)">Status</th>
      <th onclick="sortTable('portTbl',3)">Port ↕</th>
      <th onclick="sortTable('portTbl',4)">State ↕</th>
      <th onclick="sortTable('portTbl',5)">Service ↕</th>
      <th>Category</th>
      <th>Version / Info</th>
      <th>Findings</th>
    </tr></thead>
    <tbody id="portTbl">{port_rows}</tbody>
  </table></div>
</div>

<!-- ═══════════════ FINDINGS PAGE ═══════════════ -->
<div id="page-findings" class="page">
  <h2>Fingerprint Findings</h2>
  <div class="section-desc">
    Automated fingerprint analysis against {len(FINGERPRINT_RULES)} rules covering known dangerous service combinations,
    misconfigurations, and exposed management interfaces.
  </div>
  <div class="findings-filter">
    <button class="sev-btn" onclick="filterFindings(this,'')">All</button>
    <button class="sev-btn" onclick="filterFindings(this,'CRITICAL')">CRITICAL ({crit})</button>
    <button class="sev-btn" onclick="filterFindings(this,'HIGH')">HIGH ({high})</button>
    <button class="sev-btn" onclick="filterFindings(this,'MEDIUM')">MEDIUM ({med})</button>
    <button class="sev-btn" onclick="filterFindings(this,'INFO')">INFO</button>
  </div>
  <div class="tbl-wrap">
  <table>
    <thead><tr>
      <th onclick="sortTable('findTbl',0)">Severity ↕</th>
      <th>ID</th>
      <th onclick="sortTable('findTbl',2)">IP ↕</th>
      <th>Hostname</th>
      <th>Finding</th>
      <th>Description</th>
      <th>Recommendation</th>
    </tr></thead>
    <tbody id="findTbl">{findings_rows}</tbody>
  </table></div>
</div>

<!-- ═══════════════ SERVICE MAP PAGE ═══════════════ -->
<div id="page-services" class="page">
  <h2>Service Intelligence Map</h2>
  <div class="section-desc">
    All open ports grouped by service category. Each card shows which hosts expose a given service type,
    making it easy to audit exposure by function (e.g. find every host running a web server or database).
  </div>
  <div class="smap-grid">{smap_html}</div>
</div>

<footer>nmap_parser.py v2 — {total} hosts — {len(FINGERPRINT_RULES)} fingerprint rules — {now}</footer>

<script>
// ── PAGE NAVIGATION ──
function showPage(id, tab) {{
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  tab.classList.add('active');
}}

// ── PORT FILTER ──
function filterPorts() {{
  const q    = document.getElementById('portSearch').value.toLowerCase();
  const st   = document.getElementById('portState').value;
  const cat  = document.getElementById('portCat').value;
  document.querySelectorAll('#portTbl tr').forEach(r => {{
    const txt  = r.innerText.toLowerCase();
    const rs   = r.dataset.state || '';
    const rc   = r.dataset.cat  || '';
    r.style.display = (!q || txt.includes(q)) && (!st || rs===st) && (!cat || rc===cat) ? '' : 'none';
  }});
}}

// ── FINDINGS FILTER ──
function filterFindings(btn, sev) {{
  document.querySelectorAll('.sev-btn').forEach(b => b.className = 'sev-btn');
  if (sev) btn.classList.add('active-' + sev.toLowerCase());
  else btn.classList.add('active-info');
  document.querySelectorAll('#findTbl tr').forEach(r => {{
    r.style.display = !sev || r.dataset.sev === sev ? '' : 'none';
  }});
}}

// ── SORT ──
const sortDirs = {{}};
function sortTable(tbodyId, col) {{
  const tbody = document.getElementById(tbodyId);
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const key   = tbodyId + col;
  sortDirs[key] = !sortDirs[key];
  rows.sort((a,b) => {{
    const av = a.cells[col]?.innerText || '';
    const bv = b.cells[col]?.innerText || '';
    return sortDirs[key]
      ? av.localeCompare(bv, undefined, {{numeric:true}})
      : bv.localeCompare(av, undefined, {{numeric:true}});
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

# ══════════════════════════════════════════════════════════════════
#  CSV
# ══════════════════════════════════════════════════════════════════

def generate_csv(all_data, base):
    # ports CSV
    with open(base + "_ports.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP","Hostname","Host Status","Port","Protocol","State","Service","Version","Category"])
        for d in all_data:
            for p in d["ports"]:
                w.writerow([d["host"] or "", d["hostname"] or "", d["status"],
                             p["port"], p["protocol"], p["state"], p["service"],
                             p["version"], categorise_service(p["service"])])
    # findings CSV
    with open(base + "_findings.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP","Hostname","ID","Severity","Finding","Description","Recommendation"])
        for d in all_data:
            for fi in d["findings"]:
                w.writerow([d["host"] or "", d["hostname"] or "",
                             fi["id"], fi["severity"], fi["name"],
                             fi["description"], fi["recommendation"]])

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Nmap parser v2 — fingerprint + service intelligence")
    ap.add_argument("ips", nargs="*")
    ap.add_argument("--all",      action="store_true")
    ap.add_argument("--dir",      default=".")
    ap.add_argument("--out",      default="./nmap_report")
    ap.add_argument("--no-html",  action="store_true")
    ap.add_argument("--no-csv",   action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    print_banner()

    if not args.ips and not args.all:
        print(col("  Usage:", C.BOLD), "python3 nmap_parser.py <ip1> <ip2> ...")
        print(col("         python3 nmap_parser.py --all [--dir /scans] [--out /reports/run1]", C.DIM))
        sys.exit(0)

    file_map = find_nmap_files(args.ips if not args.all else [], search_dir=args.dir)
    if not file_map:
        print(col("  [!] No .nmap files found.", C.RED)); sys.exit(1)

    all_data = []
    for key, fp in file_map.items():
        if fp is None:
            print(col(f"  [!] No .nmap file for: {key}", C.BRIGHT_YELLOW)); continue
        try:
            d = parse_nmap_file(fp)
            all_data.append(d)
            fc = len([f for f in d["findings"] if f["severity"]=="CRITICAL"])
            fh = len([f for f in d["findings"] if f["severity"]=="HIGH"])
            tag = col(f" [{fc}C {fh}H findings]", C.BRIGHT_RED) if fc or fh else ""
            print(col(f"  [+] Parsed: {fp}", C.BRIGHT_GREEN) + tag)
        except Exception as e:
            print(col(f"  [!] Error: {fp}: {e}", C.RED))

    if not all_data:
        print(col("\n  [!] Nothing to display.", C.RED)); sys.exit(1)

    print()

    # ── terminal output ──
    for d in all_data:
        print_host_header(d)
        print_ports_table(d["ports"])
        print_findings(d["findings"])

    # ── service map ──
    smap = build_service_map(all_data)
    print_service_map(smap)

    # ── summary ──
    print_summary(all_data)

    # ── files ──
    base = args.out
    saved = []
    if not args.no_html:
        hp = base + ".html"
        generate_html(all_data, smap, hp)
        saved.append(("HTML Report", hp))
    if not args.no_csv:
        generate_csv(all_data, base)
        saved.append(("CSV (ports)",    base+"_ports.csv"))
        saved.append(("CSV (findings)", base+"_findings.csv"))
    jp = base + ".json"
    with open(jp,"w") as f:
        json.dump(all_data, f, indent=2)
    saved.append(("JSON", jp))

    print(col("  ┌─── OUTPUT FILES ───────────────────────────", C.BRIGHT_CYAN))
    for lbl, p in saved:
        print(col(f"  │  {lbl:<22}", C.DIM) + col(p, C.BRIGHT_WHITE))
    print(col("  └────────────────────────────────────────────\n", C.BRIGHT_CYAN))


if __name__ == "__main__":
    main()
