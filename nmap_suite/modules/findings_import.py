"""
findings_import.py - import nuclei and ssh-audit findings into the suite DB.

These are the two finding types that previously had no home in nmap_suite
(they lived in disconnected xlsx/txt files). Each importer reuses the parser
that already ships with the collection scripts at the repo root rather than
re-implementing the parsing:

  * nuclei  -> nucleiCombined.parse_nuclei_file (per-.md parser)
  * ssh     -> sshWeakCiphersAudit.parse_ssh_audit_output (raw output parser)

Both importers create their own `scan` row (grouped under an optional project),
mirroring how nmap .nmap files are imported, so the findings join the same
per-project view as everything else.
"""

import sys
from pathlib import Path

# ── path setup: this module lives in nmap_suite/modules ──────────────
_MODULES_DIR = Path(__file__).resolve().parent
_REPO_ROOT   = _MODULES_DIR.parent.parent          # nmap_suite/modules -> nmap_suite -> repo root
for _p in (str(_MODULES_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import database as db
from nmap_parser import parse_nmap_file, categorise_service

# Parser reuse from the root collection scripts. Imported lazily-safe:
# nucleiCombined no longer hard-exits or registers signal handlers at import.
from nucleiCombined import extract_template_prefixes, parse_nuclei_file
from sshWeakCiphersAudit import parse_ssh_audit_output


# ── SHARED HELPERS ───────────────────────────────────────────────────

def ensure_db():
    """Make sure the schema exists before importing. Idempotent
    (CREATE TABLE IF NOT EXISTS), safe to call from the CLI when the Flask
    app has never run and created the DB yet."""
    db.init_db()


def get_or_create_project(name):
    """Resolve a project by name, creating it if absent. Returns project id.
    Lets the Perimetr CLI use its --project name directly as the DB project."""
    for p in db.get_all_projects():
        if p["name"] == name:
            return p["id"]
    return db.create_project(name)


# ── NMAP (.nmap host scans) ──────────────────────────────────────────
# Moved here from app.py so both the Flask app and the Perimetr CLI import
# nmap scans through one code path (the CLI can't import app.py without
# dragging in Flask). The Flask app now imports these three names from here.

def evaluate_custom_rule(rule, host_data):
    """Evaluate one custom DB rule against parsed host data."""
    ct = rule['condition_type']
    cv = rule['condition_value'].strip()
    open_ports = [p for p in host_data.get('ports', []) if 'open' in p.get('state', '')]
    if ct == 'port_open':
        return any(p['port'] == cv for p in open_ports)
    elif ct == 'service_contains':
        return any(cv.lower() in p.get('service', '').lower() for p in open_ports)
    elif ct == 'version_contains':
        return any(cv.lower() in p.get('version', '').lower() for p in open_ports)
    elif ct == 'port_count_gt':
        try:
            return len(open_ports) > int(cv)
        except ValueError:
            return False
    return False


def import_nmap_data(filepath, scan_name=None, project_id=None):
    """Parse a .nmap file and persist everything to DB. Returns scan_id."""
    data = parse_nmap_file(filepath)

    # Apply overrides: filter out disabled built-in rules
    overrides    = db.get_fingerprint_overrides()
    disabled_ids = {rid for rid, en in overrides.items() if not en}
    data['findings'] = [f for f in data['findings'] if f['id'] not in disabled_ids]

    # Evaluate custom rules
    for rule in db.get_custom_rules(enabled_only=True):
        try:
            if evaluate_custom_rule(rule, data):
                data['findings'].append({
                    'id':             f"CR-{rule['id']}",
                    'severity':       rule['severity'],
                    'name':           rule['name'],
                    'description':    rule['description'],
                    'detail':         rule['description'],
                    'recommendation': rule['recommendation'],
                })
        except Exception:
            pass
    name = scan_name or Path(filepath).stem
    scan_id = db.insert_scan(
        name=name,
        scan_date=data.get("scan_time"),
        file_path=str(filepath),
        project_id=project_id
    )
    host_id = db.insert_host(
        scan_id=scan_id,
        ip=data["host"] or "",
        hostname=data["hostname"] or "",
        status=data["status"],
        scan_time=data["scan_time"]
    )
    for p in data["ports"]:
        db.insert_port(
            host_id=host_id,
            scan_id=scan_id,
            port=p["port"],
            protocol=p["protocol"],
            state=p["state"],
            service=p["service"],
            version=p["version"],
            category=categorise_service(p["service"])
        )
    for f in data["findings"]:
        db.insert_auto_finding(
            scan_id=scan_id,
            host_id=host_id,
            rule_id=f["id"],
            severity=f["severity"],
            name=f["name"],
            description=f["description"],
            detail=f["detail"],
            recommendation=f["recommendation"]
        )
    op = len([p for p in data["ports"] if "open" in p["state"]])
    db.update_scan_counts(scan_id, 1, op, len(data["findings"]))
    return scan_id


def import_multiple_nmap_files(directory, name_prefix=None, project_id=None):
    """Import all .nmap files in a directory. Returns list of scan_ids."""
    ids = []
    for fp in Path(directory).glob("*.nmap"):
        try:
            sid = import_nmap_data(fp, scan_name=(name_prefix or "") + fp.stem,
                                   project_id=project_id)
            ids.append(sid)
        except Exception as e:
            print(f"[!] Failed {fp}: {e}")
    return ids


# ── NUCLEI ───────────────────────────────────────────────────────────

def import_nuclei_results(results_dir, scan_name=None, project_id=None):
    """Parse a directory of nuclei .md findings and persist them.

    Returns (scan_id, finding_count). Raises FileNotFoundError if the
    directory doesn't exist and ValueError if it holds no .md files.
    """
    results_path = Path(results_dir)
    if not results_path.is_dir():
        raise FileNotFoundError(f"Nuclei results directory not found: {results_dir}")

    md_files = sorted(results_path.glob("*.md"))
    if not md_files:
        raise ValueError(f"No .md files found in {results_dir}")

    prefixes = extract_template_prefixes([f.name for f in md_files])

    rows = []
    for f in md_files:
        parsed = parse_nuclei_file(str(f), prefixes)
        if parsed:
            rows.append(parsed)

    name = scan_name or f"nuclei-{results_path.name}"
    scan_id = db.insert_scan(name=name, file_path=str(results_path),
                             project_id=project_id)

    hosts = set()
    for r in rows:
        sev = (r.get("severity") or "").strip()
        # normalise to upper for consistent sorting alongside other findings;
        # leave the 'N/A' placeholder untouched.
        sev = sev.upper() if sev and sev.upper() != "N/A" else sev
        host = r.get("target_domain") or ""
        hosts.add(host)
        db.insert_nuclei_finding(
            scan_id=scan_id,
            host=host,
            template=r.get("template_name") or "",
            severity=sev,
            description=r.get("description") or "",
            tags=r.get("tags") or "",
            cvss=r.get("cvss_score") or "",
            cwe=r.get("cwe_id") or "",
            curl_cmd=r.get("curl_command") or "",
            source_file=r.get("source_file") or "",
        )

    db.update_scan_counts(scan_id, len(hosts), 0, len(rows))
    db.log_activity(None, "IMPORT", "nuclei", scan_id,
                    f"Imported {len(rows)} nuclei findings from {results_path.name}")
    return scan_id, len(rows)


# ── SSH ──────────────────────────────────────────────────────────────

def import_ssh_report(report_file, scan_name=None, project_id=None):
    """Parse raw ssh-audit output (the *_RAW.txt / --mode parse input) and
    persist weak-algorithm findings.

    Returns (scan_id, finding_count). Raises FileNotFoundError if the file
    is missing and ValueError if no findings were parsed.
    """
    report_path = Path(report_file)
    if not report_path.is_file():
        raise FileNotFoundError(f"ssh-audit output file not found: {report_file}")

    content = report_path.read_text(encoding="utf-8", errors="ignore")
    results = parse_ssh_audit_output(content)

    # Flatten {target: {severity: {algo_type: [{name, reason}]}}} to rows.
    flat = []
    for target, severities in results.items():
        for severity, algo_types in severities.items():
            for algo_type, algos in algo_types.items():
                for algo in algos:
                    flat.append((target, severity, algo_type,
                                 algo.get("name", ""), algo.get("reason", "")))

    if not flat:
        raise ValueError(f"No SSH weak-algorithm findings parsed from {report_file}")

    name = scan_name or f"ssh-{report_path.stem}"
    scan_id = db.insert_scan(name=name, file_path=str(report_path),
                             project_id=project_id)

    hosts = set()
    for target, severity, algo_type, algo_name, reason in flat:
        hosts.add(target)
        db.insert_ssh_finding(
            scan_id=scan_id,
            host=target,
            severity=severity,
            algo_type=algo_type,
            algo_name=algo_name,
            reason=reason,
        )

    db.update_scan_counts(scan_id, len(hosts), 0, len(flat))
    db.log_activity(None, "IMPORT", "ssh", scan_id,
                    f"Imported {len(flat)} ssh findings from {report_path.name}")
    return scan_id, len(flat)
