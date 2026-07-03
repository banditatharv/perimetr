"""
database.py - SQLite persistence layer for nmap_suite
Tables: scans, hosts, ports, auto_findings, manual_findings, notes, tags
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

DB_PATH = os.environ.get("NMAP_SUITE_DB", str(Path(__file__).parent.parent / "data" / "suite.db"))


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
        -- ── PROJECTS ────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS projects (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT DEFAULT '',
            color       TEXT DEFAULT '#58a6ff',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- ── SCANS ───────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER REFERENCES projects(id) ON DELETE SET NULL,
            name        TEXT NOT NULL,
            scan_date   TEXT,
            imported_at TEXT NOT NULL DEFAULT (datetime('now')),
            file_path   TEXT,
            notes       TEXT DEFAULT '',
            host_count  INTEGER DEFAULT 0,
            port_count  INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0
        );

        -- ── HOSTS ───────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS hosts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            ip          TEXT NOT NULL,
            hostname    TEXT,
            status      TEXT,
            scan_time   TEXT,
            os_guess    TEXT,
            notes       TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_hosts_ip   ON hosts(ip);

        -- ── PORTS ───────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS ports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            port        TEXT NOT NULL,
            protocol    TEXT,
            state       TEXT,
            service     TEXT,
            version     TEXT,
            category    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
        CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);

        -- ── AUTO FINDINGS (fingerprint engine results) ──────────────
        CREATE TABLE IF NOT EXISTS auto_findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            rule_id      TEXT,
            severity     TEXT,
            name         TEXT,
            description  TEXT,
            detail       TEXT,
            recommendation TEXT
        );

        -- ── MANUAL FINDINGS (user-created) ──────────────────────────
        CREATE TABLE IF NOT EXISTS manual_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER REFERENCES scans(id) ON DELETE SET NULL,
            host_ip         TEXT,
            title           TEXT NOT NULL,
            severity        TEXT NOT NULL DEFAULT 'MEDIUM',
            status          TEXT NOT NULL DEFAULT 'Open',
            description     TEXT DEFAULT '',
            steps_to_reproduce TEXT DEFAULT '',
            impact          TEXT DEFAULT '',
            recommendation  TEXT DEFAULT '',
            evidence        TEXT DEFAULT '',
            tags            TEXT DEFAULT '[]',
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_mf_scan ON manual_findings(scan_id);

        -- ── NOTES ───────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            host_ip     TEXT,
            title       TEXT NOT NULL,
            content     TEXT DEFAULT '',
            pinned      INTEGER DEFAULT 0,
            color       TEXT DEFAULT 'default',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_notes_scan ON notes(scan_id);

        -- ── TAGS ────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS tags (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name    TEXT NOT NULL UNIQUE,
            color   TEXT DEFAULT '#58a6ff'
        );

        -- ── ACTIVITY LOG ────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS activity_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT NOT NULL,
            entity_type TEXT,
            entity_id   INTEGER,
            detail      TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- ── FINGERPRINT RULE OVERRIDES (enable/disable built-in rules) ──
        CREATE TABLE IF NOT EXISTS fingerprint_rule_overrides (
            rule_id TEXT PRIMARY KEY,
            enabled INTEGER DEFAULT 1
        );

        -- ── CUSTOM FINGERPRINT RULES ─────────────────────────────────
        CREATE TABLE IF NOT EXISTS custom_fingerprint_rules (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            severity        TEXT NOT NULL DEFAULT 'MEDIUM',
            description     TEXT DEFAULT '',
            recommendation  TEXT DEFAULT '',
            condition_type  TEXT NOT NULL,
            condition_value TEXT NOT NULL,
            enabled         INTEGER DEFAULT 1,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- ── NUCLEI FINDINGS (imported from nucleiCombined .md output) ──
        CREATE TABLE IF NOT EXISTS nuclei_findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host         TEXT,
            template     TEXT,
            severity     TEXT,
            description  TEXT,
            tags         TEXT,
            cvss         TEXT,
            cwe          TEXT,
            curl_cmd     TEXT,
            source_file  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_nuclei_scan ON nuclei_findings(scan_id);

        -- ── SSH FINDINGS (imported from sshWeakCiphersAudit output) ────
        CREATE TABLE IF NOT EXISTS ssh_findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host         TEXT,
            severity     TEXT,
            algo_type    TEXT,
            algo_name    TEXT,
            reason       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ssh_scan ON ssh_findings(scan_id);
        """)
    print(f"[DB] Initialised: {DB_PATH}")
    # migrate: add columns to existing databases
    with get_conn() as conn:
        for sql in [
            "ALTER TABLE ports ADD COLUMN note TEXT DEFAULT ''",
            "ALTER TABLE ports ADD COLUMN tested INTEGER DEFAULT 0",
            "ALTER TABLE manual_findings ADD COLUMN business_impact TEXT DEFAULT ''",
            "ALTER TABLE manual_findings ADD COLUMN technical_impact TEXT DEFAULT ''",
            "ALTER TABLE manual_findings ADD COLUMN cvss_score TEXT DEFAULT ''",
        ]:
            try:
                conn.execute(sql)
            except Exception:
                pass
        # copy legacy impact → business_impact for existing rows
        try:
            conn.execute(
                "UPDATE manual_findings SET business_impact = impact "
                "WHERE (business_impact IS NULL OR business_impact = '') "
                "AND impact IS NOT NULL AND impact != ''"
            )
        except Exception:
            pass


# ── PROJECTS ─────────────────────────────────────────────────────

def create_project(name, description="", color="#58a6ff"):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO projects (name, description, color) VALUES (?,?,?)",
            (name, description, color)
        )
        return cur.lastrowid

def get_all_projects():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            p = dict(r)
            p["scan_count"] = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE project_id=?", (p["id"],)
            ).fetchone()[0]
            p["host_count"] = conn.execute(
                """SELECT COUNT(*) FROM hosts h
                   JOIN scans s ON h.scan_id=s.id WHERE s.project_id=?""", (p["id"],)
            ).fetchone()[0]
            p["finding_count"] = conn.execute(
                """SELECT COUNT(*) FROM auto_findings af
                   JOIN scans s ON af.scan_id=s.id WHERE s.project_id=?""", (p["id"],)
            ).fetchone()[0]
            p["mf_count"] = conn.execute(
                "SELECT COUNT(*) FROM manual_findings WHERE scan_id IN (SELECT id FROM scans WHERE project_id=?)",
                (p["id"],)
            ).fetchone()[0]
            result.append(p)
        return result

def get_project(project_id):
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return dict(r) if r else None

def update_project(project_id, name, description="", color="#58a6ff"):
    with get_conn() as conn:
        conn.execute(
            "UPDATE projects SET name=?, description=?, color=?, updated_at=datetime('now') WHERE id=?",
            (name, description, color, project_id)
        )

def delete_project(project_id):
    """Delete project and ALL linked scans (cascades to hosts/ports/findings)."""
    with get_conn() as conn:
        # get scan ids first for cascade
        scan_ids = [r[0] for r in conn.execute(
            "SELECT id FROM scans WHERE project_id=?", (project_id,)
        ).fetchall()]
        for sid in scan_ids:
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.execute("DELETE FROM projects WHERE id=?", (project_id,))
        log_activity(conn, "DELETE", "project", project_id,
                     f"Deleted project #{project_id} and {len(scan_ids)} scans")

def get_project_scans(project_id):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM scans WHERE project_id=? ORDER BY imported_at DESC",
            (project_id,)
        ).fetchall()]

def assign_scan_to_project(scan_id, project_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET project_id=? WHERE id=?", (project_id, scan_id)
        )

# ── SCANS ────────────────────────────────────────────────────────

def insert_scan(name, scan_date=None, file_path=None, project_id=None):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (name, scan_date, file_path, project_id) VALUES (?,?,?,?)",
            (name, scan_date, file_path, project_id)
        )
        return cur.lastrowid

def update_scan_counts(scan_id, host_count, port_count, finding_count):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET host_count=?, port_count=?, finding_count=? WHERE id=?",
            (host_count, port_count, finding_count, scan_id)
        )

def get_all_scans():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            """SELECT s.*, p.name as project_name, p.color as project_color
               FROM scans s LEFT JOIN projects p ON s.project_id=p.id
               ORDER BY s.imported_at DESC"""
        ).fetchall()]

def get_scan(scan_id):
    with get_conn() as conn:
        r = conn.execute(
            """SELECT s.*, p.name as project_name, p.color as project_color
               FROM scans s LEFT JOIN projects p ON s.project_id=p.id
               WHERE s.id=?""", (scan_id,)
        ).fetchone()
        return dict(r) if r else None

def delete_scan(scan_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))

def update_scan_notes(scan_id, notes):
    with get_conn() as conn:
        conn.execute("UPDATE scans SET notes=? WHERE id=?", (notes, scan_id))

# ── HOSTS ────────────────────────────────────────────────────────

def insert_host(scan_id, ip, hostname, status, scan_time):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO hosts (scan_id,ip,hostname,status,scan_time) VALUES (?,?,?,?,?)",
            (scan_id, ip, hostname, status, scan_time)
        )
        return cur.lastrowid

def get_hosts(scan_id):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM hosts WHERE scan_id=? ORDER BY ip", (scan_id,)
        ).fetchall()]

def get_all_hosts():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            """SELECT h.*, s.name as scan_name FROM hosts h
               JOIN scans s ON h.scan_id=s.id ORDER BY h.ip"""
        ).fetchall()]

# ── PORTS ────────────────────────────────────────────────────────

def insert_port(host_id, scan_id, port, protocol, state, service, version, category):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO ports (host_id,scan_id,port,protocol,state,service,version,category) VALUES (?,?,?,?,?,?,?,?)",
            (host_id, scan_id, port, protocol, state, service, version, category)
        )

def get_all_ports_for_service_map(state_filter=None, category_filter=None):
    """Return all ports across all scans, joined with host and scan info."""
    with get_conn() as conn:
        where = ["1=1"]
        params = []
        if state_filter:
            where.append("p.state=?"); params.append(state_filter)
        if category_filter:
            where.append("p.category=?"); params.append(category_filter)
        return [dict(r) for r in conn.execute(
            f"""SELECT p.*, h.ip, h.hostname, s.name as scan_name, s.id as scan_id
                FROM ports p
                JOIN hosts h ON p.host_id=h.id
                JOIN scans s ON p.scan_id=s.id
                WHERE {' AND '.join(where)}
                ORDER BY p.category, p.service, h.ip, CAST(p.port AS INTEGER)""",
            params
        ).fetchall()]

def get_service_map_stats():
    """Quick stats for service map page."""
    with get_conn() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM ports WHERE state='open'").fetchone()[0]
        cats    = conn.execute(
            "SELECT category, COUNT(*) as cnt FROM ports WHERE state='open' GROUP BY category ORDER BY cnt DESC"
        ).fetchall()
        unique_svcs = conn.execute(
            "SELECT COUNT(DISTINCT service) FROM ports WHERE state='open'"
        ).fetchone()[0]
        unique_ips  = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM hosts WHERE status='up'"
        ).fetchone()[0]
        tested = conn.execute(
            "SELECT COUNT(*) FROM ports WHERE tested=1 AND state='open'"
        ).fetchone()[0]
        return dict(total_open=total, categories=[dict(r) for r in cats],
                    unique_services=unique_svcs, unique_hosts=unique_ips,
                    tested_count=tested)

def get_ports(host_id=None, scan_id=None):
    with get_conn() as conn:
        if host_id:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM ports WHERE host_id=? ORDER BY CAST(port AS INTEGER)", (host_id,)
            ).fetchall()]
        elif scan_id:
            return [dict(r) for r in conn.execute(
                """SELECT p.*, h.ip, h.hostname FROM ports p
                   JOIN hosts h ON p.host_id=h.id
                   WHERE p.scan_id=? ORDER BY h.ip, CAST(p.port AS INTEGER)""", (scan_id,)
            ).fetchall()]
        return []

def update_port_annotation(port_id, note=None, tested=None):
    fields, vals = [], []
    if note is not None:
        fields.append("note=?"); vals.append(note)
    if tested is not None:
        fields.append("tested=?"); vals.append(1 if tested else 0)
    if not fields: return
    vals.append(port_id)
    with get_conn() as conn:
        conn.execute(f"UPDATE ports SET {','.join(fields)} WHERE id=?", vals)

# ── AUTO FINDINGS ────────────────────────────────────────────────

def insert_auto_finding(scan_id, host_id, rule_id, severity, name, description, detail, recommendation):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO auto_findings
               (scan_id,host_id,rule_id,severity,name,description,detail,recommendation)
               VALUES (?,?,?,?,?,?,?,?)""",
            (scan_id, host_id, rule_id, severity, name, description, detail, recommendation)
        )

def get_auto_findings(scan_id=None):
    with get_conn() as conn:
        if scan_id:
            return [dict(r) for r in conn.execute(
                """SELECT af.*, h.ip, h.hostname FROM auto_findings af
                   JOIN hosts h ON af.host_id=h.id
                   WHERE af.scan_id=? ORDER BY
                   CASE af.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                   WHEN 'MEDIUM' THEN 2 ELSE 3 END""", (scan_id,)
            ).fetchall()]
        return [dict(r) for r in conn.execute(
            """SELECT af.*, h.ip, h.hostname, s.name as scan_name FROM auto_findings af
               JOIN hosts h ON af.host_id=h.id JOIN scans s ON af.scan_id=s.id
               ORDER BY CASE af.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
               WHEN 'MEDIUM' THEN 2 ELSE 3 END"""
        ).fetchall()]

# ── NUCLEI FINDINGS ──────────────────────────────────────────────

def insert_nuclei_finding(scan_id, host, template, severity, description,
                          tags, cvss, cwe, curl_cmd, source_file):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO nuclei_findings
               (scan_id,host,template,severity,description,tags,cvss,cwe,curl_cmd,source_file)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, host, template, severity, description, tags, cvss, cwe, curl_cmd, source_file)
        )

def get_nuclei_findings(scan_id=None):
    with get_conn() as conn:
        if scan_id:
            return [dict(r) for r in conn.execute(
                """SELECT * FROM nuclei_findings WHERE scan_id=? ORDER BY
                   CASE UPPER(severity) WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                   WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 WHEN 'INFO' THEN 4 ELSE 5 END,
                   template""", (scan_id,)
            ).fetchall()]
        return [dict(r) for r in conn.execute(
            """SELECT nf.*, s.name as scan_name FROM nuclei_findings nf
               JOIN scans s ON nf.scan_id=s.id ORDER BY
               CASE UPPER(nf.severity) WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
               WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 WHEN 'INFO' THEN 4 ELSE 5 END,
               nf.template"""
        ).fetchall()]

# ── SSH FINDINGS ─────────────────────────────────────────────────

def insert_ssh_finding(scan_id, host, severity, algo_type, algo_name, reason):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO ssh_findings
               (scan_id,host,severity,algo_type,algo_name,reason)
               VALUES (?,?,?,?,?,?)""",
            (scan_id, host, severity, algo_type, algo_name, reason)
        )

def get_ssh_findings(scan_id=None):
    with get_conn() as conn:
        if scan_id:
            return [dict(r) for r in conn.execute(
                """SELECT * FROM ssh_findings WHERE scan_id=? ORDER BY
                   CASE severity WHEN 'fail' THEN 0 WHEN 'warn' THEN 1
                   WHEN 'rec_remove' THEN 2 ELSE 3 END, host, algo_type""", (scan_id,)
            ).fetchall()]
        return [dict(r) for r in conn.execute(
            """SELECT sf.*, s.name as scan_name FROM ssh_findings sf
               JOIN scans s ON sf.scan_id=s.id ORDER BY
               CASE sf.severity WHEN 'fail' THEN 0 WHEN 'warn' THEN 1
               WHEN 'rec_remove' THEN 2 ELSE 3 END, sf.host, sf.algo_type"""
        ).fetchall()]

# ── MANUAL FINDINGS ──────────────────────────────────────────────

def create_manual_finding(scan_id, host_ip, title, severity, status,
                           description, steps_to_reproduce, business_impact, technical_impact,
                           recommendation, evidence, tags, cvss_score=''):
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO manual_findings
               (scan_id,host_ip,title,severity,status,description,
                steps_to_reproduce,business_impact,technical_impact,
                recommendation,evidence,tags,cvss_score)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, host_ip, title, severity, status,
             description, steps_to_reproduce, business_impact, technical_impact,
             recommendation, evidence, json.dumps(tags), cvss_score)
        )
        log_activity(conn, "CREATE", "manual_finding", cur.lastrowid, f"Created: {title}")
        return cur.lastrowid

def get_manual_findings(scan_id=None):
    with get_conn() as conn:
        if scan_id:
            rows = conn.execute(
                """SELECT mf.*, s.name as scan_name FROM manual_findings mf
                   LEFT JOIN scans s ON mf.scan_id=s.id
                   WHERE mf.scan_id=? ORDER BY
                   CASE mf.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                   WHEN 'MEDIUM' THEN 2 ELSE 3 END, mf.created_at DESC""", (scan_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT mf.*, s.name as scan_name FROM manual_findings mf
                   LEFT JOIN scans s ON mf.scan_id=s.id
                   ORDER BY CASE mf.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                   WHEN 'MEDIUM' THEN 2 ELSE 3 END, mf.created_at DESC"""
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try: d["tags"] = json.loads(d.get("tags") or "[]")
            except: d["tags"] = []
            result.append(d)
        return result

def get_manual_finding(finding_id):
    with get_conn() as conn:
        r = conn.execute(
            """SELECT mf.*, s.name as scan_name FROM manual_findings mf
               LEFT JOIN scans s ON mf.scan_id=s.id WHERE mf.id=?""", (finding_id,)
        ).fetchone()
        if not r: return None
        d = dict(r)
        try: d["tags"] = json.loads(d.get("tags") or "[]")
        except: d["tags"] = []
        return d

def update_manual_finding(finding_id, **kwargs):
    allowed = ["title","severity","status","description","steps_to_reproduce",
               "business_impact","technical_impact","cvss_score",
               "recommendation","evidence","tags","host_ip","scan_id"]
    fields, vals = [], []
    for k, v in kwargs.items():
        if k in allowed:
            fields.append(f"{k}=?")
            vals.append(json.dumps(v) if k == "tags" else v)
    if not fields: return
    vals += [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), finding_id]
    with get_conn() as conn:
        conn.execute(
            f"UPDATE manual_findings SET {','.join(fields)},updated_at=? WHERE id=?", vals
        )
        log_activity(conn, "UPDATE", "manual_finding", finding_id, f"Updated fields: {','.join(kwargs.keys())}")

def delete_manual_finding(finding_id):
    with get_conn() as conn:
        r = conn.execute("SELECT title FROM manual_findings WHERE id=?", (finding_id,)).fetchone()
        conn.execute("DELETE FROM manual_findings WHERE id=?", (finding_id,))
        if r:
            log_activity(conn, "DELETE", "manual_finding", finding_id, f"Deleted: {r['title']}")

# ── NOTES ────────────────────────────────────────────────────────

def create_note(scan_id, host_ip, title, content, pinned=False, color="default"):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO notes (scan_id,host_ip,title,content,pinned,color) VALUES (?,?,?,?,?,?)",
            (scan_id, host_ip, title, content, 1 if pinned else 0, color)
        )
        log_activity(conn, "CREATE", "note", cur.lastrowid, f"Note: {title}")
        return cur.lastrowid

def get_notes(scan_id=None):
    with get_conn() as conn:
        if scan_id:
            return [dict(r) for r in conn.execute(
                """SELECT n.*, s.name as scan_name FROM notes n
                   LEFT JOIN scans s ON n.scan_id=s.id
                   WHERE n.scan_id=? ORDER BY n.pinned DESC, n.updated_at DESC""", (scan_id,)
            ).fetchall()]
        return [dict(r) for r in conn.execute(
            """SELECT n.*, s.name as scan_name FROM notes n
               LEFT JOIN scans s ON n.scan_id=s.id
               ORDER BY n.pinned DESC, n.updated_at DESC"""
        ).fetchall()]

def get_note(note_id):
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
        return dict(r) if r else None

def update_note(note_id, **kwargs):
    allowed = ["title","content","pinned","color","host_ip","scan_id"]
    fields, vals = [], []
    for k, v in kwargs.items():
        if k in allowed:
            fields.append(f"{k}=?")
            vals.append(v)
    if not fields: return
    vals += [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), note_id]
    with get_conn() as conn:
        conn.execute(f"UPDATE notes SET {','.join(fields)},updated_at=? WHERE id=?", vals)

def delete_note(note_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM notes WHERE id=?", (note_id,))

# ── FINGERPRINT RULE OVERRIDES ───────────────────────────

def get_fingerprint_overrides():
    """Returns {rule_id: True/False} for all overridden built-in rules."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT rule_id, enabled FROM fingerprint_rule_overrides"
        ).fetchall()
        return {r['rule_id']: bool(r['enabled']) for r in rows}

def set_fingerprint_override(rule_id, enabled):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO fingerprint_rule_overrides (rule_id, enabled) VALUES (?,?) "
            "ON CONFLICT(rule_id) DO UPDATE SET enabled=excluded.enabled",
            (rule_id, 1 if enabled else 0)
        )

# ── CUSTOM FINGERPRINT RULES ──────────────────────────────

def get_custom_rules(enabled_only=False):
    with get_conn() as conn:
        if enabled_only:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM custom_fingerprint_rules WHERE enabled=1 ORDER BY created_at"
            ).fetchall()]
        return [dict(r) for r in conn.execute(
            "SELECT * FROM custom_fingerprint_rules ORDER BY created_at"
        ).fetchall()]

def create_custom_rule(name, severity, description, recommendation, condition_type, condition_value):
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO custom_fingerprint_rules
               (name, severity, description, recommendation, condition_type, condition_value)
               VALUES (?,?,?,?,?,?)""",
            (name, severity, description, recommendation, condition_type, condition_value)
        )
        return cur.lastrowid

def toggle_custom_rule(rule_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE custom_fingerprint_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?",
            (rule_id,)
        )

def delete_custom_rule(rule_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM custom_fingerprint_rules WHERE id=?", (rule_id,))

# ── BULK PORT OPERATIONS ──────────────────────────────────

def bulk_update_ports_tested(port_ids, tested):
    if not port_ids:
        return 0
    placeholders = ','.join('?' * len(port_ids))
    val = 1 if tested else 0
    with get_conn() as conn:
        conn.execute(
            f"UPDATE ports SET tested={val} WHERE id IN ({placeholders})", list(port_ids)
        )
    return len(port_ids)

# ── ACTIVITY LOG ─────────────────────────────────────────────────

def log_activity(conn_or_none, action, entity_type, entity_id, detail):
    if conn_or_none:
        conn_or_none.execute(
            "INSERT INTO activity_log (action,entity_type,entity_id,detail) VALUES (?,?,?,?)",
            (action, entity_type, entity_id, detail)
        )
    else:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO activity_log (action,entity_type,entity_id,detail) VALUES (?,?,?,?)",
                (action, entity_type, entity_id, detail)
            )

def get_activity_log(limit=50):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()]

# ── STATS ────────────────────────────────────────────────────────

def get_dashboard_stats():
    with get_conn() as conn:
        scans  = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        hosts  = conn.execute("SELECT COUNT(*) FROM hosts WHERE status='up'").fetchone()[0]
        ports  = conn.execute("SELECT COUNT(*) FROM ports WHERE state='open'").fetchone()[0]
        crit   = conn.execute("SELECT COUNT(*) FROM auto_findings WHERE severity='CRITICAL'").fetchone()[0]
        high   = conn.execute("SELECT COUNT(*) FROM auto_findings WHERE severity='HIGH'").fetchone()[0]
        mf     = conn.execute("SELECT COUNT(*) FROM manual_findings").fetchone()[0]
        mf_open= conn.execute("SELECT COUNT(*) FROM manual_findings WHERE status='Open'").fetchone()[0]
        notes  = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        return dict(scans=scans, hosts=hosts, ports=ports, crit=crit,
                    high=high, manual_findings=mf, mf_open=mf_open, notes=notes)

def get_severity_breakdown():
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT severity, COUNT(*) as cnt FROM auto_findings GROUP BY severity
               UNION ALL
               SELECT severity, COUNT(*) as cnt FROM manual_findings GROUP BY severity"""
        ).fetchall()
        totals = {}
        for r in rows:
            totals[r["severity"]] = totals.get(r["severity"], 0) + r["cnt"]
        return totals

def search_all(query):
    q = f"%{query}%"
    with get_conn() as conn:
        hosts = [dict(r) for r in conn.execute(
            """SELECT h.ip, h.hostname, h.status, s.name as scan_name
               FROM hosts h JOIN scans s ON h.scan_id=s.id
               WHERE h.ip LIKE ? OR h.hostname LIKE ?""", (q, q)
        ).fetchall()]
        findings = [dict(r) for r in conn.execute(
            "SELECT id,title,severity,status FROM manual_findings WHERE title LIKE ? OR description LIKE ?", (q, q)
        ).fetchall()]
        notes = [dict(r) for r in conn.execute(
            "SELECT id,title,content FROM notes WHERE title LIKE ? OR content LIKE ?", (q, q)
        ).fetchall()]
        ports = [dict(r) for r in conn.execute(
            """SELECT p.port, p.protocol, p.service, p.version, p.state,
                      p.category, h.ip, h.hostname, s.name as scan_name, s.id as scan_id
               FROM ports p JOIN hosts h ON p.host_id=h.id JOIN scans s ON p.scan_id=s.id
               WHERE p.service LIKE ? OR p.version LIKE ? OR p.port LIKE ?
               LIMIT 8""", (q, q, q)
        ).fetchall()]
        auto_f = [dict(r) for r in conn.execute(
            """SELECT af.id, af.severity, af.name, h.ip FROM auto_findings af
               JOIN hosts h ON af.host_id=h.id
               WHERE af.name LIKE ? OR af.description LIKE ?
               LIMIT 5""", (q, q)
        ).fetchall()]
        return dict(hosts=hosts, findings=findings, notes=notes, ports=ports, auto_findings=auto_f)
