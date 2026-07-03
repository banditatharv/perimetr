"""
app.py - nmap_suite web application
Run: python3 app.py  (then open http://localhost:5000)
"""

import os, sys, json
from pathlib import Path
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, flash, send_file)

# ── path setup ──────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "modules"))

import database as db
from nmap_parser import (parse_nmap_file, find_nmap_files,
                          run_fingerprints, build_service_map,
                          categorise_service, FINGERPRINT_RULES)
# nmap import logic lives in findings_import so the Perimetr CLI can reuse it
# without importing this Flask app.
from findings_import import import_nmap_data, import_multiple_nmap_files

app = Flask(__name__, template_folder="templates", static_folder="static")

# Stable secret key: read from env or persist to disk so sessions survive restarts
_key_file = ROOT / "data" / ".secret_key"
if os.environ.get("NMAP_SUITE_SECRET"):
    app.secret_key = os.environ["NMAP_SUITE_SECRET"].encode()
elif _key_file.exists():
    app.secret_key = _key_file.read_bytes()
else:
    _k = os.urandom(32)
    _key_file.parent.mkdir(parents=True, exist_ok=True)
    _key_file.write_bytes(_k)
    app.secret_key = _k

SCANS_DIR = ROOT / "scans"
SCANS_DIR.mkdir(exist_ok=True)

# ── bootstrap ───────────────────────────────────────────────────
db.init_db()

# ════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════
# import_nmap_data / import_multiple_nmap_files / evaluate_custom_rule now
# live in findings_import (imported above) so the Perimetr CLI shares them.

# ════════════════════════════════════════════════════════════════
#  DASHBOARD
# ════════════════════════════════════════════════════════════════

@app.route("/")
def dashboard():
    stats    = db.get_dashboard_stats()
    scans    = db.get_all_scans()
    projects = db.get_all_projects()
    activity = db.get_activity_log(20)
    sev      = db.get_severity_breakdown()
    recent_findings = db.get_manual_findings()[:5]
    pinned_notes    = [n for n in db.get_notes() if n["pinned"]][:4]
    return render_template("dashboard.html",
        stats=stats, scans=scans, projects=projects, activity=activity,
        sev=sev, recent_findings=recent_findings,
        pinned_notes=pinned_notes)

# ════════════════════════════════════════════════════════════════
#  SCANS
# ════════════════════════════════════════════════════════════════

@app.route("/scans")
def scans_list():
    scans    = db.get_all_scans()
    projects = db.get_all_projects()
    return render_template("scans.html", scans=scans, projects=projects)

@app.route("/scans/import", methods=["POST"])
def scan_import():
    mode       = request.form.get("mode", "file")
    project_id = request.form.get("project_id") or None
    if project_id:
        project_id = int(project_id)

    if mode == "file" and "nmap_file" in request.files:
        f = request.files["nmap_file"]
        if f.filename:
            dest = SCANS_DIR / f.filename
            f.save(dest)
            try:
                sid = import_nmap_data(dest,
                                       scan_name=request.form.get("scan_name") or None,
                                       project_id=project_id)
                flash(f"Imported scan #{sid} from {f.filename}", "success")
                return redirect(url_for("scan_detail", scan_id=sid))
            except Exception as e:
                flash(f"Import failed: {e}", "error")
    elif mode == "dir":
        d = request.form.get("scan_dir", "").strip()
        if d and Path(d).is_dir():
            ids = import_multiple_nmap_files(d, request.form.get("scan_name"),
                                              project_id=project_id)
            flash(f"Imported {len(ids)} scans from {d}", "success")
        else:
            flash("Directory not found", "error")
    return redirect(url_for("scans_list"))

# ════════════════════════════════════════════════════════════════
#  PROJECTS
# ════════════════════════════════════════════════════════════════

@app.route("/projects")
def projects_list():
    projects = db.get_all_projects()
    return render_template("projects.html", projects=projects)

@app.route("/projects/new", methods=["POST"])
def project_new():
    pid = db.create_project(
        name        = request.form.get("name", "Unnamed Project"),
        description = request.form.get("description", ""),
        color       = request.form.get("color", "#58a6ff")
    )
    flash(f"Project created.", "success")
    return redirect(url_for("project_detail", project_id=pid))

@app.route("/projects/<int:project_id>")
def project_detail(project_id):
    project = db.get_project(project_id)
    if not project: return redirect(url_for("projects_list"))
    scans      = db.get_project_scans(project_id)
    all_scans  = db.get_all_scans()
    # aggregate stats across all scans in project
    scan_ids   = [s["id"] for s in scans]
    auto_f     = []
    manual_f   = []
    for sid in scan_ids:
        auto_f   += db.get_auto_findings(sid)
        manual_f += db.get_manual_findings(sid)
    return render_template("project_detail.html",
        project=project, scans=scans, all_scans=all_scans,
        auto_findings=auto_f, manual_findings=manual_f)

@app.route("/projects/<int:project_id>/edit", methods=["POST"])
def project_edit(project_id):
    db.update_project(
        project_id,
        name        = request.form.get("name", "Unnamed"),
        description = request.form.get("description", ""),
        color       = request.form.get("color", "#58a6ff")
    )
    flash("Project updated.", "success")
    return redirect(url_for("project_detail", project_id=project_id))

@app.route("/projects/<int:project_id>/delete", methods=["POST"])
def project_delete(project_id):
    project = db.get_project(project_id)
    name = project["name"] if project else f"#{project_id}"
    db.delete_project(project_id)
    flash(f"Project '{name}' and all its scans deleted.", "success")
    return redirect(url_for("projects_list"))

@app.route("/projects/<int:project_id>/assign", methods=["POST"])
def project_assign_scan(project_id):
    scan_id = request.form.get("scan_id")
    if scan_id:
        db.assign_scan_to_project(int(scan_id), project_id)
        flash("Scan added to project.", "success")
    return redirect(url_for("project_detail", project_id=project_id))

@app.route("/scans/<int:scan_id>")
def scan_detail(scan_id):
    scan    = db.get_scan(scan_id)
    if not scan: return redirect(url_for("scans_list"))
    hosts   = db.get_hosts(scan_id)
    ports   = db.get_ports(scan_id=scan_id)
    auto_f  = db.get_auto_findings(scan_id)
    manual_f= db.get_manual_findings(scan_id)
    notes   = db.get_notes(scan_id)
    nuclei_f= db.get_nuclei_findings(scan_id)
    ssh_f   = db.get_ssh_findings(scan_id)
    # service map
    host_data = []
    for h in hosts:
        hp = [p for p in ports if p.get("host_id") == h["id"] or p.get("ip") == h["ip"]]
        host_data.append({"host": h["ip"], "hostname": h["hostname"],
                          "status": h["status"], "ports": [
                              {"port":p["port"],"protocol":p["protocol"],
                               "state":p["state"],"service":p["service"],
                               "version":p["version"]} for p in hp]})
    smap = build_service_map(host_data) if host_data else {}
    return render_template("scan_detail.html",
        scan=scan, hosts=hosts, ports=ports,
        auto_findings=auto_f, manual_findings=manual_f,
        notes=notes, smap=smap,
        nuclei_findings=nuclei_f, ssh_findings=ssh_f)

@app.route("/scans/<int:scan_id>/notes", methods=["POST"])
def save_scan_notes(scan_id):
    db.update_scan_notes(scan_id, request.form.get("notes",""))
    flash("Scan notes saved.", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id) + "#notes-tab")

@app.route("/scans/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    db.delete_scan(scan_id)
    flash("Scan deleted.", "success")
    return redirect(url_for("scans_list"))

# ════════════════════════════════════════════════════════════════
#  NUCLEI / SSH FINDINGS  (imported, read-only global views)
# ════════════════════════════════════════════════════════════════

@app.route("/nuclei")
def nuclei_list():
    findings = db.get_nuclei_findings()
    return render_template("nuclei.html", findings=findings)

@app.route("/ssh")
def ssh_list():
    findings = db.get_ssh_findings()
    return render_template("ssh.html", findings=findings)

# ════════════════════════════════════════════════════════════════
#  MANUAL FINDINGS  (CRUD)
# ════════════════════════════════════════════════════════════════

@app.route("/findings")
def findings_list():
    findings = db.get_manual_findings()
    scans    = db.get_all_scans()
    auto_f   = db.get_auto_findings()
    return render_template("findings.html",
        findings=findings, scans=scans, auto_findings=auto_f)

@app.route("/findings/new", methods=["GET","POST"])
def finding_new():
    scans = db.get_all_scans()
    if request.method == "POST":
        tags = [t.strip() for t in request.form.get("tags","").split(",") if t.strip()]
        fid = db.create_manual_finding(
            scan_id            = request.form.get("scan_id") or None,
            host_ip            = request.form.get("host_ip",""),
            title              = request.form["title"],
            severity           = request.form.get("severity","MEDIUM"),
            status             = request.form.get("status","Open"),
            description        = request.form.get("description",""),
            steps_to_reproduce = request.form.get("steps_to_reproduce",""),
            business_impact    = request.form.get("business_impact",""),
            technical_impact   = request.form.get("technical_impact",""),
            recommendation     = request.form.get("recommendation",""),
            evidence           = request.form.get("evidence",""),
            tags               = tags,
            cvss_score         = request.form.get("cvss_score","")
        )
        flash(f"Finding #{fid} created.", "success")
        return redirect(url_for("finding_detail", finding_id=fid))
    return render_template("finding_form.html", finding=None, scans=scans, mode="new")

@app.route("/findings/<int:finding_id>")
def finding_detail(finding_id):
    f = db.get_manual_finding(finding_id)
    if not f: return redirect(url_for("findings_list"))
    return render_template("finding_detail.html", finding=f)

@app.route("/findings/<int:finding_id>/edit", methods=["GET","POST"])
def finding_edit(finding_id):
    f     = db.get_manual_finding(finding_id)
    scans = db.get_all_scans()
    if not f: return redirect(url_for("findings_list"))
    if request.method == "POST":
        tags = [t.strip() for t in request.form.get("tags","").split(",") if t.strip()]
        db.update_manual_finding(
            finding_id,
            scan_id            = request.form.get("scan_id") or None,
            host_ip            = request.form.get("host_ip",""),
            title              = request.form["title"],
            severity           = request.form.get("severity","MEDIUM"),
            status             = request.form.get("status","Open"),
            description        = request.form.get("description",""),
            steps_to_reproduce = request.form.get("steps_to_reproduce",""),
            business_impact    = request.form.get("business_impact",""),
            technical_impact   = request.form.get("technical_impact",""),
            recommendation     = request.form.get("recommendation",""),
            evidence           = request.form.get("evidence",""),
            tags               = tags,
            cvss_score         = request.form.get("cvss_score","")
        )
        flash("Finding updated.", "success")
        return redirect(url_for("finding_detail", finding_id=finding_id))
    return render_template("finding_form.html", finding=f, scans=scans, mode="edit")

@app.route("/findings/<int:finding_id>/delete", methods=["POST"])
def finding_delete(finding_id):
    db.delete_manual_finding(finding_id)
    flash("Finding deleted.", "success")
    return redirect(url_for("findings_list"))

@app.route("/findings/<int:finding_id>/status", methods=["POST"])
def finding_status(finding_id):
    db.update_manual_finding(finding_id, status=request.form.get("status","Open"))
    return jsonify(ok=True)

# ════════════════════════════════════════════════════════════════
#  NOTES  (CRUD)
# ════════════════════════════════════════════════════════════════

@app.route("/notes")
def notes_list():
    notes = db.get_notes()
    scans = db.get_all_scans()
    return render_template("notes.html", notes=notes, scans=scans)

@app.route("/notes/new", methods=["POST"])
def note_new():
    nid = db.create_note(
        scan_id  = request.form.get("scan_id") or None,
        host_ip  = request.form.get("host_ip",""),
        title    = request.form.get("title","Untitled"),
        content  = request.form.get("content",""),
        pinned   = bool(request.form.get("pinned")),
        color    = request.form.get("color","default")
    )
    flash(f"Note #{nid} created.", "success")
    return redirect(request.referrer or url_for("notes_list"))

@app.route("/notes/<int:note_id>/edit", methods=["POST"])
def note_edit(note_id):
    db.update_note(
        note_id,
        title   = request.form.get("title","Untitled"),
        content = request.form.get("content",""),
        pinned  = 1 if request.form.get("pinned") else 0,
        color   = request.form.get("color","default")
    )
    flash("Note updated.", "success")
    return redirect(request.referrer or url_for("notes_list"))

@app.route("/notes/<int:note_id>/delete", methods=["POST"])
def note_delete(note_id):
    db.delete_note(note_id)
    flash("Note deleted.", "success")
    return redirect(request.referrer or url_for("notes_list"))

# ════════════════════════════════════════════════════════════════
#  API  (JSON endpoints for JS)
# ════════════════════════════════════════════════════════════════

@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_dashboard_stats())

@app.route("/api/search")
def api_search():
    q = request.args.get("q","").strip()
    if len(q) < 2: return jsonify(hosts=[],findings=[],notes=[],ports=[])
    results = db.search_all(q)
    # also search ports/services
    with db.get_conn() as conn:
        port_rows = [dict(r) for r in conn.execute(
            """SELECT p.port, p.service, p.version, p.state, h.ip, h.hostname, s.name as scan_name
               FROM ports p JOIN hosts h ON p.host_id=h.id JOIN scans s ON p.scan_id=s.id
               WHERE p.service LIKE ? OR p.version LIKE ? OR p.port LIKE ?
               LIMIT 5""",
            (f"%{q}%", f"%{q}%", f"%{q}%")
        ).fetchall()]
    results["ports"] = port_rows
    return jsonify(results)

# ════════════════════════════════════════════════════════════════
#  SERVICE MAP  (global — across all scans)
# ════════════════════════════════════════════════════════════════

@app.route("/services")
def service_map():
    stats = db.get_service_map_stats()
    ports = db.get_all_ports_for_service_map()
    # group by category
    from collections import defaultdict
    by_cat = defaultdict(list)
    for p in ports:
        by_cat[p["category"]].append(p)
    return render_template("service_map.html",
        stats=stats, by_cat=dict(by_cat), ports=ports)

@app.route("/api/ports/<int:port_id>/annotation", methods=["PATCH"])
def api_port_annotation(port_id):
    data = request.get_json()
    db.update_port_annotation(
        port_id,
        note=data.get("note"),
        tested=data.get("tested")
    )
    return jsonify(ok=True)

@app.route("/api/findings/<int:fid>/status", methods=["PATCH"])
def api_finding_status(fid):
    data = request.get_json()
    db.update_manual_finding(fid, status=data.get("status","Open"))
    return jsonify(ok=True)

@app.route("/api/notes/<int:nid>/pin", methods=["PATCH"])
def api_note_pin(nid):
    note = db.get_note(nid)
    if note:
        db.update_note(nid, pinned=0 if note["pinned"] else 1)
    return jsonify(ok=True)

# ════════════════════════════════════════════════════════════════
#  FINGERPRINT RULES
# ════════════════════════════════════════════════════════════════

@app.route("/rules")
def rules_list():
    overrides    = db.get_fingerprint_overrides()
    custom_rules = db.get_custom_rules()
    return render_template("rules.html",
        builtin_rules=FINGERPRINT_RULES,
        overrides=overrides,
        custom_rules=custom_rules)

@app.route("/rules/<rule_id>/toggle", methods=["POST"])
def rule_toggle(rule_id):
    overrides = db.get_fingerprint_overrides()
    current   = overrides.get(rule_id, True)
    db.set_fingerprint_override(rule_id, not current)
    return jsonify(ok=True, enabled=not current)

@app.route("/rules/custom/new", methods=["POST"])
def custom_rule_new():
    name  = request.form.get("name","").strip()
    value = request.form.get("condition_value","").strip()
    if not name or not value:
        flash("Name and condition value are required.", "error")
        return redirect(url_for("rules_list"))
    db.create_custom_rule(
        name            = name,
        severity        = request.form.get("severity","MEDIUM"),
        description     = request.form.get("description",""),
        recommendation  = request.form.get("recommendation",""),
        condition_type  = request.form.get("condition_type","port_open"),
        condition_value = value
    )
    flash("Custom rule created.", "success")
    return redirect(url_for("rules_list"))

@app.route("/rules/custom/<int:rule_id>/toggle", methods=["POST"])
def custom_rule_toggle(rule_id):
    db.toggle_custom_rule(rule_id)
    return jsonify(ok=True)

@app.route("/rules/custom/<int:rule_id>/delete", methods=["POST"])
def custom_rule_delete(rule_id):
    db.delete_custom_rule(rule_id)
    flash("Custom rule deleted.", "success")
    return redirect(url_for("rules_list"))

@app.route("/api/ports/bulk-test", methods=["PATCH"])
def api_bulk_port_test():
    data     = request.get_json()
    port_ids = data.get("port_ids", [])
    tested   = data.get("tested", True)
    count    = db.bulk_update_ports_tested(port_ids, tested)
    return jsonify(ok=True, count=count)


if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════════════╗")
    print("  ║   nmap_suite  — web interface                    ║")
    print("  ║   http://localhost:5000                          ║")
    print("  ╚══════════════════════════════════════════════════╝\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
