# nmap_suite

A self-hosted web app for managing nmap scan results, tracking security findings, and taking notes.

## Quick Start

```bash
# 1. Extract the zip
unzip nmap_suite.zip
cd nmap_suite

# 2. Run the installer (installs Flask, starts the app)
chmod +x install.sh
./install.sh

# 3. Open in browser
http://localhost:5000
```

## Requirements

- Python 3.7+
- pip
- Linux (tested on RHEL/CentOS, Ubuntu, Debian)

## Features

### Scans
- Import `.nmap` files (single file or whole directory)
- Per-scan port table with filtering by state/category
- Automatic fingerprint analysis (13 rules: JBoss, Prometheus, SMB, dual SSH, Tomcat, etc.)
- Service Intelligence Map grouped by function

### Findings
- **Auto Findings** — from the fingerprint engine (CRITICAL/HIGH/MEDIUM/INFO)
- **Manual Findings** — your own documented vulnerabilities
  - Title, Severity, Status, Description
  - Steps to Reproduce
  - Impact, Recommendation, Evidence
  - Tags, linked scan, affected host IP
  - Quick status updates (Open → In Progress → Resolved → Accepted)

### Notes
- Free-form notes linked to scans or hosts
- Color coding (default, blue, green, yellow, red)
- Pin important notes to the dashboard
- Filter by scan, color, pinned status

### Dashboard
- Stats overview
- Pinned notes
- Recent findings
- Activity log
- Quick scan list

## Usage

### Import a scan
1. Go to **Scans** → click **Import Scan**
2. Upload your `.nmap` file
3. The fingerprint engine runs automatically

### Run nmap and import
```bash
# Scan a host
nmap -v -sSCV -A -Pn -oA ./scans/10.32.77.206 10.32.77.206

# Start the suite
./install.sh

# Import via UI or drop the .nmap file in the scans/ folder and import via directory
```

### Add a manual finding
1. Go to **Findings** → **New Finding**
2. Fill in Title, Severity, Description, Steps to Reproduce
3. Link to a scan and host IP
4. Track progress with status updates

## File Structure

```
nmap_suite/
├── app.py              — Flask web application
├── install.sh          — Install & run script
├── modules/
│   ├── database.py     — SQLite persistence layer
│   └── nmap_parser.py  — Nmap file parser + fingerprint engine
├── templates/          — HTML templates
├── static/
│   └── css/main.css    — Stylesheet
├── scans/              — Drop .nmap files here
└── data/
    └── suite.db        — SQLite database (auto-created)
```

## Database

All data is stored in `data/suite.db` (SQLite). Back it up with:
```bash
cp data/suite.db data/suite.backup.$(date +%Y%m%d).db
```

## Running on a Server

To run persistently in the background:
```bash
nohup python3 app.py > data/app.log 2>&1 &
echo $! > data/app.pid

# Stop it
kill $(cat data/app.pid)
```

Or use screen:
```bash
screen -S nmap_suite
./install.sh
# Ctrl+A then D to detach
```
