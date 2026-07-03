#!/bin/bash
# nmap_suite — install.sh
# Installs dependencies and starts the web app

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   nmap_suite — installer                         ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "  [!] python3 not found. Install it first:"
    echo "      sudo apt install python3 python3-pip   (Debian/Ubuntu)"
    echo "      sudo yum install python3               (RHEL/CentOS)"
    exit 1
fi

PYTHON=$(command -v python3)
echo "  [+] Python: $($PYTHON --version)"

# Install pip if needed
if ! $PYTHON -m pip --version &>/dev/null; then
    echo "  [*] Installing pip..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | $PYTHON
fi

# Install Flask
echo "  [*] Installing Flask..."
$PYTHON -m pip install flask --quiet --break-system-packages 2>/dev/null || \
$PYTHON -m pip install flask --quiet

echo "  [+] Flask installed."

# Create data dir
mkdir -p "$SCRIPT_DIR/data" "$SCRIPT_DIR/scans"

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   Ready!  Starting nmap_suite...                 ║"
echo "  ║   Open: http://localhost:5000                    ║"
echo "  ║   Ctrl+C to stop                                 ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

$PYTHON "$SCRIPT_DIR/app.py"
