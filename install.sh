#!/usr/bin/env bash
# =============================================================================
# InfraScanner installer - Copyright (c) ZXSPRD.COM - GNU GPL v3
# Distribution-agnostic: Oracle Linux, RHEL, Rocky, AlmaLinux, Fedora
# (dnf/yum), Ubuntu, Debian, Kali (apt). Run as root or with sudo.
# Usage:  ./install.sh [--deps-only]
# =============================================================================
set -euo pipefail

DEPS_ONLY="${1:-}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\e[1;32m[install]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[install]\e[0m %s\n' "$*"; }
die()  { printf '\e[1;31m[install]\e[0m %s\n' "$*" >&2; exit 1; }

# ----------------------------------------------------------- detect manager
if command -v dnf >/dev/null 2>&1; then
    PM="dnf"; PKG_INSTALL="dnf install -y"
elif command -v yum >/dev/null 2>&1; then
    PM="yum"; PKG_INSTALL="yum install -y"
elif command -v apt-get >/dev/null 2>&1; then
    PM="apt"; PKG_INSTALL="apt-get install -y"
else
    die "No supported package manager found (dnf/yum/apt)."
fi
log "Package manager: $PM"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "Run as root or install sudo."
    SUDO="sudo"
fi

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- python
PYBIN=""
for c in python3.12 python3.11 python3; do
    if have "$c"; then PYBIN="$c"; break; fi
done
if [ -z "$PYBIN" ]; then
    log "Installing Python..."
    case "$PM" in
        dnf|yum) $SUDO $PKG_INSTALL python3 python3-pip ;;
        apt)     $SUDO apt-get update -y && $SUDO $PKG_INSTALL python3 python3-pip ;;
    esac
    PYBIN=python3
fi
PYVER="$($PYBIN -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
log "Python $PYVER detected ($PYBIN)"

# ------------------------------------------------------------- nmap (+masscan optional)
if ! have nmap; then
    log "Installing Nmap..."
    case "$PM" in
        dnf|yum) $SUDO $PKG_INSTALL nmap nmap-scripts nc || $SUDO $PKG_INSTALL nmap ;;
        apt)     $SUDO apt-get update -y; $SUDO $PKG_INSTALL nmap netcat || $SUDO $PKG_INSTALL nmap ;;
    esac
fi
have nmap && log "Nmap OK: $(nmap --version | head -1)" || warn "Nmap still missing - deep scans unavailable."

if ! have masscan; then
    if $SUDO $PKG_INSTALL masscan >/dev/null 2>&1; then
        log "Masscan installed (optional accelerator)."
    else
        warn "Masscan not available on this distro repo (optional - Nmap discovery will be used)."
    fi
fi

# ------------------------------------------------------------ crontab
if ! have crontab; then
    case "$PM" in
        dnf|yum) $SUDO $PKG_INSTALL cronie >/dev/null 2>&1 || true ;;
        apt)     $SUDO $PKG_INSTALL cron >/dev/null 2>&1 || true ;;
    esac
fi

# ------------------------------------------------------- python packages (venv)
VENV="$DIR/.venv"
if [ ! -d "$VENV" ]; then
    log "Creating virtualenv at $VENV"
    $PYBIN -m venv "$VENV" || die "venv creation failed (install python3-venv on Debian/Ubuntu)."
fi
log "Installing Python dependencies (PyYAML, fpdf2)..."
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet PyYAML fpdf2

# make launcher use the venv automatically
ln -sf "$VENV/bin/python" "$DIR/.python-link" 2>/dev/null || true

# ---------------------------------------------------------- config bootstrap
mkdir -p "$DIR/logs" "$DIR/temp" "$DIR/backups" \
         "$DIR/scans/raw" "$DIR/scans/processed" "$DIR/scans/archive" \
         "$DIR/reports/html" "$DIR/reports/csv" "$DIR/reports/pdf" \
         "$DIR/reports/json" "$DIR/reports/archive" "$DIR/reports/latest"
chmod +x "$DIR/infrascan" 2>/dev/null || true

if [ "$DEPS_ONLY" = "--deps-only" ]; then
    log "Dependency pass complete."
    exit 0
fi

log "Installation complete."
echo
echo "  Next steps:"
echo "    1. Edit config/config.yaml   (networks, email, Teams webhook)"
echo "       - or run the menu and choose 10 (Configure)"
echo "    2. Test:      sudo ./infrascan --non-interactive test-email"
echo "                sudo ./infrascan --non-interactive health"
echo "    3. Launch:    sudo ./infrascan"
echo
echo "  Tip: scan profiles live under 'scan_profiles:' in config.yaml."
echo "  Copyright (c) ZXSPRD.COM - GNU GPL v3 - https://zxsprd.com"
