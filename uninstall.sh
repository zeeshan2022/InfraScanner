#!/usr/bin/env bash
# InfraScanner uninstaller - removes venv, managed cron entries, caches.
# Reports/scans/logs are preserved unless --purge-data is given.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PURGE="${1:-}"

echo "[uninstall] Removing managed cron entries..."
if command -v crontab >/dev/null 2>&1; then
    (crontab -l 2>/dev/null || true) | grep -v "INFRA-SCANNER" | \
        grep -v "^$DIR/infrascan" > /tmp/cron.new || true
    # also drop lines between markers
    awk '/# INFRA-SCANNER-BEGIN/{skip=1} /# INFRA-SCANNER-END/{skip=0;next} !skip' \
        /tmp/cron.new > /tmp/cron.clean 2>/dev/null || true
    crontab /tmp/cron.clean 2>/dev/null || true
    rm -f /tmp/cron.new /tmp/cron.clean
fi

echo "[uninstall] Removing virtualenv and caches..."
rm -rf "$DIR/.venv" "$DIR/.python-link"
find "$DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

if [ "$PURGE" = "--purge-data" ]; then
    echo "[uninstall] Purging reports, scans, logs, temp..."
    rm -rf "$DIR/reports" "$DIR/scans" "$DIR/logs" "$DIR/temp" "$DIR/backups"
fi

echo "[uninstall] Done. Source files kept. Copyright (c) ZXSPRD.COM - GPL v3"
