"""Maintenance: retention cleanup of reports/scans, health checks."""

from __future__ import annotations

import glob
import os
import platform
import shutil
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

from .logger import get
from .utils import disk_free_gb, is_root

log = get("scanner")


def cleanup(cfg, dry_run: bool = False) -> dict:
    """Delete files older than retention policy; archive monthly first."""
    removed = []
    now = datetime.now()
    report_days = int(cfg.get("retention.report_days", 90))
    scan_days = int(cfg.get("retention.scan_days", 90))
    monthly_keep = int(cfg.get("retention.monthly_keep", 12))

    rdir = cfg.dir("reports_dir")
    sdir = cfg.dir("scans_dir")

    # monthly archive of reports older than current month
    arch = rdir / "archive"
    arch.mkdir(parents=True, exist_ok=True)
    for sub in ("html", "csv", "pdf", "json"):
        d = rdir / sub
        if not d.exists():
            continue
        for f in d.iterdir():
            if f.is_file() and f.suffix in (".html", ".csv", ".pdf", ".json", ".txt"):
                mtime = datetime.fromtimestamp(f.stat().st_mtime)
                if mtime < now - timedelta(days=31):
                    dest = arch / f.name
                    if not dry_run:
                        shutil.move(str(f), str(dest))
                    removed.append(str(f))

    # purge archived beyond monthly_keep months
    monthly = sorted(arch.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    cutoff_files = []
    seen_months = []
    for f in monthly:
        stamp_month = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m")
        if stamp_month not in seen_months:
            seen_months.append(stamp_month)
        if len(seen_months) > monthly_keep:
            cutoff_files.append(f)
    for f in cutoff_files:
        if not dry_run:
            f.unlink(missing_ok=True)
        removed.append(str(f))

    # age-based deletion
    for base, days in ((rdir, report_days), (sdir / "raw", scan_days),
                       (sdir / "processed", scan_days)):
        if not base.exists():
            continue
        for f in glob.glob(str(base / "**" / "*"), recursive=True):
            p = Path(f)
            if p.is_file():
                age = now - datetime.fromtimestamp(p.stat().st_mtime)
                if age.days > days:
                    if not dry_run:
                        p.unlink(missing_ok=True)
                    removed.append(f)

    log.info("Cleanup %s %d files", "(dry-run)" if dry_run else "removed", len(removed))
    return {"removed": len(removed), "files": removed[:50], "dry_run": dry_run}


# ------------------------------------------------------------------ health
def health_check(cfg) -> list[tuple[str, str, str]]:
    """Returns [(component, OK/WARN/FAIL, detail)]."""
    results = []

    def add(comp, ok, warn, detail):
        results.append((comp, "OK" if ok else ("WARN" if warn else "FAIL"), detail))

    py = platform.python_version()
    add("Python", tuple(int(x) for x in py.split(".")[:2]) >= (3, 9), True, py)

    nmap = shutil.which("nmap")
    ver = ""
    if nmap:
        try:
            ver = subprocess.run([nmap, "--version"], capture_output=True,
                                 text=True, timeout=10).stdout.splitlines()[0]
        except Exception:
            ver = "found"
    add("Nmap", bool(nmap), False, ver or "missing - install via menu 11")

    mass = shutil.which("masscan")
    add("Masscan", bool(mass), True, mass or "optional (not installed)")

    try:
        import yaml  # noqa
        add("PyYAML", True, False, "installed")
    except ImportError:
        add("PyYAML", False, False, "missing")
    try:
        import fpdf  # noqa
        add("fpdf2 (PDF)", True, True, "installed")
    except ImportError:
        add("fpdf2 (PDF)", False, True, "missing - PDF falls back to text")

    # SMTP reachability (TCP connect only, no auth spam)
    srv = cfg.get("email.smtp_server", "")
    port = int(cfg.get("email.smtp_port", 587))
    smtp_ok = False
    detail = "not configured"
    if srv and "example.com" not in srv:
        import socket
        try:
            with socket.create_connection((srv, port), timeout=5):
                smtp_ok = True
                detail = f"{srv}:{port} reachable"
        except OSError as exc:
            detail = f"{srv}:{port} unreachable ({exc})"
    elif srv:
        detail = "placeholder server in config"
    add("SMTP", smtp_ok, not smtp_ok, detail)

    url = cfg.get("teams.webhook_url", "")
    teams_ok = bool(url) and "example.com" not in url
    add("Teams Webhook", teams_ok, not teams_ok,
        "configured" if teams_ok else "placeholder/empty - configure via menu 10")

    free = disk_free_gb(cfg.root)
    add("Disk Space", free > 1, free > 0.2, f"{free:.1f} GB free")

    cron = shutil.which("crontab")
    add("Cron", bool(cron), not cron, cron or "crontab binary missing")

    add("Privileges", is_root(), True,
        "root" if is_root() else "non-root: OS detection/SYN features degraded")

    return results
