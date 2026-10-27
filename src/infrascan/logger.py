"""Centralised logging for InfraScanner.

Rotating file logs: scanner.log, email.log, teams.log, cron.log
plus console output for interactive use.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False


def setup(cfg) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    log_dir: Path = cfg.dir("logs_dir")
    log_dir.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, str(cfg.get("logging.level", "INFO")).upper(), logging.INFO)
    if cfg.get("logging.verbose_debug", False):
        # Verbose debug mode: log every nmap command, its stdout/stderr and
        # parser counters (raw vs parsed) to scanner.log.
        level = logging.DEBUG
    max_bytes = int(cfg.get("logging.max_bytes", 5_242_880))
    backups = int(cfg.get("logging.backup_count", 5))

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    root = logging.getLogger("infrascan")
    root.setLevel(level)
    for name in ("scanner", "email", "teams"):
        lg = logging.getLogger(f"infrascan.{name}")
        h = RotatingFileHandler(log_dir / f"{name}.log",
                                maxBytes=max_bytes, backupCount=backups,
                                encoding="utf-8")
        h.setFormatter(fmt)
        lg.addHandler(h)
        lg.setLevel(level)
        lg.propagate = True
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)
    _CONFIGURED = True


def get(name: str) -> logging.Logger:
    """Return infrascan.<name> logger (auto-created)."""
    return logging.getLogger(f"infrascan.{name}")
