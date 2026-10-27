"""Cron schedule management (view/add/modify/remove/enable/disable).

Managed entries are wrapped with marker comments so they can be identified:
    # INFRA-SCANNER-BEGIN <name>
    ...
    # INFRA-SCANNER-END <name>
Schedules are also stored in config.yaml (schedules:) for backup/restore.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from .logger import get

log = get("scanner")

BEGIN = "# INFRA-SCANNER-BEGIN {name}"
END = "# INFRA-SCANNER-END {name}"

PRESETS = {
    "daily-discovery": {"name": "daily-discovery",
                        "description": "Daily discovery-only scan at 01:00",
                        "cron": "0 1 * * *"},
    "weekly-deep": {"name": "weekly-deep",
                    "description": "Weekly full deep scan Sunday 02:00",
                    "cron": "0 2 * * 0"},
    "monthly-report": {"name": "monthly-report",
                       "description": "Monthly management report 1st day 08:00",
                       "cron": "0 8 1 * *"},
}


def _crontab_bin() -> str:
    return shutil.which("crontab") or "crontab"


def read_crontab() -> str:
    try:
        r = subprocess.run([_crontab_bin(), "-l"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
    except OSError:
        pass
    return ""


def write_crontab(text: str) -> None:
    subprocess.run([_crontab_bin(), "-"], input=text, text=True, check=True)


def managed_names(cron_text: str) -> list[str]:
    return re.findall(r"# INFRA-SCANNER-BEGIN (\S+)", cron_text)


def list_schedules(cfg) -> list[dict]:
    """Return managed schedules merged from crontab + config."""
    out = []
    for s in cfg.get("schedules", []) or []:
        out.append(dict(s))
    return out


def command_for(kind: str, root: str) -> str:
    logf = f"{root}/logs/cron.log"
    if kind == "discovery":
        return (f"{root}/infrascan --non-interactive scan-all --discovery-only "
                f">> {logf} 2>&1")
    if kind == "deep":
        return f"{root}/infrascan --non-interactive full-scan >> {logf} 2>&1"
    if kind == "report":
        return f"{root}/infrascan --non-interactive report-and-send >> {logf} 2>&1"
    raise ValueError(f"unknown schedule kind {kind}")


def add_schedule(cfg, name: str, cron_expr: str, kind: str, enabled: bool = True) -> None:
    root = str(cfg.root)
    schedules = cfg.get("schedules", []) or []
    schedules = [s for s in schedules if s.get("name") != name]
    entry = {"name": name, "cron": cron_expr, "kind": kind,
             "enabled": enabled, "description": PRESETS.get(name, {}).get("description", kind)}
    schedules.append(entry)
    cfg.set("schedules", schedules)
    cfg.save()
    apply_crontab(cfg)
    log.info("Schedule '%s' (%s) saved", name, cron_expr)


def remove_schedule(cfg, name: str) -> bool:
    schedules = [s for s in (cfg.get("schedules", []) or []) if s.get("name") != name]
    changed = len(schedules) != len(cfg.get("schedules", []) or [])
    cfg.set("schedules", schedules)
    cfg.save()
    apply_crontab(cfg)
    return changed


def set_enabled(cfg, name: str, enabled: bool) -> bool:
    schedules = cfg.get("schedules", []) or []
    found = False
    for s in schedules:
        if s.get("name") == name:
            s["enabled"] = enabled
            found = True
    cfg.set("schedules", schedules)
    cfg.save()
    apply_crontab(cfg)
    return found


def apply_crontab(cfg) -> None:
    """Rewrite only our managed block; leave everything else untouched."""
    current = read_crontab()
    # strip existing managed lines
    lines, keep, skipping = current.splitlines(), [], False
    for ln in lines:
        if ln.startswith(BEGIN.format(name="")):
            skipping = True
        if ln.strip().startswith("# INFRA-SCANNER-END"):
            skipping = False
            continue
        if ln.strip().startswith("# INFRA-SCANNER-BEGIN"):
            skipping = True
            continue
        if not skipping:
            keep.append(ln)
    root = str(cfg.root)
    for s in cfg.get("schedules", []) or []:
        if not s.get("enabled", True):
            continue
        cmd = command_for(s["kind"], root)
        keep.append(BEGIN.format(name=s["name"]))
        keep.append(f"{s['cron']} {cmd}")
        keep.append(END.format(name=s["name"]))
    write_crontab("\n".join(keep).strip() + "\n")
