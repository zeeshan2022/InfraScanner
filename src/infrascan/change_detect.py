"""Asset change detection: compares current inventory vs previous scan.

Detects NEW HOST / REMOVED HOST / NEW PORT / CLOSED PORT / OS CHANGED /
HOSTNAME CHANGED and stores history in scans/processed/last_inventory.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from .logger import get

log = get("scanner")

PREV_FILE = "last_inventory.json"


def _prev_path(cfg) -> Path:
    return cfg.dir("scans_dir") / "processed" / PREV_FILE


def snapshot_and_compare(cfg, hosts: list) -> dict:
    """Compare new results to previous snapshot; store new snapshot as baseline.

    Returns change summary dict used by Teams notifier + change report.
    """
    cur = {h.ip: h for h in hosts}
    prev_file = _prev_path(cfg)
    changes = {"new_hosts": [], "removed_hosts": [], "new_ports": [],
               "closed_ports": [], "os_changed": [], "hostname_changed": [],
               "first_scan": not prev_file.exists()}
    prev = {}
    if prev_file.exists():
        try:
            data = json.load(open(prev_file))
            prev = {h["ip"]: h for h in data.get("hosts", [])}
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not read previous inventory: %s", exc)

    for ip, h in cur.items():
        if ip not in prev:
            changes["new_hosts"].append({"ip": ip, "vlan": h.vlan,
                                         "hostname": h.hostname})
            continue
        old = prev[ip]
        old_ports = {(p["port"], p.get("protocol", "tcp")) for p in old.get("ports", [])}
        new_ports = {(p.port, p.protocol) for p in h.ports}
        for pp in sorted(new_ports - old_ports):
            changes["new_ports"].append({"ip": ip, "port": pp[0], "proto": pp[1]})
        for pp in sorted(old_ports - new_ports):
            changes["closed_ports"].append({"ip": ip, "port": pp[0], "proto": pp[1]})
        if old.get("os_guess", "Unknown") != h.os_guess:
            changes["os_changed"].append({"ip": ip, "old": old.get("os_guess"),
                                          "new": h.os_guess})
        if (old.get("hostname", "") or "") != (h.hostname or ""):
            changes["hostname_changed"].append({"ip": ip,
                                                "old": old.get("hostname", ""),
                                                "new": h.hostname})
    for ip in prev:
        if ip not in cur:
            changes["removed_hosts"].append({"ip": ip,
                                             "vlan": prev[ip].get("vlan", ""),
                                             "hostname": prev[ip].get("hostname", "")})

    # write new baseline atomically
    snap = cfg.dir("scans_dir") / "processed" / "latest_inventory.json"
    if snap.exists():
        tmp = prev_file.with_suffix(".tmp")
        tmp.write_text(snap.read_text())
        Path.rename(tmp, prev_file)

    total = (len(changes["new_hosts"]) + len(changes["removed_hosts"]) +
             len(changes["new_ports"]) + len(changes["closed_ports"]) +
             len(changes["os_changed"]) + len(changes["hostname_changed"]))
    changes["total_changes"] = total
    log.info("Change detection: %d differences (%s first scan)",
             total, "" if not changes["first_scan"] else "initial ")
    return changes
