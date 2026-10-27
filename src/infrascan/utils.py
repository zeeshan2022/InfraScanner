"""Shared helpers: privilege detection, time windows, network utilities."""

from __future__ import annotations

import ipaddress
import os
import shutil
from datetime import datetime, timedelta


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def disk_free_gb(path) -> float:
    try:
        return shutil.disk_usage(str(path)).free / (1024 ** 3)
    except OSError:
        return -1.0


def in_maintenance_window(start_hhmm: str, end_hhmm: str, now=None) -> bool:
    """True if now is inside [start, end) handling wrap past midnight."""
    now = now or datetime.now()
    s = datetime.strptime(start_hhmm, "%H:%M").time()
    e = datetime.strptime(end_hhmm, "%H:%M").time()
    cur = now.time()
    if s <= e:
        return s <= cur < e
    return cur >= s or cur < e


def subnet_ips(subnet: str):
    net = ipaddress.ip_network(subnet, strict=False)
    return list(net.hosts()) if net.num_addresses > 2 else list(net)


def ip_in_exclusions(ip: str, hosts: list, subnets: list) -> bool:
    addr = ipaddress.ip_address(ip)
    if str(addr) in {str(h) for h in hosts}:
        return True
    for s in subnets:
        if addr in ipaddress.ip_network(s, strict=False):
            return True
    return False


def vlan_for_ip(ip: str, networks: list) -> str:
    addr = ipaddress.ip_address(ip)
    for n in networks:
        try:
            if addr in ipaddress.ip_network(n["subnet"], strict=False):
                return n["name"]
        except (ValueError, KeyError):
            continue
    return "UNKNOWN"


def human_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}h {m:02d}m {s:02d}s"


def stamp(dt=None) -> str:
    return (dt or datetime.now()).strftime("%Y%m%d_%H%M%S")
