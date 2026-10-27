"""Scan engine: discovery, deep scan, resume checkpoints, exclusions,
maintenance-window protection. Uses python-nmap-parser if available, but the
XML parsing here is stdlib-only (xml.etree) so there is one less dependency.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .logger import get
from .utils import (in_maintenance_window, ip_in_exclusions, stamp, subnet_ips,
                    vlan_for_ip)

log = get("scanner")


class ScanError(Exception):
    pass


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


@dataclass
class Port:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""


@dataclass
class Host:
    ip: str
    vlan: str = ""
    hostname: str = ""
    status: str = "up"
    os_guess: str = "Unknown"
    mac: str = ""
    ports: list = field(default_factory=list)   # list[Port]
    scripts: dict = field(default_factory=dict)  # id -> output text
    scanned_at: str = ""

    def to_dict(self):
        d = asdict(self)
        d["ports"] = [asdict(p) if isinstance(p, Port) else p for p in self.ports]
        return d

    @staticmethod
    def from_dict(d):
        h = Host(ip=d["ip"], vlan=d.get("vlan", ""), hostname=d.get("hostname", ""),
                 status=d.get("status", "up"), os_guess=d.get("os_guess", "Unknown"),
                 mac=d.get("mac", ""), scripts=d.get("scripts", {}),
                 scanned_at=d.get("scanned_at", ""))
        h.ports = [Port(**p) for p in d.get("ports", [])]
        return h


# ---------------------------------------------------------------------------
# Phase 1 - host discovery (ping sweep per VLAN)
# ---------------------------------------------------------------------------

def discover_network(cfg, subnet: str) -> list[str]:
    """Nmap ping sweep; returns list of alive IPv4/IPv6 strings."""
    if not nmap_available():
        raise ScanError("nmap binary not found - run menu 11 (Install Requirements)")
    excl_h = cfg.get("exclude.hosts", []) or []
    excl_s = cfg.get("exclude.subnets", []) or []
    tmp = cfg.dir("temp_dir") / f"discover_{stamp()}"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["nmap", "-sn", "-PS", "-PA", "-PU", "-PE",
           "--host_timeout", cfg.get("performance.host_timeout", "15m"),
           "-v", "-oX", f"{tmp}.xml", subnet]
    par = str(cfg.get("performance.discovery_parallelism", "300"))
    cmd += ["-T4", "--max_parallelism", par]
    log.info("Discovery %s ...", subnet)
    try:
        subprocess.run(cmd, check=False, timeout=3600 * 4,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        raise ScanError(f"Discovery timed out on {subnet}")
    alive = []
    if Path(f"{tmp}.xml").exists():
        root = ET.parse(f"{tmp}.xml").getroot()
        for host in root.iter("host"):
            addr = ""
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
            st = host.find("status")
            if addr and st is not None and st.get("state") == "up":
                if not ip_in_exclusions(addr, excl_h, excl_s):
                    alive.append(addr)
        Path(f"{tmp}.xml").unlink(missing_ok=True)
    log.info("Discovery %s -> %d live hosts", subnet, len(alive))
    return sorted(set(alive), key=lambda x: ipaddress.ip_address(x))


def discover_all(cfg) -> dict:
    """Returns {subnet: [ips]} across configured networks."""
    result = {}
    for net in cfg.get("networks", []):
        result[net["subnet"]] = discover_network(cfg, net["subnet"])
    total = sum(len(v) for v in result.values())
    ips = sum(ipaddress.ip_network(s, strict=False).num_addresses for s in result)
    _write_hosts_txt(cfg, result, ips, total)
    return result


def _write_hosts_txt(cfg, by_subnet, total_ips, total_alive):
    scans = cfg.dir("scans_dir") / "raw"
    scans.mkdir(parents=True, exist_ok=True)
    path = scans / "hosts.txt"
    with open(path, "w") as fh:
        for subnet, ips in by_subnet.items():
            for ip in ips:
                fh.write(f"{ip}\t{subnet}\t{vlan_for_ip(ip, cfg.get('networks', []))}\n")
    meta = scans / "discovery_meta.json"
    json.dump({"time": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "total_ips": total_ips, "alive": total_alive,
               "by_subnet": {k: len(v) for k, v in by_subnet.items()}},
              open(meta, "w"), indent=2)
    return path


# ---------------------------------------------------------------------------
# Phase 2/3 - deep scan of live hosts
# ---------------------------------------------------------------------------

def build_nmap_cmd(cfg, profile: dict, target: str, out_xml: Path,
                   privileged: bool) -> list[str]:
    args = ["nmap"]
    ports_spec = "T:1-65535" if profile.get("full_ports") \
        else f"T:--top-{profile.get('top_ports', 1000)}"
    if profile.get("udp_top100"):
        # nmap cannot mix --top-N with explicit ranges; use combined top list
        ports_spec = "--top-1100"
    args += ["-p", ports_spec]
    if profile.get("version_detection"):
        args += ["-sV"]
        vi = profile.get("version_intensity")
        if vi is not None:
            args += ["--version-intensity", str(vi)]
    if profile.get("nse_default"):
        args += ["-sC"]
    if profile.get("os_detection") and privileged:
        args += ["-O"]
    elif profile.get("os_detection") and not privileged:
        log.warning("OS detection skipped for %s (requires root)", target)
    args += ["-T" + _timing(profile.get("timing", "normal"))]
    perf = cfg.get("performance", {}) or {}
    if perf.get("packet_rate"):
        args += ["--max-rate", str(perf["packet_rate"])]
    args += ["--host_timeout", perf.get("host_timeout", "15m"),
             "--script_timeout", perf.get("script_timeout", "60s"),
             "--min_rt_timeout", perf.get("min_rtt_timeout", "200ms"),
             "--retries", str(perf.get("retries", 1))]
    args += ["-oX", str(out_xml), target]
    return args


_TIMING = {"paranoid": "0", "sneaky": "1", "polite": "2",
           "normal": "3", "aggressive": "4", "insane": "5"}


def _timing(name: str) -> str:
    return _TIMING.get(str(name).lower(), "3")


def parse_nmap_xml(xml_path: Path, networks: list) -> Host | None:
    """Parse a single-host nmap XML into Host dataclass."""
    if not xml_path.exists():
        return None
    root = ET.parse(xml_path).getroot()
    host_el = root.find("host")
    if host_el is None:
        return None
    status = host_el.find("status")
    if status is None or status.get("state") != "up":
        return None
    ip = hostname = mac = ""
    for a in host_el.findall("address"):
        t = a.get("addrtype")
        if t in ("ipv4", "ipv6"):
            ip = a.get("addr")
        elif t == "mac":
            mac = a.get("addr")
    names = host_el.find("hostnames")
    if names is not None:
        hn = names.find("hostname")
        if hn is not None:
            hostname = hn.get("name", "")
    h = Host(ip=ip, vlan=vlan_for_ip(ip, networks), hostname=hostname, mac=mac,
             scanned_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
    # OS
    os_el = host_el.find("os")
    if os_el is not None:
        line = os_el.find("osmatch")
        if line is not None:
            h.os_guess = line.get("name", "Unknown")
    for port_el in host_el.iter("port"):
        pid = port_el.get("protocol", "tcp")
        state = (port_el.find("state") or {}).get("state", "unknown") \
            if port_el.find("state") is not None else "unknown"
        if state != "open":
            continue
        svc = port_el.find("service")
        p = Port(port=int(port_el.get("portid", "0")), protocol=pid, state=state)
        if svc is not None:
            p.service = svc.get("name", "")
            p.product = svc.get("product", "")
            p.version = svc.get("version", "")
            p.extrainfo = svc.get("extrainfo", "")
            p.tunnel = svc.get("tunnel", "")
        h.ports.append(p)
    # host scripts (ssl-cert, smb-os-discovery, http-title etc.)
    hs = host_el.find("hostscript")
    if hs is not None:
        for s in hs.findall("script"):
            h.scripts[s.get("id", "")] = s.get("output", "").strip()
    return h


def scan_host(cfg, profile: dict, target: str, privileged: bool) -> Host | None:
    raw = cfg.dir("scans_dir") / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    out = raw / f"host_{target.replace(':', '_')}_{stamp()}.xml"
    cmd = build_nmap_cmd(cfg, profile, target, out, privileged)
    log.info("Deep scan %s (%s)", target, cfg.get("scan.profile"))
    try:
        subprocess.run(cmd, check=False, timeout=7200,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        log.error("Deep scan timed out on %s", target)
    h = parse_nmap_xml(out, cfg.get("networks", []))
    if h:
        keep = raw / f"result_{target}_{stamp()}.xml"
        try:
            out.rename(keep)
        except OSError:
            pass
    return h


# --------------------------------------------------------------- checkpointing
def _checkpoint_path(cfg) -> Path:
    return cfg.dir("scans_dir") / "processed" / "resume_checkpoint.json"


def save_checkpoint(cfg, state: dict) -> None:
    if not cfg.get("scan.resume_enabled", True):
        return
    p = _checkpoint_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    json.dump(state, open(p, "w"), indent=2)


def load_checkpoint(cfg) -> dict | None:
    p = _checkpoint_path(cfg)
    if p.exists():
        try:
            return json.load(open(p))
        except json.JSONDecodeError:
            return None
    return None


def clear_checkpoint(cfg) -> None:
    _checkpoint_path(cfg).unlink(missing_ok=True)


# --------------------------------------------------------------- main pipeline
def check_window(cfg, profile_name: str) -> tuple[bool, str]:
    """Maintenance window guard for heavy profiles."""
    mw = cfg.get("scan.maintenance_window", {}) or {}
    if not mw.get("enabled"):
        return True, ""
    if profile_name in ("deep", "extreme"):
        if not in_maintenance_window(mw.get("start", "22:00"), mw.get("end", "06:00")):
            return False, (f"Profile '{profile_name}' allowed only during "
                           f"maintenance window {mw.get('start')}-{mw.get('end')}")
    return True, ""


def run_full_scan(cfg, targets_by_subnet: dict | None = None,
                  operator: str = "") -> dict:
    """Full pipeline: discovery -> deep scan -> processed JSON. Returns summary."""
    from .notifier import notify_event
    from .change_detect import snapshot_and_compare

    if not nmap_available():
        raise ScanError("nmap not installed. Use menu 11.")
    profile_name = cfg.get("scan.profile", "standard")
    ok, why = check_window(cfg, profile_name)
    if not ok:
        raise ScanError(why)
    profile = cfg.get(f"scan_profiles.{profile_name}", {})
    privileged = _can_raw_sockets()

    started = time.time()
    total_ips = 0
    if targets_by_subnet is None:
        targets_by_subnet = discover_all(cfg)
    for s in targets_by_subnet:
        total_ips += ipaddress.ip_network(s, strict=False).num_addresses
    alive = [ip for ips in targets_by_subnet.values() for ip in ips]

    notify_event(cfg, "scan_started", {
        "networks": len(targets_by_subnet), "ips": total_ips,
        "live": len(alive), "operator": operator or _whoami(),
        "profile": profile_name})

    ckpt = load_checkpoint(cfg)
    done_map = {}
    if ckpt and ckpt.get("profile") == profile_name:
        done_map = {h["ip"]: Host.from_dict(h) for h in ckpt.get("hosts", [])}
        log.info("Resuming: %d hosts already completed", len(done_map))

    todo = [ip for ip in alive if ip not in done_map]
    hosts = list(done_map.values())
    max_par = int(cfg.get("performance.max_parallel_hosts", 8))
    errors = []

    def _one(ip):
        return scan_host(cfg, profile, ip, privileged)

    with ThreadPoolExecutor(max_workers=max_par) as ex:
        futures = {ex.submit(_one, ip): ip for ip in todo}
        for i, fut in enumerate(as_completed(futures), 1):
            ip = futures[fut]
            try:
                h = fut.result()
                if h:
                    hosts.append(h)
                if cfg.get("scan.resume_enabled", True) and i % 5 == 0:
                    save_checkpoint(cfg, {"profile": profile_name,
                                          "hosts": [h.to_dict() for h in hosts],
                                          "remaining": len(todo) - i})
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{ip}: {exc}")
                log.error("Host %s failed: %s", ip, exc)

    clear_checkpoint(cfg)
    duration = time.time() - started
    processed = cfg.dir("scans_dir") / "processed"
    processed.mkdir(parents=True, exist_ok=True)
    snap_file = processed / f"inventory_{stamp()}.json"
    json.dump({"scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "profile": profile_name, "duration_sec": round(duration, 1),
               "hosts": [h.to_dict() for h in hosts]},
              open(snap_file, "w"), indent=2)
    # latest pointer for report-only mode
    (processed / "latest_inventory.json").write_text(snap_file.read_text())

    changes = snapshot_and_compare(cfg, hosts)

    summary = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "profile": profile_name,
        "duration_sec": round(duration, 1),
        "networks": len(targets_by_subnet),
        "total_ips": total_ips,
        "live_hosts": len(hosts),
        "open_ports": sum(len(h.ports) for h in hosts),
        "errors": errors,
        "changes": changes,
        "inventory_file": str(snap_file),
    }
    notify_event(cfg, "scan_completed", summary)
    log.info("Scan complete: %d live hosts, %d open ports, %.0fs",
             summary["live_hosts"], summary["open_ports"], duration)
    return summary


def scan_single_target(cfg, target: str) -> dict:
    """Scan one IP (or explicit CIDR) without touching discovery state."""
    profile_name = cfg.get("scan.profile", "standard")
    ok, why = check_window(cfg, profile_name)
    if not ok:
        raise ScanError(why)
    profile = cfg.get(f"scan_profiles.{profile_name}", {})
    privileged = _can_raw_sockets()
    started = time.time()
    if "/" in target:
        ips = [str(i) for i in subnet_ips(target)]
        sub = {target: ips}
        _write_hosts_txt(cfg, sub, ipaddress.ip_network(target, strict=False).num_addresses, len(ips))
        return run_full_scan(cfg, sub)
    h = scan_host(cfg, profile, target, privileged)
    hosts = [h] if h else []
    processed = cfg.dir("scans_dir") / "processed"
    processed.mkdir(parents=True, exist_ok=True)
    json.dump({"scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "profile": profile_name, "duration_sec": round(time.time() - started, 1),
               "hosts": [x.to_dict() for x in hosts]},
              open(processed / "latest_inventory.json", "w"), indent=2)
    return {"live_hosts": len(hosts), "open_ports": sum(len(x.ports) for x in hosts),
            "duration_sec": round(time.time() - started, 1)}


def _can_raw_sockets() -> bool:
    import os
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    # fall back: can we bind a raw socket? (CAP_NET_RAW via sudo works too)
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except OSError:
        return False


def _whoami() -> str:
    import getpass
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
