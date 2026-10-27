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
# Subprocess helper (debug logging of command + stdout/stderr)
# ---------------------------------------------------------------------------

# Nmap CLI options we generate, validated against Nmap 7.92 / current stable.
# Maps our internal/performance keys to the correct nmap flag names.
_NMAP_FLAG_FIXES = {"--retries": "--max-retries"}   # --retries does NOT exist


def validate_nmap_cmd(cmd: list[str]) -> None:
    """Pre-execution validation of generated nmap arguments.

    Rejects known-bad flags (e.g. --retries, which makes nmap exit RC=255
    before scanning anything) and normalises them to the correct syntax.
    Raises ScanError on anything unfixable so a host scan aborts immediately
    instead of silently producing no XML."""
    fixed, out = [], []
    for tok in cmd:
        if tok in _NMAP_FLAG_FIXES:
            log.warning("Invalid nmap option '%s' in generated command - "
                        "correcting to '%s'", tok, _NMAP_FLAG_FIXES[tok])
            out.append(_NMAP_FLAG_FIXES[tok])
            continue
        out.append(tok)
    joined = " ".join(out)
    # sanity checks on numeric/enum style args
    import re as _re
    m = _re.search(r"--top-ports (\S+)", joined)
    if m and not m.group(1).isdigit():
        raise ScanError(f"invalid --top-ports value: {m.group(1)}")
    m = _re.search(r"-T(\S+)", joined)
    if m and m.group(1) not in "012345":
        raise ScanError(f"invalid timing template: -T{m.group(1)}")
    m = _re.search(r"--max-retries (\S+)", joined)
    if m and not m.group(1).isdigit():
        raise ScanError(f"invalid --max-retries value: {m.group(1)}")
    cmd[:] = out


def record_command(cmd: list[str], rc: int | None = None,
                   stderr: str = "", duration: float = 0.0) -> None:
    """Append the executed nmap command + result to logs/last_commands.log
    (rolling, last 200 entries kept) for the Diagnostics menu item."""
    try:
        from .config_manager import ROOT
        p = ROOT / cfg_logs_dir() / "last_commands.log"
        line = json.dumps({
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "cmd": " ".join(cmd), "rc": rc,
            "duration_sec": round(duration, 1),
            "stderr_tail": (stderr or "")[-500:],
        })
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        # keep rolling window of 200 commands
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
            if len(lines) > 200:
                p.write_text("\n".join(lines[-200:]) + "\n", encoding="utf-8")
        except OSError:
            pass
    except Exception:  # diagnostics must never break scanning
        pass


_CFG_REF = None  # set by _run_nmap via module-level config pointer


def cfg_logs_dir() -> Path:
    if _CFG_REF is not None:
        try:
            return _CFG_REF.dir("logs_dir")
        except Exception:
            pass
    return Path("logs")


def _run_nmap(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run nmap capturing output. Logs the exact command, exit code and
    stdout/stderr (DEBUG always; WARNING when verbose_debug or failure).
    Aborts immediately on non-zero return code with full stderr surfaced."""
    validate_nmap_cmd(cmd)
    verbose = bool(_CFG_REF and _CFG_REF.get("logging.verbose_debug", False))
    log.debug("EXEC: %s", " ".join(cmd))
    if verbose:
        log.info("NMAP CMD: %s", " ".join(cmd))
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, check=False, timeout=timeout,
                              capture_output=True, text=True)
    except FileNotFoundError:
        record_command(cmd, rc=-1, stderr="binary not found",
                      duration=time.time() - t0)
        raise ScanError(f"binary not found: {cmd[0]} - run menu 11 (Install Requirements)")
    except subprocess.TimeoutExpired:
        record_command(cmd, rc=-1, stderr="TIMEOUT", duration=time.time() - t0)
        log.error("TIMEOUT after %.0fs: %s", time.time() - t0, " ".join(cmd))
        raise
    dur = time.time() - t0
    record_command(cmd, rc=proc.returncode, stderr=proc.stderr or "",
                   duration=dur)
    log.debug("nmap exited rc=%d in %.1fs", proc.returncode, dur)
    if proc.stdout:
        log.debug("nmap STDOUT:\n%s", proc.stdout)
        if verbose and proc.returncode == 0:
            log.info("nmap STDOUT (tail):\n%s", proc.stdout[-2000:])
    if proc.stderr:
        log.debug("nmap STDERR:\n%s", proc.stderr)
    if proc.returncode != 0:
        # Full stderr ALWAYS logged at error level (requirement #5) and shown
        # to the operator when verbose debug is on (requirement #6).
        log.error("nmap FAILED rc=%d for: %s\nSTDERR:\n%s",
                  proc.returncode, " ".join(cmd), proc.stderr.strip() or "(empty)")
        if verbose and proc.stderr:
            print(f"\n!! nmap stderr:\n{proc.stderr.strip()}")
        raise ScanError(
            f"nmap exited with code {proc.returncode}: "
            f"{(proc.stderr or '').strip()[:300] or 'see logs/scanner.log'}")
    return proc


# ---------------------------------------------------------------------------
# Parsing helpers (XML + GNMAP, with raw-vs-parsed validation counters)
# ---------------------------------------------------------------------------

def _host_addr(host_el) -> tuple[str, str]:
    """Return (ip, mac) from a <host> element."""
    ip = mac = ""
    for a in host_el.findall("address"):
        t = a.get("addrtype")
        if t in ("ipv4", "ipv6"):
            ip = a.get("addr")
        elif t == "mac":
            mac = a.get("addr")
    return ip, mac


def parse_gnmap_alive(gnmap_path: Path) -> list[str]:
    """Parse an Nmap -oG file for up hosts ('Host: <ip> ()  Status: Up').
    Works for both -sn sweeps and -Pn scans (any 'Status: Up' counts)."""
    ips = []
    import re
    pat = re.compile(r"^Host:\s+(\S+).*Status:\s+Up", re.IGNORECASE)
    with open(gnmap_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = pat.match(line)
            if m:
                ips.append(m.group(1))
    return ips


# ---------------------------------------------------------------------------
# Phase 1 - host discovery (ping sweep per VLAN)
# ---------------------------------------------------------------------------

def discover_network(cfg, subnet: str) -> list[str]:
    """Nmap ping sweep; returns list of alive IPv4/IPv6 strings.

    Uses --open so filtered ports don't mask live hosts, writes XML + GNMAP
    raw files to scans/raw/, logs parsed-vs-raw counters, and falls back to
    -Pn if the sweep produced no output file."""
    if not nmap_available():
        raise ScanError("nmap binary not found - run menu 11 (Install Requirements)")
    excl_h = cfg.get("exclude.hosts", []) or []
    excl_s = cfg.get("exclude.subnets", []) or []
    raw = cfg.dir("scans_dir") / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    base = raw / f"discovery_{subnet.replace('/', '_')}_{stamp()}"
    cmd = ["nmap", "-sn", "-PS21-25,53,80,110,135,139,143,443,445,3389",
           "-PA,PU,PE", "--open",
           "-v", "-oX", f"{base}.xml", "-oG", f"{base}.gnmap", subnet]
    par = str(cfg.get("performance.discovery_parallelism", "300"))
    cmd += ["-T4", "--max-parallelism", par]
    hto = str(cfg.get("performance.host_timeout", "15m")).rstrip("m")
    cmd += ["--host-timeout", f"{hto}s"] if hto.isdigit() else \
           ["--host-timeout", str(cfg.get("performance.host_timeout", "15m"))]
    log.info("Discovery %s ...", subnet)
    global _CFG_REF
    _CFG_REF = cfg
    alive: list[str] = []
    try:
        proc = _run_nmap(cmd, timeout=3600 * 4)
    except ScanError:
        raise
    except subprocess.TimeoutExpired:
        raise ScanError(f"Discovery timed out on {subnet}")

    xml_file = Path(f"{base}.xml")
    gnmap_file = Path(f"{base}.gnmap")

    # Primary parse: XML
    raw_hosts = 0
    up_hosts = 0
    if xml_file.exists():
        try:
            root = ET.parse(xml_file).getroot()
            for host in root.iter("host"):
                raw_hosts += 1
                addr, _mac = _host_addr(host)
                st = host.find("status")
                if addr and st is not None and st.get("state") == "up":
                    up_hosts += 1
                    if not ip_in_exclusions(addr, excl_h, excl_s):
                        alive.append(addr)
        except ET.ParseError as exc:
            log.error("Discovery XML parse error in %s: %s", xml_file, exc)
    else:
        log.error("Discovery XML not found: %s (nmap rc=%s, stderr above)",
                  xml_file, proc.returncode)

    # Cross-validate with GNMAP parser
    if gnmap_file.exists():
        try:
            g_alive = parse_gnmap_alive(gnmap_file)
            log.debug("GNMAP cross-check %s: %d up hosts (XML said %d)",
                      subnet, len(g_alive), up_hosts)
            if not alive and g_alive:
                alive = [ip for ip in g_alive
                         if not ip_in_exclusions(ip, excl_h, excl_s)]
                log.info("Recovered %d hosts via GNMAP fallback for %s",
                         len(alive), subnet)
        except OSError as exc:
            log.error("GNMAP read error %s: %s", gnmap_file, exc)

    # Fallback: some firewalls drop all probe types -> retry with -Pn
    if not alive and not xml_file.exists():
        log.warning("Discovery produced no output for %s; retrying with -Pn", subnet)
        cmd2 = ["nmap", "-Pn", "-p21-25,53,80,110,135,139,143,443,445,3389",
                "--open", "-v", "-oX", f"{base}_pn.xml", subnet]
        try:
            _run_nmap(cmd2, timeout=3600 * 4)
        except subprocess.TimeoutExpired:
            pass
        pn = Path(f"{base}_pn.xml")
        if pn.exists():
            root = ET.parse(pn).getroot()
            for host in root.iter("host"):
                addr, _ = _host_addr(host)
                ports_open = any(
                    p.find("state") is not None and p.find("state").get("state") == "open"
                    for p in host.iter("port"))
                if addr and ports_open and not ip_in_exclusions(addr, excl_h, excl_s):
                    alive.append(addr)
            pn.unlink(missing_ok=True)

    log.info("Discovery %s -> raw_hosts=%d up_hosts=%d parsed_live=%d",
             subnet, raw_hosts, up_hosts, len(alive))
    if raw_hosts and not alive:
        log.warning("Nmap saw %d hosts but parser found 0 live - check %s "
                    "(enable logging.verbose_debug and inspect nmap STDOUT in scanner.log)",
                    raw_hosts, xml_file)
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
    # -Pn: host already proven alive by discovery (or explicitly requested);
    # never let a blocked/filtered ping make a live host look dead.
    args += ["-Pn"]
    if profile.get("udp_top100"):
        udp_list = ("U:53,67,68,69,123,137,138,161,162,389,445,514,5353,"
                    "1194,1701,1900,4500,5060,5355")
        tcp_part = "T:1-65535" if profile.get("full_ports") else \
            f"T:1-{profile.get('top_ports', 1000)}"
        args += ["-p", f"{tcp_part},{udp_list}"]
    elif profile.get("full_ports"):
        args += ["-p1-65535"]
    else:
        args += ["--top-ports", str(profile.get("top_ports", 1000))]
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
    args += ["--host-timeout", perf.get("host_timeout", "15m"),
             "--script-timeout", perf.get("script_timeout", "60s"),
             "--min-rtt-timeout", perf.get("min_rtt_timeout", "200ms"),
             # NOTE: nmap has no '--retries' option (exits RC=255).
             # The correct flag is '--max-retries'.
             "--max-retries", str(perf.get("retries", 1))]
    args += ["-oX", str(out_xml), "-oG", f"{out_xml}.gnmap", target]
    return args


_TIMING = {"paranoid": "0", "sneaky": "1", "polite": "2",
           "normal": "3", "aggressive": "4", "insane": "5"}


def _timing(name: str) -> str:
    return _TIMING.get(str(name).lower(), "3")


def parse_nmap_xml(xml_path: Path, networks: list) -> Host | None:
    """Parse an nmap XML (single- or multi-host) into Host dataclass.
    Returns the first UP host; logs why parsing failed for debugging."""
    if not xml_path.exists():
        log.error("Nmap XML not found after scan: %s", xml_path)
        return None
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        log.error("Nmap XML parse error in %s: %s", xml_path, exc)
        return None
    hosts_el = root.findall("host")
    if not hosts_el:
        log.error("Nmap XML %s contains no <host> elements", xml_path)
        return None
    host_el = None
    for he in hosts_el:
        st = he.find("status")
        if st is not None and st.get("state") == "up":
            host_el = he
            break
    if host_el is None:
        log.warning("Nmap XML %s: all %d host(s) reported DOWN by scanner",
                    xml_path.name, len(hosts_el))
        return None
    hostname = ""
    ip, mac = _host_addr(host_el)
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
    ports_el = host_el.find("ports")
    port_els = list(ports_el.findall("port")) if ports_el is not None \
        else list(host_el.iter("port"))
    open_total = 0
    for port_el in port_els:
        pid = port_el.get("protocol", "tcp")
        st_el = port_el.find("state")
        state = st_el.get("state") if st_el is not None else "unknown"
        if state != "open":
            continue
        open_total += 1
        svc = port_el.find("service")
        p = Port(port=int(port_el.get("portid", "0")), protocol=pid, state=state)
        if svc is not None:
            p.service = svc.get("name", "")
            p.product = svc.get("product", "")
            p.version = svc.get("version", "")
            p.extrainfo = svc.get("extrainfo", "")
            p.tunnel = svc.get("tunnel", "")
        h.ports.append(p)
    log.debug("XML parse %s: hosts_in_file=%d open_ports_parsed=%d",
              xml_path.name, len(hosts_el), open_total)
    # host scripts (ssl-cert, smb-os-discovery, http-title etc.)
    hs = host_el.find("hostscript")
    if hs is not None:
        for s in hs.findall("script"):
            h.scripts[s.get("id", "")] = s.get("output", "").strip()
    return h


def scan_host(cfg, profile: dict, target: str, privileged: bool) -> Host | None:
    global _CFG_REF
    _CFG_REF = cfg          # lets _run_nmap honour logging.verbose_debug
    raw = cfg.dir("scans_dir") / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    out = raw / f"host_{target.replace(':', '_')}_{stamp()}.xml"
    cmd = build_nmap_cmd(cfg, profile, target, out, privileged)
    log.info("Deep scan %s (%s)", target, cfg.get("scan.profile"))
    try:
        _run_nmap(cmd, timeout=7200)   # raises ScanError on rc!=0 -> abort host
    except subprocess.TimeoutExpired:
        log.error("Deep scan timed out on %s", target)
    h = parse_nmap_xml(out, cfg.get("networks", []))
    # Raw XML/GNMAP always kept in scans/raw/ for post-mortem debugging.
    log.info("Parse result %s: raw_xml=%s live=%s open_ports_parsed=%d",
             target, out.exists(), bool(h), len(h.ports) if h else 0)
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
    from .notifier import notify_event
    notify_event(cfg, "scan_started", {
        "networks": 1, "ips": 1, "live": 0,
        "operator": _whoami(), "profile": profile_name})
    h = scan_host(cfg, profile, target, privileged)
    hosts = [h] if h else []
    if not hosts:
        # XML said down/nothing - cross-check with a GNMAP-parsed sweep of
        # the single IP before declaring it dead.
        log.warning("Single-IP %s parsed as live=0; running discovery cross-check",
                    target)
        alive = discover_network(cfg, f"{target}/32")
        if alive:
            h = scan_host(cfg, dict(profile, full_ports=False), target, privileged)
            hosts = [h] if h else []
    summary = {"live_hosts": len(hosts),
               "open_ports": sum(len(x.ports) for x in hosts),
               "duration_sec": round(time.time() - started, 1)}
    notify_event(cfg, "scan_completed", summary)
    processed = cfg.dir("scans_dir") / "processed"
    processed.mkdir(parents=True, exist_ok=True)
    json.dump({"scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "profile": profile_name, "duration_sec": round(time.time() - started, 1),
               "hosts": [x.to_dict() for x in hosts]},
              open(processed / "latest_inventory.json", "w"), indent=2)
    return summary


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
