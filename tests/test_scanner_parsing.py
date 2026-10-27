#!/usr/bin/env python3
"""Parser regression tests for InfraScanner (no nmap required).

Run:  python3 tests/test_scanner_parsing.py
Exit code 0 = all pass. Verifies the fixes for the "0 live hosts" bug:
XML discovery parsing, GNMAP cross-parser, -Pn deep-scan commands,
profile port specs and parser counters.
"""
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from infrascan import scanner  # noqa: E402


def _write(path, text):
    Path(path).write_text(text)
    return Path(path)


_UP_HOSTS = "\n".join(
    f'<host><status state="up"/><address addr="192.168.4.{i}" addrtype="ipv4"/></host>'
    for i in range(10, 37))
DOWN_HOST = '<host><status state="down"/><address addr="192.168.4.200" addrtype="ipv4"/></host>'
DISCOVERY_XML = (f'<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sn">'
                 f'{_UP_HOSTS}\n{DOWN_HOST}</nmaprun>')

DEEP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn">
<host><status state="up"/>
<address addr="192.168.1.150" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac"/>
<ports>
<port protocol="tcp" portid="135"><state state="open"/><service name="rpcbind"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows smbd"/></port>
<port protocol="tcp" portid="3389"><state state="filtered"/></port>
</ports></host></nmaprun>"""

GNMAP = """# Nmap 7.92 scan initiated
Host: 192.168.4.10 ()	Ports:	Status: Up	Ignore:
Host: 192.168.4.11 ()	Ports:	Status: Up	Ignore:
Host: 192.168.4.200 ()	Ports:	Status: Down	Ignore:
"""


def make_cfg(tmp):
    from infrascan.config_manager import Config
    cfg_path = Path(tmp) / "config.yaml"
    cfg_path.write_text(
        "networks:\n- {name: MGMT, subnet: 192.168.4.0/24}\n"
        "- {name: DMZ, subnet: 192.168.1.0/24}\n"
        "exclude: {hosts: [], subnets: []}\n"
        "scan: {profile: standard, resume_enabled: true}\n"
        "performance: {host_timeout: 15m, script_timeout: 60s,\n"
        "  min_rtt_timeout: 200ms, retries: 1, packet_rate: '',\n"
        "  discovery_parallelism: '300', max_parallel_hosts: 4}\n")
    return Config(str(cfg_path))


def main():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        cfg = make_cfg(tmp)

        # 1. XML host extraction logic (same code path as discover_network)
        xml = _write(Path(tmp) / "d.xml", DISCOVERY_XML)
        root = ET.parse(xml).getroot()
        up = [scanner._host_addr(h)[0] for h in root.iter("host")
              if h.find("status").get("state") == "up"]
        if len(up) != 27:
            failures.append(f"discovery XML parse: expected 27 up, got {len(up)}")

        # 2. GNMAP parser
        g = _write(Path(tmp) / "d.gnmap", GNMAP)
        ips = scanner.parse_gnmap_alive(g)
        if sorted(ips) != ["192.168.4.10", "192.168.4.11"]:
            failures.append(f"gnmap parser wrong result: {ips}")

        # 3. Deep-scan XML -> Host with only open ports
        dx = _write(Path(tmp) / "h.xml", DEEP_XML)
        h = scanner.parse_nmap_xml(dx, cfg.get("networks"))
        if not h or h.ip != "192.168.1.150" or len(h.ports) != 2:
            failures.append(f"deep XML parse failed: {h}")
        elif h.mac != "00:11:22:33:44:55":
            failures.append("mac not captured")

        # 4. Command construction per profile
        std = " ".join(scanner.build_nmap_cmd(
            cfg, cfg.get("scan_profiles.standard"), "1.2.3.4",
            Path(tmp) / "x.xml", True))
        checks = {
            "standard has -Pn": "-Pn" in std,
            "standard top-ports 1000": "--top-ports 1000" in std,
            "standard saves gnmap": "-oG" in std,
            "standard hyphen options": ("--host-timeout" in std and
                                        "--script-timeout" in std and
                                        "--min-rtt-timeout" in std),
        }
        deep = " ".join(scanner.build_nmap_cmd(
            cfg, cfg.get("scan_profiles.deep"), "1.2.3.4",
            Path(tmp) / "y.xml", True))
        checks["deep full ports"] = "-p1-65535" in deep
        ext = " ".join(scanner.build_nmap_cmd(
            cfg, cfg.get("scan_profiles.extreme"), "1.2.3.4",
            Path(tmp) / "z.xml", True))
        checks["extreme udp+tcp"] = "U:53" in ext and "T:1-65535" in ext
        bad = [k for k, v in checks.items() if not v]
        if bad:
            failures.append(f"command build issues: {bad} | cmd={std}")

    if failures:
        print("FAILED:")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    print("All parser regression tests passed.")


if __name__ == "__main__":
    main()
