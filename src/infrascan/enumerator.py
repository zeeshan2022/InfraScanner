"""Service enumeration + security findings with severity levels.

Extracts SSL/TLS certificate info, HTTP banners/titles, SMB details and
database presence from nmap XML results (scripts + service fields), then
evaluates severity rules: CRITICAL / HIGH / MEDIUM / LOW / INFO.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .logger import get

log = get("scanner")

DB_SERVICES = {"oracle", "oracle-tsn", "ms-sql-s", "mysql", "postgresql",
               "mongodb", "mssql", "db2", "sybase"}
DB_PORTS = {1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
            27017: "MongoDB"}
HIGH_RISK_PORTS = {3389: "RDP", 445: "SMB", 139: "NetBIOS", 21: "FTP",
                   23: "Telnet"}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _find_sev(cfg, key, default):
    return cfg.get(f"severity_rules.{key}", default)


def enumerate_services(host) -> dict:
    """Return structured enrichment for a Host dataclass."""
    info = {"http": [], "ssl": [], "smb": {}, "databases": []}
    for p in host.ports:
        svc = (p.service or "").lower()
        prod = (p.product or "").lower()
        # databases
        if p.port in DB_PORTS or svc in DB_SERVICES:
            name = DB_PORTS.get(p.port, svc)
            info["databases"].append({"port": p.port, "name": name,
                                      "product": p.product, "version": p.version})
        # http / https
        if svc in ("http", "https", "http-proxy") or p.tunnel == "ssl":
            info["http"].append({"port": p.port, "service": p.service,
                                 "product": p.product, "version": p.version,
                                 "tunnel": p.tunnel})
    # NSE script outputs
    scripts = host.scripts or {}
    title = scripts.get("http-title", "")
    m = re.search(r"Site title:\s*(.+)", title)
    if m:
        for h in info["http"]:
            h.setdefault("title", m.group(1).strip())
    server_hdr = ""
    hm = re.search(r"Server:\s*(\S+)", scripts.get("http-headers", ""))
    if hm:
        server_hdr = hm.group(1)
        for h in info["http"]:
            h.setdefault("server_header", server_hdr)
    # ssl-cert script output
    cert_out = scripts.get("ssl-cert", "")
    if cert_out:
        cert = _parse_cert(cert_out)
        info["ssl"].append(cert)
    # smb-os-discovery
    smb_out = scripts.get("smb-os-discovery", "") + scripts.get("smb-security-mode", "")
    if smb_out:
        smbv1 = bool(re.search(r"SMBv?1|protocol\s*=\s*NT1", smb_out, re.I))
        signing = None
        ms = re.search(r"(message signing (supported|required|enabled)|"
                       r"enable_security_signature[_ ]?=[_ ]?\w+)", smb_out, re.I)
        if ms:
            signing = ms.group(1)
        info["smb"] = {"detected": True, "smbv1": smbv1, "signing": signing,
                       "raw": smb_out[:500]}
    return info


def _parse_cert(text: str) -> dict:
    cert = {"subject": "", "issuer": "", "not_after": "", "expired": False,
            "self_signed": False, "tls_version": ""}
    sub = re.search(r"Subject:\s*(.+)", text)
    if sub:
        cert["subject"] = sub.group(1).strip()
    iss = re.search(r"Issuer:\s*(.+)", text)
    if iss:
        cert["issuer"] = iss.group(1).strip()
        if cert["subject"] and cert["subject"] == cert["issuer"]:
            cert["self_signed"] = True
    na = re.search(r"Not After\s*:\s*(.+)", text)
    if na:
        cert["not_after"] = na.group(1).strip()
        try:
            exp = datetime.strptime(cert["not_after"], "%y%m%d%H%M%SZ")
            cert["expired"] = exp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        except ValueError:
            pass
    tv = re.search(r"TLSv?(\d[\.\d]*)", text)
    if tv:
        cert["tls_version"] = "TLS" + tv.group(1)
    return cert


def evaluate_findings(cfg, hosts: list, inventories: dict) -> list[dict]:
    """Severity-ranked findings across the estate."""
    findings = []
    dmz_names = {n["name"].lower() for n in cfg.get("networks", [])
                 if "dmz" in n["name"].lower()}

    def add(sev, category, host_ip, detail):
        findings.append({"severity": sev, "category": category,
                         "host": host_ip, "detail": detail})

    for h in hosts:
        inv = inventories.get(h.ip, {})
        is_dmz = h.vlan.lower() in dmz_names or "dmz" in h.vlan.lower()
        open_ports = {p.port for p in h.ports}
        # RDP exposed
        if 3389 in open_ports:
            if is_dmz:
                add(_find_sev(cfg, "rdp_in_dmz", "CRITICAL"), "RDP exposed in DMZ",
                    h.ip, "TCP 3389 open on DMZ segment")
            else:
                add("MEDIUM", "RDP exposed", h.ip, "TCP 3389 open")
        # Databases
        for db in inv.get("databases", []):
            if is_dmz:
                add(_find_sev(cfg, "exposed_database_in_dmz", "CRITICAL"),
                    "Database exposed in DMZ", h.ip,
                    f"{db['name']} on port {db['port']}")
            else:
                add(_find_sev(cfg, "open_database", "HIGH"), "Database reachable",
                    h.ip, f"{db['name']} on port {db['port']}")
        # SMB
        smb = inv.get("smb", {})
        if smb.get("smbv1"):
            add(_find_sev(cfg, "smbv1", "HIGH"), "SMBv1 detected", h.ip,
                "Legacy SMB protocol enabled")
        elif 445 in open_ports and is_dmz:
            add("HIGH", "SMB exposed in DMZ", h.ip, "TCP 445 open on DMZ segment")
        # SSL
        for cert in inv.get("ssl", []):
            if cert.get("expired"):
                add(_find_sev(cfg, "expired_ssl", "MEDIUM"), "Expired SSL certificate",
                    h.ip, f"Cert for {cert['subject'] or 'unknown'} expired")
            elif cert.get("self_signed"):
                add(_find_sev(cfg, "ssl_self_signed", "MEDIUM"), "Self-signed certificate",
                    h.ip, f"Subject {cert['subject'] or 'unknown'}")
        # HTTP
        if inv.get("http"):
            add(_find_sev(cfg, "http_exposed", "LOW"), "HTTP/HTTPS service",
                h.ip, ", ".join(str(x["port"]) for x in inv["http"]))
        # Telnet / FTP always flagged
        for port, label in ((23, "Telnet"), (21, "FTP")):
            if port in open_ports:
                add("HIGH", f"Insecure protocol: {label}", h.ip, f"TCP {port} open")
        # Unknown devices
        if h.os_guess in ("", "Unknown") and not h.hostname:
            add(_find_sev(cfg, "unknown_device", "INFO"), "Unknown device", h.ip,
                "No hostname or OS identified")

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return findings


def severity_counts(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
