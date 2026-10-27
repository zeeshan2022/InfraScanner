"""Report generation: HTML, CSV, JSON, Executive PDF, Technical PDF, ZIP bundle.

All reports can be rebuilt from the latest stored scan (Generate Reports Only)
without rescanning. Branding/classification pulled from config.yaml.
"""

from __future__ import annotations

import csv
import html as html_mod
import json
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

from .enumerator import enumerate_services, evaluate_findings, severity_counts, SEVERITY_ORDER
from .logger import get
from .utils import human_duration, stamp

log = get("scanner")

SEV_COLORS = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f",
              "LOW": "#3498db", "INFO": "#95a5a6"}


# --------------------------------------------------------------------- inputs
def load_latest_inventory(cfg) -> dict | None:
    p = cfg.dir("scans_dir") / "processed" / "latest_inventory.json"
    if not p.exists():
        return None
    try:
        return json.load(open(p))
    except (json.JSONDecodeError, OSError):
        return None


def _hosts_from(inv: dict):
    from .scanner import Host
    return [Host.from_dict(h) for h in inv.get("hosts", [])]


# ------------------------------------------------------------------ statistics
def compute_stats(cfg, hosts) -> dict:
    port_counter = Counter()
    svc_counter = Counter()
    vlan_counter = Counter()
    os_counter = Counter()
    open_ports = 0
    for h in hosts:
        vlan_counter[h.vlan or "?"] += 1
        os_counter[_os_class(h.os_guess)] += 1
        for p in h.ports:
            open_ports += 1
            port_counter[p.port] += 1
            if p.service:
                svc_counter[p.service] += 1
    return {
        "hosts": len(hosts),
        "open_ports": open_ports,
        "top_ports": port_counter.most_common(10),
        "top_services": svc_counter.most_common(10),
        "vlan_distribution": vlan_counter.most_common(),
        "os_distribution": os_counter.most_common(),
    }


def _os_class(osname: str) -> str:
    o = (osname or "").lower()
    if "windows" in o:
        return "Windows"
    if any(k in o for k in ("linux", "oracle linux", "rhel", "ubuntu", "red hat")):
        return "Linux"
    if any(k in o for k in ("ios", "cisco", "junos", "nx-os", "switch", "router",
                            "printer", "hp", "ups")):
        return "Network Device/Printer"
    if o in ("", "unknown"):
        return "Unknown"
    return "Other"


# ------------------------------------------------------------------- builders
def generate_reports(cfg, inventory: dict | None = None,
                     changes: dict | None = None) -> list[Path]:
    """Produce all configured report formats; returns file paths."""
    inv = inventory or load_latest_inventory(cfg)
    if not inv:
        raise RuntimeError("No scan data found. Run a scan first.")
    hosts = _hosts_from(inv)
    inventories = {h.ip: enumerate_services(h) for h in hosts}
    findings = evaluate_findings(cfg, hosts, inventories)
    stats = compute_stats(cfg, hosts)
    meta = {
        "scan_time": inv.get("scan_time", ""),
        "duration": human_duration(inv.get("duration_sec", 0)),
        "profile": inv.get("profile", ""),
        "org": cfg.get("reporting.organization_name", "My Company"),
        "author": cfg.get("reporting.report_author", "InfraScanner"),
        "classification": cfg.get("reporting.classification", "Internal"),
        "product": f"{cfg.get('project.scanner_name', 'InfraScanner')} v{cfg.get('_version', '')}",
        "vendor": cfg.get("project.organization", "ZXSPRD.COM"),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    out_paths = []
    formats = cfg.get("reporting.formats", ["html", "csv", "pdf", "json"])
    rdirs = {f: cfg.dir("reports_dir") / f for f in formats}
    for d in rdirs.values():
        d.mkdir(parents=True, exist_ok=True)
    date = datetime.now().strftime("%Y%m%d")

    if "html" in formats:
        out_paths.append(_write_html(cfg, rdirs["html"], date, hosts, inventories,
                                     findings, stats, meta, changes))
    if "csv" in formats:
        out_paths.append(_write_csv(rdirs["csv"], date, hosts, inventories, findings))
    if "json" in formats:
        out_paths.append(_write_json(rdirs["json"], date, hosts, inventories,
                                     findings, stats, meta))
    if "pdf" in formats:
        if cfg.get("reporting.executive_pdf", True):
            out_paths.append(_write_exec_pdf(rdirs["pdf"], date, findings, stats, meta))
        if cfg.get("reporting.technical_pdf", True):
            out_paths.append(_write_tech_pdf(rdirs["pdf"], date, hosts, inventories,
                                             findings, stats, meta))
    if cfg.get("reporting.change_report", True) and changes is not None:
        out_paths.append(_write_change_html(cfg, rdirs.get("html", cfg.dir("reports_dir") / "html"),
                                            date, changes, meta))
    # symlink/copy 'latest' pointer
    latest = cfg.dir("reports_dir") / "latest"
    latest.mkdir(exist_ok=True)
    for p in out_paths:
        dst = latest / p.name
        try:
            dst.write_bytes(p.read_bytes())
        except OSError:
            pass
    return out_paths


def _write_html(cfg, dirpath, date, hosts, inventories, findings, stats, meta, changes):
    path = dirpath / f"Infrastructure_Report_{date}.html"
    counts = severity_counts(findings)
    rows = []
    for h in sorted(hosts, key=lambda x: (x.vlan, x.ip)):
        ports_html = "<br>".join(
            f"{p.port}/{p.protocol} {html_mod.escape(p.service)} "
            f"{html_mod.escape((p.product + ' ' + p.version).strip())}"
            for p in sorted(h.ports, key=lambda x: x.port)) or "-"
        inv = inventories.get(h.ip, {})
        extra = []
        for db in inv.get("databases", []):
            extra.append(f"DB: {db['name']}:{db['port']}")
        for c in inv.get("ssl", []):
            flag = "EXPIRED" if c["expired"] else ("self-signed" if c["self_signed"] else "ok")
            extra.append(f"SSL {flag}")
        smb = inv.get("smb", {})
        if smb.get("detected"):
            extra.append("SMBv1!" if smb.get("smbv1") else "SMB")
        rows.append(f"<tr><td>{html_mod.escape(h.hostname or '-')}</td><td>{h.ip}</td>"
                    f"<td>{h.vlan}</td><td>{html_mod.escape(h.os_guess)}</td>"
                    f"<td>{len(h.ports)}</td><td>{ports_html}</td>"
                    f"<td>{html_mod.escape('; '.join(extra)) or '-'}</td></tr>")
    find_rows = "".join(
        f"<tr><td><span style='color:{SEV_COLORS[f['severity']]};font-weight:bold'>"
        f"{f['severity']}</span></td><td>{html_mod.escape(f['category'])}</td>"
        f"<td>{f['host']}</td><td>{html_mod.escape(f['detail'])}</td></tr>"
        for f in findings[:500])
    top_ports = "".join(f"<li>{port} - {n} hosts</li>" for port, n in stats["top_ports"])
    vlans = "".join(f"<li>{v} - {n}</li>" for v, n in stats["vlan_distribution"])
    oss = "".join(f"<li>{o} - {n}</li>" for o, n in stats["os_distribution"])
    change_block = ""
    if changes and not changes.get("first_scan"):
        change_block = (f"<h2>Asset Changes vs Previous Scan</h2><p>New hosts: "
                        f"{len(changes['new_hosts'])} | Removed: {len(changes['removed_hosts'])} | "
                        f"New ports: {len(changes['new_ports'])} | Closed ports: "
                        f"{len(changes['closed_ports'])} | OS changed: {len(changes['os_changed'])} | "
                        f"Hostname changed: {len(changes['hostname_changed'])}</p>")
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Infrastructure Report - {meta['org']}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:2em;color:#222}}
h1{{border-bottom:3px solid #2c3e50}} table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:4px 8px;font-size:13px}} th{{background:#2c3e50;color:#fff;text-align:left}}
tr:nth-child(even){{background:#f4f6f7}} .badge{{padding:2px 8px;border-radius:4px;color:#fff}}
.footer{{margin-top:2em;font-size:12px;color:#777}}
</style></head><body>
<h1>{meta['org']} - Infrastructure Scan Report</h1>
<p><b>Classification:</b> {meta['classification']} &nbsp;|&nbsp;
<b>Generated:</b> {meta['generated']} &nbsp;|&nbsp; <b>Scan time:</b> {meta['scan_time']}
&nbsp;|&nbsp; <b>Profile:</b> {meta['profile']} &nbsp;|&nbsp; <b>Duration:</b> {meta['duration']}</p>
<h2>Executive Summary</h2>
<ul>
<li>Active hosts: <b>{stats['hosts']}</b></li>
<li>Open ports: <b>{stats['open_ports']}</b></li>
<li>Findings: CRITICAL <b>{counts['CRITICAL']}</b>, HIGH <b>{counts['HIGH']}</b>,
MEDIUM <b>{counts['MEDIUM']}</b>, LOW <b>{counts['LOW']}</b>, INFO <b>{counts['INFO']}</b></li>
</ul>
{change_block}
<h2>Top Ports</h2><ul>{top_ports}</ul>
<h2>Hosts per VLAN</h2><ul>{vlans}</ul>
<h2>OS Distribution</h2><ul>{oss}</ul>
<h2>Security Findings (severity ranked)</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Detail</th></tr>{find_rows}</table>
<h2>Host Inventory ({len(hosts)})</h2>
<table><tr><th>Hostname</th><th>IP</th><th>VLAN</th><th>OS</th><th>Open</th>
<th>Ports / Services</th><th>Notes</th></tr>{''.join(rows)}</table>
<div class="footer">{meta['product']} - Copyright (c) {meta['vendor']} - GNU GPL v3 -
Report author: {meta['author']}</div>
</body></html>"""
    path.write_text(doc, encoding="utf-8")
    log.info("HTML report: %s", path)
    return path


def _write_csv(dirpath, date, hosts, inventories, findings):
    path = dirpath / f"Infrastructure_Report_{date}.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["hostname", "ip", "vlan", "os", "port", "protocol",
                    "state", "service", "product", "version", "tunnel",
                    "databases", "http_title", "ssl_expired", "smbv1"])
        for h in sorted(hosts, key=lambda x: (x.vlan, x.ip)):
            inv = inventories.get(h.ip, {})
            dbs = ";".join(f"{d['name']}:{d['port']}" for d in inv.get("databases", []))
            titles = ";".join(x.get("title", "") for x in inv.get("http", []))
            expired = any(c["expired"] for c in inv.get("ssl", []))
            smbv1 = bool(inv.get("smb", {}).get("smbv1"))
            if not h.ports:
                w.writerow([h.hostname, h.ip, h.vlan, h.os_guess, "", "", "",
                            "", "", "", "", dbs, titles, expired, smbv1])
            for p in sorted(h.ports, key=lambda x: x.port):
                w.writerow([h.hostname, h.ip, h.vlan, h.os_guess, p.port, p.protocol,
                            p.state, p.service, p.product, p.version, p.tunnel,
                            dbs, titles, expired, smbv1])
    log.info("CSV report: %s", path)
    return path


def _write_json(dirpath, date, hosts, inventories, findings, stats, meta):
    path = dirpath / f"Infrastructure_Report_{date}.json"
    payload = {"meta": meta, "statistics": stats,
               "findings": findings,
               "hosts": [h.to_dict() | {"enumeration": inventories.get(h.ip, {})}
                         for h in hosts]}
    json.dump(payload, open(path, "w"), indent=2)
    log.info("JSON report: %s", path)
    return path


# ---------------------------------------------------------------------- PDFs
def _pdf_or_fallback(pdf_path: Path, title: str, lines: list[str], html_fallback: Path):
    """Render PDF with fpdf2; if unavailable write a printable .txt next to it."""
    try:
        from fpdf import FPDF
    except ImportError:
        txt = pdf_path.with_suffix(".txt")
        txt.write_text("\n".join(lines), encoding="utf-8")
        log.warning("fpdf2 missing - wrote text fallback %s (menu 11 installs it)", txt)
        return txt

    def clean(s: str) -> str:
        # latin-1 core fonts cannot render emoji/special unicode -> transliterate
        return s.encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, clean(title))          # legacy args leave cursor at right edge...
    pdf.ln(10)                              # ...reset to left margin before body
    pdf.set_font("Helvetica", "", 10)
    for ln in lines:
        pdf.multi_cell(0, 5, clean(ln), new_x="LMARGIN", new_y="NEXT")
    pdf.output(str(pdf_path))
    return pdf_path


def _write_exec_pdf(dirpath, date, findings, stats, meta):
    path = dirpath / f"Executive_Report_{date}.pdf"
    counts = severity_counts(findings)
    crit = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    lines = [
        f"Organization : {meta['org']}",
        f"Classification: {meta['classification']}",
        f"Scan date     : {meta['scan_time']}   Duration: {meta['duration']}",
        "",
        "INFRASTRUCTURE SUMMARY",
        f"  Active hosts : {stats['hosts']}",
        f"  Open ports   : {stats['open_ports']}",
        "",
        "FINDINGS BY SEVERITY",
        *[f"  {s:<9}: {counts[s]}" for s in SEVERITY_ORDER],
        "",
        "TOP CRITICAL/HIGH FINDINGS",
    ]
    if not crit:
        lines.append("  None detected.")
    for f in crit[:20]:
        lines.append(f"  [{f['severity']}] {f['category']} - {f['host']}")
    lines += ["", f"Generated by {meta['product']} (C) {meta['vendor']} - GPL v3"]
    return _pdf_or_fallback(path, "Infrastructure Executive Report", lines, path)


def _write_tech_pdf(dirpath, date, hosts, inventories, findings, stats, meta):
    path = dirpath / f"Technical_Report_{date}.pdf"
    lines = [f"Organization : {meta['org']}",
             f"Scan date    : {meta['scan_time']}  Profile: {meta['profile']}",
             f"Hosts: {stats['hosts']}  Open ports: {stats['open_ports']}", ""]
    for h in sorted(hosts, key=lambda x: (x.vlan, x.ip)):
        lines.append(f"HOST {h.ip}  {h.hostname}  VLAN={h.vlan}  OS={h.os_guess}")
        for p in sorted(h.ports, key=lambda x: x.port):
            lines.append(f"   {p.port}/{p.protocol} {p.state} {p.service} "
                         f"{p.product} {p.version}".rstrip())
        lines.append("")
    lines.append("FINDINGS")
    for f in findings[:200]:
        lines.append(f"[{f['severity']}] {f['category']} - {f['host']} - {f['detail']}")
    lines += ["", f"Generated by {meta['product']} (C) {meta['vendor']} - GPL v3"]
    return _pdf_or_fallback(path, "Infrastructure Technical Report", lines, path)


def _write_change_html(cfg, dirpath, date, changes, meta):
    dirpath.mkdir(parents=True, exist_ok=True)
    path = dirpath / f"change_report_{date}.html"

    def table(items, cols, headers):
        if not items:
            return "<p><i>None</i></p>"
        body = "".join("<tr>" + "".join(f"<td>{html_mod.escape(str(i.get(c, '')))}</td>"
                                        for c in cols) + "</tr>" for i in items)
        head = "".join(f"<th>{h}</th>" for h in headers)
        return f"<table><tr>{head}</tr>{body}</table>"

    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Change Report</title>
<style>body{{font-family:Segoe UI,Arial;margin:2em}}table{{border-collapse:collapse}}
td,th{{border:1px solid #aaa;padding:3px 8px}}</style></head><body>
<h1>Infrastructure Change Report - {meta['org']}</h1>
<p>Generated {meta['generated']} | Classification: {meta['classification']}</p>
<h2>New Hosts ({len(changes['new_hosts'])})</h2>{table(changes['new_hosts'], ['ip','vlan','hostname'], ['IP','VLAN','Hostname'])}
<h2>Removed Hosts ({len(changes['removed_hosts'])})</h2>{table(changes['removed_hosts'], ['ip','vlan','hostname'], ['IP','VLAN','Hostname'])}
<h2>New Open Ports ({len(changes['new_ports'])})</h2>{table(changes['new_ports'], ['ip','port','proto'], ['IP','Port','Proto'])}
<h2>Closed Ports ({len(changes['closed_ports'])})</h2>{table(changes['closed_ports'], ['ip','port','proto'], ['IP','Port','Proto'])}
<h2>OS Changed ({len(changes['os_changed'])})</h2>{table(changes['os_changed'], ['ip','old','new'], ['IP','Old','New'])}
<h2>Hostname Changed ({len(changes['hostname_changed'])})</h2>{table(changes['hostname_changed'], ['ip','old','new'], ['IP','Old','New'])}
<div style="color:#777;font-size:12px">{meta['product']} - Copyright (c) {meta['vendor']}</div>
</body></html>"""
    path.write_text(doc, encoding="utf-8")
    return path


# ----------------------------------------------------------------------- ZIP
def package_zip(cfg, report_paths: list[Path]) -> Path | None:
    if not cfg.get("reporting.package_zip", True) or not report_paths:
        return None
    date = datetime.now().strftime("%Y%m%d")
    zp = cfg.dir("reports_dir") / f"Infrastructure_Report_{date}.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in report_paths:
            if p.exists():
                zf.write(p, arcname=p.name)
    log.info("ZIP bundle: %s", zp)
    return zp
