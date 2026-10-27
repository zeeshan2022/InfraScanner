"""Interactive menu + CLI for InfraScanner.

Menu (locked v2 spec):
 1 Full Infrastructure Scan      2 Scan Single VLAN       3 Scan Single IP
 4 Resume Interrupted Scan       5 Generate Reports       6 Send Reports
 7 View Last Report              8 View Statistics        9 View Change Report
10 Configure                     11 Install/Verify Requirements
12 Schedule Jobs                 13 Test Email            14 Test Teams
15 Health Check                  16 Maintenance           17 About
 0 Exit
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from .config_manager import Config, ConfigError
from .logger import setup as log_setup, get
from .maintenance import cleanup, health_check
from .mailer import send_reports, build_summary, send_test as email_test, EmailError
from .notifier import notify_event, send_test as teams_test
from .reporter import generate_reports, load_latest_inventory, package_zip, compute_stats
from .scanner import (ScanError, discover_all, run_full_scan, scan_single_target,
                      load_checkpoint, clear_checkpoint)
from .enumerator import enumerate_services, evaluate_findings, severity_counts
from .scheduler import PRESETS, add_schedule, list_schedules, remove_schedule, set_enabled
from .utils import human_duration, is_root

log = get("scanner")

BANNER = r"""
╔════════════════════════════════════════════════════════════╗
║   ____       _                ____                         ║
║  / ___|_ __ (_)_ __ __ _     / ___|  ___ __ _ _ __  _ __   ║
║ | |   | '_ \| | '__/ _` |_  | |  _ / _ \ '_ \| '_ \| '_ \  ║
║ | |___| | | | | | | (_| | | | |_| |  __/ |_) | |_) | |_) | ║
║  \____|_| |_|_|_|  \__,_|_|  \____|\___| .__/| .__/| .__/  ║
║                                        |_|   |_|   |_|     ║
║  Enterprise Network Discovery & Reporting Platform         ║
║  Copyright (c) ZXSPRD.COM  -  GNU GPL v3  -  zxsprd.com    ║
║  Version {ver}                                              ║
╚════════════════════════════════════════════════════════════╝
"""


def banner():
    print(BANNER.format(ver=__version__))


# ---------------------------------------------------------------- helpers
def _pause():
    try:
        input("\nPress Enter to continue...")
    except EOFError:
        pass


def _profile_menu(cfg):
    print("\nScan profile:")
    for i, name in enumerate(["quick", "standard", "deep", "extreme"], 1):
        mark = "*" if cfg.get("scan.profile") == name else " "
        desc = {"quick": "Top 100 ports, fast",
                "standard": "Top 1000 + services + OS + NSE (default)",
                "deep": "All TCP ports 1-65535 + full detection",
                "extreme": "All TCP + top-100 UDP + intensity 9"}[name]
        print(f"  {mark}{i}. {name:<9} - {desc}")
    sel = input("Select [1-4] or Enter to keep current: ").strip()
    if sel in {"1", "2", "3", "4"}:
        cfg.set("scan.profile", ["quick", "standard", "deep", "extreme"][int(sel) - 1])
        cfg.save()
        print(f"Profile set to: {cfg.get('scan.profile')}")


def _scan_and_report(cfg, targets=None, operator=""):
    t0 = time.time()
    summary = run_full_scan(cfg, targets, operator=operator)
    inv = load_latest_inventory(cfg)
    hosts = inv.get("hosts", []) if inv else []
    from .scanner import Host
    host_objs = [Host.from_dict(h) for h in hosts]
    enrich = {h.ip: enumerate_services(h) for h in host_objs}
    findings = evaluate_findings(cfg, host_objs, enrich)
    counts = severity_counts(findings)
    summary["critical_findings"] = counts["CRITICAL"]
    summary["high_findings"] = counts["HIGH"]
    paths = generate_reports(cfg, inv, changes=summary.get("changes"))
    zp = package_zip(cfg, paths)
    attachments = [zp] if zp else paths
    sent = False
    try:
        sent = send_reports(cfg, attachments, summary,
                            critical=(counts["CRITICAL"] > 0 and
                                      cfg.get("email.critical_severity_alert", True)))
    except EmailError as exc:
        log.error("Email step failed: %s", exc)
        print(f"!! Email failed: {exc}  (reports still saved in reports/)")
    if sent:
        notify_event(cfg, "report_sent", {
            "recipients": cfg.get("email.recipients", []),
            "attachments": len(attachments)})
    ch = summary.get("changes", {})
    if ch and ch.get("total_changes", 0) > 0:
        notify_event(cfg, "changes_detected", {
            "new_hosts": len(ch.get("new_hosts", [])),
            "removed_hosts": len(ch.get("removed_hosts", [])),
            "new_ports": len(ch.get("new_ports", [])),
            "closed_ports": len(ch.get("closed_ports", []))})
    print("\n--- Summary -------------------------------------------------")
    print(f"Duration      : {human_duration(time.time() - t0)}")
    print(f"Live hosts    : {summary['live_hosts']}")
    print(f"Open ports    : {summary['open_ports']}")
    print(f"Findings      : CRIT {counts['CRITICAL']} HIGH {counts['HIGH']} "
          f"MED {counts['MEDIUM']} LOW {counts['LOW']} INFO {counts['INFO']}")
    print(f"Reports       : {', '.join(p.name for p in paths)}")
    if zp:
        print(f"ZIP bundle    : {zp.name}")
    print(f"Email sent    : {'yes' if sent else 'no/skipped'}")
    return summary


# ---------------------------------------------------------------- actions
def act_full_scan(cfg):
    _profile_menu(cfg)
    if not is_root():
        print("NOTE: not running as root - SYN/OS-detection features degraded.")
    _scan_and_report(cfg)
    _pause()


def act_scan_vlan(cfg):
    nets = cfg.get("networks", [])
    print("\nAvailable VLANs:")
    for i, n in enumerate(nets, 1):
        print(f"  {i}. {n['name']:<14} {n['subnet']}")
    sel = input("Select VLAN number: ").strip()
    if not sel.isdigit() or not (1 <= int(sel) <= len(nets)):
        print("Invalid choice"); return _pause()
    net = nets[int(sel) - 1]
    _profile_menu(cfg)
    ips = discover_all_for(cfg, net["subnet"])
    _scan_and_report(cfg, {net["subnet"]: ips}, operator=_user())
    _pause()


def discover_all_for(cfg, subnet):
    from .scanner import discover_network
    return discover_network(cfg, subnet)


def act_scan_ip(cfg):
    ip = input("\nEnter IP or CIDR: ").strip()
    if not ip:
        return _pause()
    _profile_menu(cfg)
    res = scan_single_target(cfg, ip)
    inv = load_latest_inventory(cfg)
    paths = generate_reports(cfg, inv)
    print(f"\nResult: live={res.get('live_hosts')} open_ports={res.get('open_ports')}")
    print("Reports:", ", ".join(p.name for p in paths))
    _pause()


def act_resume(cfg):
    ck = load_checkpoint(cfg)
    if not ck:
        print("No interrupted scan found."); return _pause()
    done = len(ck.get("hosts", []))
    rem = ck.get("remaining", "?")
    print(f"\nInterrupted scan ({ck.get('profile')}) found.\n"
          f"Completed hosts: {done}\nRemaining estimate: {rem}")
    if input("Resume this scan? [y/N]: ").strip().lower() != "y":
        if input("Discard checkpoint instead? [y/N]: ").lower() == "y":
            clear_checkpoint(cfg)
        return _pause()
    # resume: rerun full pipeline; scanner picks up checkpoint automatically
    _scan_and_report(cfg)
    _pause()


def act_generate_reports(cfg):
    inv = load_latest_inventory(cfg)
    if not inv:
        print("No scan data available. Run a scan first."); return _pause()
    paths = generate_reports(cfg, inv)
    zp = package_zip(cfg, paths)
    print("Generated:", ", ".join(p.name for p in paths))
    if zp:
        print("ZIP:", zp.name)
    _pause()


def act_send_reports(cfg):
    rdir = cfg.dir("reports_dir") / "latest"
    files = sorted([p for p in rdir.glob("*") if p.is_file()]) if rdir.exists() else []
    if not files:
        print("No reports found in reports/latest. Generate first."); return _pause()
    zp = package_zip(cfg, files)
    attachments = [zp] if zp else files
    summary = build_summary(cfg, load_latest_inventory(cfg) or {})
    try:
        send_reports(cfg, attachments, summary)
        notify_event(cfg, "report_sent", {"recipients": cfg.get("email.recipients", []),
                                          "attachments": len(attachments)})
        print("Report emailed successfully.")
    except EmailError as exc:
        print(f"Email failed: {exc}")
    _pause()


def act_view_last(cfg):
    latest = cfg.dir("reports_dir") / "latest"
    htmls = sorted(latest.glob("*.html")) if latest.exists() else []
    if not htmls:
        print("No report yet."); return _pause()
    p = htmls[-1]
    print(f"Latest report: {p}")
    browser = os.environ.get("BROWSER")
    if browser:
        subprocess.Popen([browser, str(p)])
    else:
        print("Tip: set $BROWSER, or open the file with any viewer, e.g.:")
        print(f"  python3 -m http.server --directory {latest} 8088")
    _pause()


def act_statistics(cfg):
    """Shared stats printer; pauses only when interactive=True."""
    inv = load_latest_inventory(cfg)
    if not inv:
        print("No scan data."); return _pause()
    from .scanner import Host
    hosts = [Host.from_dict(h) for h in inv.get("hosts", [])]
    st = compute_stats(cfg, hosts)
    print(f"""
Last Scan     : {inv.get('scan_time')}
Profile       : {inv.get('profile')}
Duration      : {human_duration(inv.get('duration_sec', 0))}
VLANs Scanned : {len(cfg.get('networks', []))}
IPs Checked   : {sum(_net_size(n['subnet']) for n in cfg.get('networks', []))}
Live Hosts    : {st['hosts']}

OS Distribution:""")
    for o, n in st["os_distribution"]:
        print(f"  {o:<22}: {n}")
    print("\nHosts per VLAN:")
    for v, n in st["vlan_distribution"]:
        print(f"  {v:<14}: {n}")
    print("\nTop Ports:")
    for port, n in st["top_ports"]:
        print(f"  {port:<6}: {n} hosts")
    print("\nTop Services:")
    for svc, n in st["top_services"][:8]:
        print(f"  {svc:<14}: {n} hosts")


def _net_size(cidr):
    import ipaddress
    return ipaddress.ip_network(cidr, strict=False).num_addresses


def act_change_report(cfg):
    latest = cfg.dir("reports_dir") / "latest"
    p = sorted(latest.glob("change_report_*.html"))
    if p:
        print(f"Change report: {p[-1]}")
    else:
        print("No change report yet (generated after 2nd+ scan).")
    prevf = cfg.dir("scans_dir") / "processed" / "last_inventory.json"
    curf = cfg.dir("scans_dir") / "processed" / "latest_inventory.json"
    if prevf.exists() and curf.exists():
        prev = {h["ip"] for h in json.load(open(prevf)).get("hosts", [])}
        cur = {h["ip"] for h in json.load(open(curf)).get("hosts", [])}
        print(f"Quick diff -> new: {sorted(cur - prev)}  removed: {sorted(prev - cur)}")
    _pause()


# ---------------------------------------------------------------- configure
def menu_configure(cfg):
    while True:
        print("""
Configuration
 1. Network Ranges (add / edit / delete VLANs)
 2. Exclusions (hosts / subnets)
 3. SMTP Settings (server, port, TLS, auth, sender)
 4. Receipt Emails (add / remove / modify recipients)
 5. Teams Webhook Settings
 6. Scan Profile & Timing
 7. Performance Settings (threads, packet rate, timeouts)
 8. Report Settings (formats, branding, classification)
 9. Retention Settings
10. Restore Default Scan Settings
11. Backup Manager (save / list / restore config backups)
12. Export Config Wizard (portable bundle incl. backups)
13. Import Config Wizard (restore from bundle or file)
14. Verbose Debug Mode (log nmap commands, stdout/stderr, parser counters)
 0. Back""")
        c = input("> ").strip()
        if c == "0":
            return
        elif c == "1":
            cfg_networks(cfg)
        elif c == "2":
            cfg_exclusions(cfg)
        elif c == "3":
            cfg_smtp(cfg)
        elif c == "4":
            cfg_recipients(cfg)
        elif c == "5":
            cfg_teams(cfg)
        elif c == "6":
            _profile_menu(cfg)
            mw = input("Enable maintenance-window protection? [y/N]: ")
            if mw.lower() == "y":
                s = input("Start HH:MM [22:00]: ") or "22:00"
                e = input("End HH:MM [06:00]: ") or "06:00"
                cfg.set("scan.maintenance_window.enabled", True)
                cfg.set("scan.maintenance_window.start", s)
                cfg.set("scan.maintenance_window.end", e)
            else:
                cfg.set("scan.maintenance_window.enabled", False)
            cfg.save()
        elif c == "7":
            cfg_performance(cfg)
        elif c == "8":
            cfg_reporting(cfg)
        elif c == "9":
            cfg_retention_wizard(cfg)
        elif c == "10":
            if input("Restore factory DEFAULT SCAN settings? [y/N]: ").lower() == "y":
                cfg.backup()
                cfg.restore_scan_defaults()
                print("Scan/profile/performance settings restored to defaults.")
        elif c == "11":
            menu_backup_manager(cfg)
        elif c == "12":
            print("Export bundle written:", export_config_bundle(cfg))
        elif c == "13":
            imp = input("Path to bundle (.zip) or config yaml: ").strip()
            if imp:
                try:
                    import_config_bundle(cfg, Path(imp))
                    print("Config imported and validated; previous live config auto-backed up.")
                except Exception as exc:
                    print(f"Import failed: {exc}")
        elif c == "14":
            cur = bool(cfg.get("logging.verbose_debug", False))
            ans = input(f"Enable verbose debug mode? current={'ON' if cur else 'OFF'} [y/N]: ").strip().lower()
            cfg.set("logging.verbose_debug", ans == "y")
            cfg.save()
            print("Verbose debug is now", "ON - full nmap command/stdout/stderr and parser"
                  " counters will be written to logs/scanner.log"
                  if ans == "y" else "OFF")
            print("Note: takes effect on next program start.")


def _edit_list(items, prompt_key, add_prompt):
    """Generic editor for list-of-scalars."""
    while True:
        print("\nCurrent entries:")
        for i, v in enumerate(items, 1):
            print(f"  {i}. {v}")
        c = input("Enter number to delete, '+' to add, 'e<n>' to edit, Enter done: ").strip()
        if not c:
            return items
        if c == "+":
            items.append(input(add_prompt).strip())
        elif c.startswith("e") and c[1:].isdigit() and int(c[1:]) <= len(items):
            idx = int(c[1:]) - 1
            items[idx] = input(f"New value [{items[idx]}]: ").strip() or items[idx]
        elif c.isdigit() and int(c) <= len(items):
            items.pop(int(c) - 1)


def cfg_networks(cfg):
    nets = cfg.get("networks", [])
    while True:
        print("\nNetworks:")
        for i, n in enumerate(nets, 1):
            print(f"  {i}. {n['name']:<14} {n['subnet']}")
        c = input("+ add / e<num> edit / <num> delete / Enter done: ").strip()
        if not c:
            cfg.set("networks", nets); cfg.save(); return
        if c == "+":
            name = input("VLAN name: ").strip()
            subnet = input("Subnet (CIDR): ").strip()
            try:
                import ipaddress; ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                print("Invalid CIDR"); continue
            nets.append({"name": name, "subnet": subnet})
        elif c.startswith("e") and c[1:].isdigit() and int(c[1:]) <= len(nets):
            idx = int(c[1:]) - 1
            nets[idx]["name"] = input(f"Name [{nets[idx]['name']}]: ").strip() or nets[idx]["name"]
            nets[idx]["subnet"] = input(f"Subnet [{nets[idx]['subnet']}]: ").strip() or nets[idx]["subnet"]
        elif c.isdigit() and int(c) <= len(nets):
            nets.pop(int(c) - 1)


def cfg_exclusions(cfg):
    hosts = list(cfg.get("exclude.hosts", []) or [])
    subs = list(cfg.get("exclude.subnets", []) or [])
    print("(Edit excluded HOSTS)")
    hosts = _edit_list(hosts, "host", "IP to exclude: ")
    print("(Edit excluded SUBNETS)")
    subs = _edit_list(subs, "subnet", "Subnet to exclude (CIDR): ")
    cfg.set("exclude.hosts", hosts)
    cfg.set("exclude.subnets", subs)
    cfg.save()
    print("Exclusions saved.")


def cfg_smtp(cfg):
    """SMTP connection settings only (no recipients - see Receipt Emails)."""
    def ask(key, label):
        cur = cfg.get(key, "")
        val = input(f"{label} [{cur}]: ").strip()
        if val:
            cfg.set(key, val)
    print("\nSMTP Settings")
    ask("email.smtp_server", "SMTP server")
    p = input(f"SMTP port [{cfg.get('email.smtp_port', 587)}]: ").strip()
    if p.isdigit():
        cfg.set("email.smtp_port", int(p))
    ask("email.username", "Username")
    if input("Set password? [y/N]: ").lower() == "y":
        import getpass
        cfg.set("email.password", getpass.getpass("Password: "))
    tls = input("Use STARTTLS/TLS? [Y/n]: ").strip()
    cfg.set("email.use_tls", tls.lower() != "n")
    ask("email.sender", "Sender (From) address")
    ask("email.subject_prefix", "Subject prefix")
    en = input("Email enabled? [Y/n]: ").strip()
    cfg.set("email.enabled", en.lower() != "n")
    cfg.save()
    print("SMTP settings saved. Use 'Test Email' from the main menu to verify.")


def cfg_recipients(cfg):
    """Receipt email management: add / remove / modify report recipients."""
    print("\nReceipt Emails (report recipients)")
    recips = list(cfg.get("email.recipients", []) or [])
    recips = _edit_list(recips, "recipient", "Recipient email: ")
    # keep only non-empty, de-duplicated entries
    seen, clean = set(), []
    for r in recips:
        r = r.strip()
        if r and r not in seen:
            seen.add(r)
            clean.append(r)
    cfg.set("email.recipients", clean)
    cfg.save()
    print("Recipient list saved:", ", ".join(clean) if clean else "(none)")


def cfg_teams(cfg):
    url = cfg.get("teams.webhook_url", "")
    v = input(f"Teams Workflows webhook URL [{url}]: ").strip()
    if v:
        cfg.set("teams.webhook_url", v)
    en = input("Teams notifications enabled? [Y/n]: ").strip()
    cfg.set("teams.enabled", en.lower() != "n")
    cfg.save()
    print("Teams settings saved.")


def cfg_performance(cfg):
    def num(key, label, cast=int):
        cur = cfg.get(f"performance.{key}", "")
        v = input(f"{label} [{cur}]: ").strip()
        if v:
            try:
                cfg.set(f"performance.{key}", cast(v))
            except ValueError:
                cfg.set(f"performance.{key}", v)
    num("max_parallel_hosts", "Parallel host scans")
    num("packet_rate", "Packet rate limit (--max-rate, empty=none)", str)
    num("host_timeout", "Host timeout (e.g. 15m)")
    num("script_timeout", "Script timeout (e.g. 60s)")
    num("retries", "Retries")
    num("discovery_parallelism", "Discovery parallelism")
    cfg.save()
    print("Performance settings saved.")


def cfg_reporting(cfg):
    print("\nReport Settings (Enter keeps current value)")
    org = input(f"Organization name [{cfg.get('reporting.organization_name', '')}]: ").strip()
    if org:
        cfg.set("reporting.organization_name", org)
    cls = input(f"Classification label [{cfg.get('reporting.classification', 'Internal')}]: ").strip()
    if cls:
        cfg.set("reporting.classification", cls)
    fmts = input("Formats (comma: html,csv,pdf,json) [html,csv,pdf,json]: ").strip()
    if fmts:
        cfg.set("reporting.formats", [f.strip() for f in fmts.split(",")])
    cur_z = "Y/n" if cfg.get("reporting.package_zip", True) else "y/N"
    cfg.set("reporting.package_zip",
            input(f"ZIP bundle for email? [{cur_z}]: ").strip().lower() != "n")
    hist = input("Email subject for historical re-sends shows '(Historical <date>)'. "
                 "Enable historical report emailing? [Y/n]: ").strip().lower() != "n"
    cfg.set("email.historical_enabled", hist)
    cfg.save()
    print("Report settings saved.")


def cfg_retention_wizard(cfg):
    """Retention Configuration Wizard (menu 9 inside Configure)."""
    def ask_num(key, label, default):
        cur = cfg.get(f"retention.{key}", default)
        v = input(f"{label} [{cur}]: ").strip()
        if v:
            try:
                cfg.set(f"retention.{key}", int(v))
            except ValueError:
                print(f"  (ignored '{v}' - must be a number)")
    print("\nRetention Configuration Wizard\n"
          "(Enter keeps the current value; values apply on next cleanup run)")
    ask_num("report_days", "Report retention days", 90)
    ask_num("scan_days", "Scan data retention days", 90)
    ask_num("monthly_keep", "Keep monthly archives (count)", 12)
    ask_num("config_backups", "Config backups to keep (repo + /tmp emergency)", 20)
    lg = input("Log max size MB [5]: ").strip() or "5"
    try:
        cfg.set("logging.max_bytes", int(float(lg) * 1_048_576))
    except ValueError:
        pass
    lc = input("Log backup file count [5]: ").strip()
    if lc:
        try:
            cfg.set("logging.backup_count", int(lc))
        except ValueError:
            pass
    cfg.save()
    print("Retention policy saved. Run Maintenance -> Cleanup to apply now.")


# ------------------------------------------------------- backup manager / wizards
def menu_backup_manager(cfg):
    """Save / list / restore configuration backups.
    Every save goes to <repo>/backups AND an emergency copy in /tmp/InfraScanner.
    The last 20 backups are retained automatically."""
    while True:
        backups = cfg.list_backups()
        print(f"\nConfiguration Backup Manager   (keep last "
              f"{cfg.get('retention.config_backups', 20)}, emergency dir: "
              f"{cfg.EMERGENCY_BACKUP_DIR})")
        for i, b in enumerate(backups[:20], 1):
            print(f"  {i:>2}. {b.name:<38} {b.stat().st_size // 1024} KB")
        if not backups:
            print("  (no backups yet)")
        c = input("s=save new backup / <num>=restore / 0=back: ").strip().lower()
        if c in ("", "0"):
            return _pause()
        if c == "s":
            dest = cfg.backup()
            print("Backup saved:", dest)
            print("Emergency copy:", cfg.EMERGENCY_BACKUP_DIR / "backups" / dest.name)
        elif c.isdigit() and 1 <= int(c) <= len(backups):
            if input(f"Restore {backups[int(c)-1].name}? Current config will be "
                     f"auto-backed up first. [y/N]: ").lower() == "y":
                cfg.restore_from(backups[int(c) - 1])
                print("Config restored.")


def export_config_bundle(cfg) -> Path:
    """Wizard: portable ZIP with config.yaml + defaults + recent backups."""
    import zipfile as _zf
    out_dir = cfg.root / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    bundle = out_dir / f"infrascan_config_bundle_{stamp}.zip"
    with _zf.ZipFile(bundle, "w", _zf.ZIP_DEFLATED) as zf:
        zf.write(cfg.path, "config/config.yaml")
        from .config_manager import DEFAULTS_FILE
        if DEFAULTS_FILE.exists():
            zf.write(DEFAULTS_FILE, "config/config.defaults.yaml")
        for b in cfg.list_backups()[:20]:
            zf.write(b, f"backups/{b.name}")
    log.info("Config bundle exported: %s", bundle)
    return bundle


def import_config_bundle(cfg, src: Path) -> None:
    """Wizard: import a bundle ZIP (or plain config yaml) with validation."""
    import zipfile as _zf
    src = Path(src)
    if not src.exists():
        raise ConfigError(f"File not found: {src}")
    tmp_target = None
    if src.suffix.lower() == ".zip":
        extract = cfg.root / "backups" / "_import_tmp"
        extract.mkdir(parents=True, exist_ok=True)
        with _zf.ZipFile(src) as zf:
            if "config/config.yaml" not in zf.namelist():
                raise ConfigError("Bundle does not contain config/config.yaml")
            zf.extract("config/config.yaml", extract)
            for name in zf.namelist():
                if name.startswith("backups/") and name.endswith(".yaml"):
                    zf.extract(name, extract)
        tmp_target = extract / "config" / "config.yaml"
    elif src.suffix.lower() in (".yaml", ".yml"):
        tmp_target = src
    else:
        raise ConfigError("Unsupported file type (use .zip bundle or .yaml)")
    # validate parseability BEFORE touching the live config (rollback protection)
    import yaml as _yaml
    with open(tmp_target, encoding="utf-8") as fh:
        data = _yaml.safe_load(fh) or {}
    if not data.get("networks"):
        raise ConfigError("Imported config has no networks - refusing to import")
    cfg.restore_from(tmp_target)
    log.info("Config imported from %s", src)


# ---------------------------------------------------------------- schedule
def menu_schedule(cfg):
    while True:
        scheds = list_schedules(cfg)
        print("\nSchedule Jobs")
        for i, s in enumerate(scheds, 1):
            state = "enabled" if s.get("enabled", True) else "DISABLED"
            print(f"  {i}. {s['name']:<16} '{s['cron']}' kind={s['kind']} [{state}]")
        if not scheds:
            print("  (none configured)")
        print("""  a. Add from preset (daily-discovery / weekly-deep / monthly-report)
  c. Add custom entry
  d. Delete by number
  e/  dis. Toggle enable/disable by number
  0. Back""")
        c = input("> ").strip().lower()
        if c in ("0", ""):
            return
        elif c == "a":
            for i, (name, p) in enumerate(PRESETS.items(), 1):
                print(f"  {i}. {name} - {p['description']} ({p['cron']})")
            sel = input("Preset number: ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(PRESETS):
                name = list(PRESETS)[int(sel) - 1]
                expr = input(f"Cron expression [{PRESETS[name]['cron']}]: ").strip() \
                    or PRESETS[name]["cron"]
                kind = {"daily-discovery": "discovery", "weekly-deep": "deep",
                        "monthly-report": "report"}[name]
                add_schedule(cfg, name, expr, kind)
                print("Added and installed into crontab.")
        elif c == "c":
            name = input("Schedule name: ").strip()
            expr = input("Cron expression (e.g. 0 3 * * *): ").strip()
            kind = input("Kind (discovery/deep/report): ").strip()
            if name and expr and kind:
                add_schedule(cfg, name, expr, kind)
                print("Installed into crontab.")
        elif c.startswith("d") and c[1:].isdigit():
            idx = int(c[1:]) - 1
            if 0 <= idx < len(scheds):
                remove_schedule(cfg, scheds[idx]["name"])
                print("Removed.")
        elif c.startswith("e") and c[1:].isdigit():
            idx = int(c[1:]) - 1
            if 0 <= idx < len(scheds):
                s = scheds[idx]
                set_enabled(cfg, s["name"], not s.get("enabled", True))
                print("Toggled.")


def act_install(cfg):
    print("\nVerifying prerequisites...")
    for comp, status, detail in health_check(cfg):
        print(f"  [{status:<4}] {comp:<15} {detail}")
    if input("\nAttempt automatic install of missing system packages? [y/N]: ") \
            .strip().lower() == "y":
        installer = cfg.root / "install.sh"
        if installer.exists():
            r = subprocess.run(["bash", str(installer), "--deps-only"])
            print("Installer exit code:", r.returncode)
        else:
            print("install.sh not found next to project root.")
    _pause()


def act_health(cfg):
    print("\nHealth Check")
    for comp, status, detail in health_check(cfg):
        icon = {"OK": "\u2714", "WARN": "\u26a0", "FAIL": "\u2716"}[status]
        print(f"  {icon} {status:<4} {comp:<15} {detail}")
    _pause()


def act_maintenance(cfg):
    print("\nMaintenance")
    print(" 1. Cleanup old reports/scans (apply retention policy)")
    print(" 2. Cleanup dry-run preview")
    c = input("> ").strip()
    if c in ("1", "2"):
        res = cleanup(cfg, dry_run=(c == "2"))
        print(f"{res['removed']} files affected.")
        for f in res["files"][:20]:
            print("   ", f)
    _pause()


def act_about(cfg):
    print(f"""
InfraScanner v{__version__} - Enterprise Network Discovery & Reporting Platform
Copyright (c) ZXSPRD.COM - Licensed under GNU GPL v3
Maintained by: zxsprd.com

Pipeline: Discovery -> Deep Scan -> Report Generation -> Distribution
(Email + Microsoft Teams lifecycle notifications)
All parameters live in config/config.yaml.""")
    _pause()


# ---------------------------------------------------------------- diagnostics
def act_diagnostics(cfg):
    """Show recently executed nmap commands and the last log entries."""
    import json as _json
    from .config_manager import ROOT
    print("\nDiagnostics")
    # 1. executed nmap commands
    lcp = cfg.dir("logs_dir") / "last_commands.log"
    if not lcp.exists():
        lcp = ROOT / "logs" / "last_commands.log"
    print("\n--- Executed Nmap commands (latest first) ---------------")
    if lcp.exists():
        lines = lcp.read_text(errors="replace").splitlines()[-20:]
        for line in reversed(lines):
            try:
                rec = _json.loads(line)
                rc = rec.get("rc")
                mark = "\u2714" if rc == 0 else f"\u2716 rc={rc}"
                print(f"[{rec.get('time','')}] {mark} ({rec.get('duration_sec',0)}s)")
                print(f"    {rec.get('cmd','')}")
                if rec.get("stderr_tail"):
                    print(f"    stderr: {rec['stderr_tail'][:200]}")
            except ValueError:
                print("   ", line)
    else:
        print("  (no commands recorded yet - logs/last_commands.log missing)")
    # 2. last 100 scanner log entries
    sl = cfg.dir("logs_dir") / "scanner.log"
    if not sl.exists():
        sl = ROOT / "logs" / "scanner.log"
    print("\n--- Last 100 scanner.log entries --------------------------")
    if sl.exists():
        for ln in sl.read_text(errors="replace").splitlines()[-100:]:
            print(ln)
    else:
        print("  (scanner.log not found)")
    # 3. current environment summary
    print("\n--- Environment -------------------------------------------")
    for comp, status, detail in health_check(cfg):
        print(f"  [{status:<4}] {comp:<15} {detail}")
    _pause()


# ---------------------------------------------------------------- history / browser
def act_send_historical(cfg):
    """Menu 17: pick a past scan date and email its reports (ZIP attached)."""
    from .reporter import list_report_history, load_inventory_for_date
    hist = [h for h in list_report_history(cfg) if h["files"]]
    if not hist:
        print("No historical reports found."); return _pause()
    print("\nHistorical Reports")
    for i, h in enumerate(hist[:30], 1):
        names = ", ".join(sorted({f.suffix.lstrip(".") for f in h["files"]}))
        print(f"  {i:>2}. {h['date']}  ({names})  scan_time={h['scan_time'] or 'n/a'}")
    sel = input("Number to email (0 cancel): ").strip()
    if not sel.isdigit() or not (1 <= int(sel) <= min(30, len(hist))):
        return _pause()
    entry = hist[int(sel) - 1]
    files = [f for f in entry["files"] if f.suffix.lower() != ".zip"]
    inv = load_inventory_for_date(cfg, entry["date"]) or {}
    summary = {"scan_time": inv.get("scan_time", entry["date"]),
               "profile": inv.get("profile", ""),
               "live_hosts": len(inv.get("hosts", [])),
               "open_ports": sum(len(h.get("ports", [])) for h in inv.get("hosts", [])),
               "networks": "", "total_ips": ""}
    zp = package_zip(cfg, files, date_override=entry["date"])
    attachments = [zp] if zp else files
    try:
        send_reports(cfg, attachments, summary,
                     subject_suffix=f"Historical {entry['date']}")
        notify_event(cfg, "report_sent", {
            "recipients": cfg.get("email.recipients", []),
            "attachments": len(attachments)})
        print(f"Historical report {entry['date']} emailed successfully.")
    except EmailError as exc:
        print(f"Email failed: {exc}")
    _pause()


def act_report_browser(cfg):
    """Menu 18: browse all generated reports; open one locally."""
    from .reporter import list_report_history
    hist = [h for h in list_report_history(cfg) if h["files"]]
    if not hist:
        print("No reports yet. Run a scan first."); return _pause()
    while True:
        print("\nReport Browser")
        idx_map = []
        n = 0
        for h in hist[:15]:
            print(f"  [{h['date']}]")
            for f in sorted(h["files"]):
                n += 1
                idx_map.append((n, f))
                kb = f.stat().st_size // 1024
                print(f"    {n:>2}. {f.name:<48} {kb} KB")
        c = input("Open number (Enter back, s=serve dir, q=quit): ").strip().lower()
        if c == "q":
            return
        if not c:
            return _pause()
        if c == "s":
            d = cfg.dir("reports_dir") / "latest"
            print(f"Serving {d} on http://<this-host>:8088  (Ctrl+C to stop)")
            subprocess.run([sys.executable, "-m", "http.server", "8088",
                            "--directory", str(d)])
            continue
        if c.isdigit() and 1 <= int(c) <= len(idx_map):
            p = idx_map[int(c) - 1][1]
            browser = os.environ.get("BROWSER")
            if browser:
                subprocess.Popen([browser, str(p)])
                print(f"Opened {p}")
            else:
                print(f"File: {p}\n(set $BROWSER to auto-open, or download/view manually)")
            _pause()


# ---------------------------------------------------------------- main menu
MENU_ITEMS = [
    ("1", "Full Infrastructure Scan", act_full_scan),
    ("2", "Scan Single VLAN", act_scan_vlan),
    ("3", "Scan Single IP", act_scan_ip),
    ("4", "Resume Interrupted Scan", act_resume),
    ("5", "Generate Reports (no scan)", act_generate_reports),
    ("6", "Send Latest Reports", act_send_reports),
    ("7", "View Last Report", act_view_last),
    ("8", "View Scan Statistics", lambda cfg: (act_statistics(cfg), _pause())),
    ("9", "View Change Report", act_change_report),
    ("10", "Configure", None),
    ("11", "Install / Verify Requirements", act_install),
    ("12", "Schedule Jobs", None),
    ("13", "Test Email", lambda cfg: (print("OK - test sent") if email_test(cfg) else print("Failed"), _pause())),
    ("14", "Test Teams Webhook", lambda cfg: (print("OK - card posted") if teams_test(cfg) else print("Failed (check URL/logs)"), _pause())),
    ("15", "Health Check", act_health),
    ("16", "Maintenance", act_maintenance),
    ("17", "Send Historical Reports", act_send_historical),
    ("18", "Report Browser", act_report_browser),
    ("19", "Diagnostics", act_diagnostics),
    ("20", "About", act_about),
]

STATUS_ICONS = {"OK": "\u2714", "WARN": "\u26a0", "FAIL": "\u2716"}


def _env_summary_lines(cfg):
    """Compact one-line-per-item environment strip shown inside the menu."""
    nets = cfg.get("networks", []) or []
    prof = cfg.get("scan.profile", "standard")
    recips = cfg.get("email.recipients", []) or []
    smtp = cfg.get("email.smtp_server", "") or "not set"
    teams_on = bool(cfg.get("teams.enabled", False)) and \
        "example.com" not in (cfg.get("teams.webhook_url", "") or "")
    inv = load_latest_inventory(cfg)
    last = inv.get("scan_time", "never") if inv else "never"
    live = len(inv.get("hosts", [])) if inv else 0
    ck = load_checkpoint(cfg)
    resume = f"  [RESUMABLE SCAN: {len(ck.get('hosts', []))} done]" if ck else ""
    priv = "root" if is_root() else "non-root (SYN/OS degraded)"
    return [
        f" Networks : {len(nets)} ({', '.join(n['name'] for n in nets[:4])}{'...' if len(nets) > 4 else ''})",
        f" Profile  : {prof}          Privileges : {priv}",
        f" SMTP     : {smtp}  Recipients: {len(recips)}  Teams: {'ON' if teams_on else 'OFF'}",
        f" Last scan: {last}  ({live} live hosts){resume}",
    ]


def interactive(cfg):
    while True:
        banner()
        print("-" * 60)
        for ln in _env_summary_lines(cfg):
            print(ln)
        print("-" * 60)
        items = list(MENU_ITEMS)
        half = (len(items) + 1) // 2
        left, right = items[:half], items[half:]
        for i in range(half):
            k1, l1 = left[i][0], left[i][1]
            if i < len(right):
                k2, l2 = right[i][0], right[i][1]
                print(f"  {k1:>2}. {l1:<28} {k2:>2}. {l2}")
            else:
                print(f"  {k1:>2}. {l1}")
        print("   0. Exit")
        print("=" * 60)
        c = input("Choice: ").strip()
        if c == "0":
            print("Goodbye."); return
        try:
            if c == "10":
                menu_configure(cfg)
            elif c == "12":
                menu_schedule(cfg)
            else:
                fn = dict((k, f) for k, l, f in MENU_ITEMS)[c]
                if fn:
                    fn(cfg)
        except KeyError:
            print("Invalid choice.")
        except (ScanError, EmailError, ConfigError) as exc:
            log.error("Action %s failed: %s", c, exc)
            notify_event(cfg, "error", {"phase": f"menu-{c}", "reason": str(exc),
                                        "hostname": os.uname().nodename})
            print(f"\n!! Error: {exc}")
            _pause()
        except KeyboardInterrupt:
            print("\nInterrupted. (Use menu 4 to resume if a scan was running.)")


# ---------------------------------------------------------------- CLI
def build_parser():
    ap = argparse.ArgumentParser(prog="infrascan",
                                 description="InfraScanner - ZXSPRD.COM")
    ap.add_argument("--non-interactive", action="store_true",
                    help="run one command then exit (for cron)")
    ap.add_argument("--config", default=None, help="path to config.yaml")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("menu", help="interactive menu (default)")
    sub.add_parser("full-scan", help="discovery + deep scan + reports + email")
    p = sub.add_parser("scan-vlan", help="scan one VLAN by name")
    p.add_argument("vlan")
    p = sub.add_parser("scan-ip", help="scan one IP/CIDR")
    p.add_argument("target")
    sub.add_parser("scan-all", help="discovery only across all VLANs")
    sub.add_parser("report", help="generate reports from latest scan")
    sub.add_parser("send", help="email latest reports")
    sub.add_parser("report-and-send", help="generate + email (cron friendly)")
    sub.add_parser("test-email")
    sub.add_parser("test-teams")
    sub.add_parser("health")
    sub.add_parser("stats")
    sub.add_parser("cleanup")
    sub.add_parser("diagnostics")
    sub.add_parser("history")
    sub.add_parser("about")
    return ap


def cli_main(argv=None):
    args = build_parser().parse_args(argv)
    cfg = Config(args.config) if args.config else Config()
    errs = cfg.validate()
    if errs:
        for e in errs:
            print(f"CONFIG ERROR: {e}", file=sys.stderr)
        if args.non_interactive:
            sys.exit(2)
    log_setup(cfg)
    cmd = args.cmd or ("menu" if not args.non_interactive else "full-scan")
    try:
        if cmd == "menu":
            if args.non_interactive:
                print("menu requires interactive terminal"); sys.exit(2)
            interactive(cfg)
        elif cmd == "full-scan":
            _scan_and_report(cfg, operator="cron")
        elif cmd == "scan-all":
            res = discover_all(cfg)
            print(json.dumps({k: len(v) for k, v in res.items()}, indent=2))
        elif cmd == "scan-vlan":
            net = next((n for n in cfg.get("networks", []) if n["name"] == args.vlan), None)
            if not net:
                print(f"Unknown VLAN {args.vlan}"); sys.exit(2)
            ips = discover_all_for(cfg, net["subnet"])
            _scan_and_report(cfg, {net["subnet"]: ips})
        elif cmd == "scan-ip":
            scan_single_target(cfg, args.target)
            generate_reports(cfg)
        elif cmd == "report":
            print(generate_reports(cfg))
        elif cmd == "send":
            act_send_reports_cli(cfg)
        elif cmd == "report-and-send":
            paths = generate_reports(cfg)
            zp = package_zip(cfg, paths)
            inv = load_latest_inventory(cfg) or {}
            send_reports(cfg, [zp] if zp else paths,
                         {"scan_time": inv.get("scan_time", ""),
                          "profile": inv.get("profile", ""),
                          "live_hosts": len(inv.get("hosts", [])),
                          "open_ports": sum(len(h.get("ports", []))
                                            for h in inv.get("hosts", []))})
            notify_event(cfg, "report_sent",
                         {"recipients": cfg.get("email.recipients", []),
                          "attachments": 1})
        elif cmd == "test-email":
            email_test(cfg); print("OK")
        elif cmd == "test-teams":
            print("OK" if teams_test(cfg) else "FAILED")
        elif cmd == "health":
            for row in health_check(cfg):
                print(*row)
        elif cmd == "stats":
            act_statistics_nopause(cfg)
        elif cmd == "cleanup":
            print(cleanup(cfg))
        elif cmd == "diagnostics":
            act_diagnostics(cfg)
        elif cmd == "history":
            from .reporter import list_report_history
            for h in list_report_history(cfg):
                print(h["date"], h["scan_time"], [f.name for f in h["files"]])
        elif cmd == "about":
            act_about(cfg)
    except (ScanError, EmailError) as exc:
        log.error("CLI %s failed: %s", cmd, exc)
        notify_event(cfg, "error", {"phase": cmd, "reason": str(exc),
                                    "hostname": os.uname().nodename})
        sys.exit(1)


def act_send_reports_cli(cfg):
    rdir = cfg.dir("reports_dir") / "latest"
    files = sorted([p for p in rdir.glob("*") if p.is_file()])
    if not files:
        print("No reports."); sys.exit(2)
    zp = package_zip(cfg, files)
    inv = load_latest_inventory(cfg) or {}
    send_reports(cfg, [zp] if zp else files,
                 {"scan_time": inv.get("scan_time", ""),
                  "live_hosts": len(inv.get("hosts", []))})


def act_statistics_nopause(cfg):
    inv = load_latest_inventory(cfg)
    if not inv:
        print("No data"); return
    from .scanner import Host
    st = compute_stats(cfg, [Host.from_dict(h) for h in inv["hosts"]])
    print(json.dumps(st, indent=2, default=str))


if __name__ == "__main__":
    cli_main()
