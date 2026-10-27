"""Email engine: SMTP with STARTTLS/auth, ZIP or multi-attachment delivery."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from .logger import get

log = get("email")


class EmailError(Exception):
    pass


def _connect(cfg):
    server = cfg.get("email.smtp_server", "")
    port = int(cfg.get("email.smtp_port", 587))
    use_tls = bool(cfg.get("email.use_tls", True))
    user = cfg.get("email.username", "")
    pw = cfg.get("email.password", "")
    if not server:
        raise EmailError("email.smtp_server not configured")
    ctx = ssl.create_default_context()
    if port == 465:
        srv = smtplib.SMTP_SSL(server, port, context=ctx, timeout=30)
    else:
        srv = smtplib.SMTP(server, port, timeout=30)
        if use_tls:
            srv.starttls(context=ctx)
    if user:
        try:
            srv.login(user, pw)
        except smtplib.SMTPException as exc:
            srv.quit()
            raise EmailError(f"SMTP login failed: {exc}") from exc
    return srv


def send_reports(cfg, attachments: list[Path], summary: dict,
                 critical: bool = False) -> bool:
    """Send report attachments. Returns True on success."""
    if not cfg.get("email.enabled", True):
        log.info("Email disabled in config; skipping send.")
        return False
    recipients = cfg.get("email.recipients", []) or []
    if not recipients:
        raise EmailError("No recipients configured (email.recipients)")
    hosts = summary.get("live_hosts", "?")
    date = summary.get("scan_time", "")[:10]
    prefix = (cfg.get("email.alert_subject_prefix", "[ALERT]") if critical
              else cfg.get("email.subject_prefix", "[Infrastructure Scan]"))
    subject = f"{prefix} {hosts} Hosts Discovered | {date}"
    if critical:
        subject = f"{prefix} Infrastructure Scan Found Critical Exposure - {date}"

    body_lines = [
        "InfraScanner infrastructure scan summary",
        "=========================================",
        f"Scan time       : {summary.get('scan_time', '')}",
        f"Profile         : {summary.get('profile', '')}",
        f"Networks        : {summary.get('networks', '')}",
        f"IPs scanned     : {summary.get('total_ips', '')}",
        f"Live hosts      : {summary.get('live_hosts', '')}",
        f"Open ports      : {summary.get('open_ports', '')}",
        f"Findings CRIT/HIGH : {summary.get('critical_findings', 0)} / "
        f"{summary.get('high_findings', 0)}",
        "",
        "Attachments: " + ", ".join(p.name for p in attachments),
        "",
        "-- InfraScanner | Copyright (c) ZXSPRD.COM | GNU GPL v3",
    ]
    msg = EmailMessage()
    msg["From"] = cfg.get("email.sender", "InfraScanner <noreply@localhost>")
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content("\n".join(body_lines))
    for p in attachments:
        if not p.exists():
            continue
        maint, sub = _mime(p)
        msg.add_attachment(p.read_bytes(), maintype=maint, subtype=sub,
                           filename=p.name)
    try:
        srv = _connect(cfg)
        srv.send_message(msg)
        srv.quit()
        log.info("Email sent to %s (%d attachments)", recipients, len(attachments))
        return True
    except (smtplib.SMTPException, OSError) as exc:
        log.error("Email failed: %s", exc)
        raise EmailError(str(exc)) from exc


def send_test(cfg) -> bool:
    """Menu 13 - Test Email."""
    recipients = cfg.get("email.recipients", []) or []
    if not recipients:
        raise EmailError("No recipients configured")
    msg = EmailMessage()
    msg["From"] = cfg.get("email.sender", "InfraScanner <noreply@localhost>")
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = "InfraScanner Test Message"
    msg.set_content("Email configuration working.\n\n-- InfraScanner (ZXSPRD.COM)")
    srv = _connect(cfg)
    srv.send_message(msg)
    srv.quit()
    log.info("Test email sent to %s", recipients)
    return True


def _mime(p: Path):
    ext = p.suffix.lower()
    return {
        ".html": ("text", "html"), ".csv": ("text", "csv"),
        ".json": ("application", "json"), ".pdf": ("application", "pdf"),
        ".zip": ("application", "zip"), ".txt": ("text", "plain"),
    }.get(ext, ("application", "octet-stream"))
