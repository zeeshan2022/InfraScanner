"""Notification engine: Microsoft Teams message cards (webhook).

Pluggable design - Slack/Telegram stubs land in v1.1 behind the same
notify_event() interface. Lifecycle events: scan_started, scan_completed,
report_sent, error, changes_detected.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from datetime import datetime

from .logger import get

log = get("teams")


def _post(url: str, payload: dict) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            ok = resp.status < 400
            if not ok:
                log.error("Teams webhook HTTP %s", resp.status)
            return ok
    except (urllib.error.URLError, OSError) as exc:
        log.error("Teams webhook failed: %s", exc)
        return False


def _card(title: str, color: str, text_md: str) -> dict:
    """Adaptive-card-ish MessageCard payload (works with Teams Workflows)."""
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "title": title,
        "text": text_md,
    }


def notify_event(cfg, event: str, data: dict) -> bool:
    """Send a lifecycle notification if enabled for this event."""
    if not cfg.get("teams.enabled", False):
        return False
    events = cfg.get("teams.events", []) or []
    if event not in events:
        return False
    url = cfg.get("teams.webhook_url", "")
    if not url or "webhook.example.com" in url:
        log.warning("Teams webhook not configured (placeholder URL); event '%s' skipped", event)
        return False
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    org = cfg.get("reporting.organization_name", "My Company")

    if event == "scan_started":
        title, color = "\U0001F680 Infrastructure Scan Started", "0078D4"
        text = (f"**Started:** {now}\n\n"
                f"**Organization:** {org}\n"
                f"**Networks:** {data.get('networks')}\n"
                f"**IPs to check:** {data.get('ips')}\n"
                f"**Profile:** {data.get('profile')}\n"
                f"**Operator:** {data.get('operator')}")
    elif event == "scan_completed":
        ch = data.get("changes", {}) or {}
        title, color = "\u2705 Scan Completed", "107C10"
        text = (f"**Duration:** {data.get('duration_sec', 0)}s\n\n"
                f"**Networks:** {data.get('networks')}\n"
                f"**IPs Scanned:** {data.get('total_ips')}\n"
                f"**Live Hosts:** {data.get('live_hosts')}\n"
                f"**New Hosts:** {len(ch.get('new_hosts', []))}\n"
                f"**Removed Hosts:** {len(ch.get('removed_hosts', []))}\n"
                f"**New Ports:** {len(ch.get('new_ports', []))}\n"
                f"**Closed Ports:** {len(ch.get('closed_ports', []))}\n"
                f"**Open Ports Total:** {data.get('open_ports')}\n"
                f"**Critical Findings:** {data.get('critical_findings', 'pending report')}\n"
                f"**High Findings:** {data.get('high_findings', 'pending report')}\n\n"
                f"Reports generated: HTML / CSV / PDF / JSON")
    elif event == "report_sent":
        title, color = "\U0001F4E7 Report Delivered", "107C10"
        text = (f"**Recipients:** {', '.join(data.get('recipients', []))}\n"
                f"**Attachments:** {data.get('attachments')}\n"
                f"**Status:** Success")
    elif event == "changes_detected":
        title, color = "\U0001F514 Infrastructure Changes Detected", "FFA500"
        text = (f"**New Hosts:** {data.get('new_hosts', 0)}\n"
                f"**Removed Hosts:** {data.get('removed_hosts', 0)}\n"
                f"**New Open Ports:** {data.get('new_ports', 0)}\n"
                f"**Closed Ports:** {data.get('closed_ports', 0)}\n\n"
                f"View Report: reports/latest/change_report.html")
    elif event == "error":
        title, color = "\U0001F6A8 Scan Failed", "D13438"
        text = (f"**Phase:** {data.get('phase', 'unknown')}\n"
                f"**Reason:** {data.get('reason', '')}\n"
                f"**Host:** {data.get('hostname', '')}\n**Time:** {now}")
    else:
        return False

    ok = _post(url, _card(title, color, text))
    log.info("Teams event '%s' delivered=%s", event, ok)
    return ok


def send_test(cfg) -> bool:
    """Menu 14 - Test Teams Webhook."""
    url = cfg.get("teams.webhook_url", "")
    if not url:
        log.error("No webhook configured")
        return False
    return _post(url, _card("\U0001F9ED InfraScanner Test Message", "0078D4",
                            "Teams webhook configuration working."))
