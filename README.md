```text
   ____       _                ____
  / ___|_ __ (_)_ __ __ _     / ___|  ___ __ _ _ __  _ __   ___ _ __
 | |   | '_ \| | '__/ _` |_  | |  _ / _ \ '_ \| '_ \| '_ \ / _ \ '__|
 | |___| | | | | | | (_| | | | |_| |  __/ |_) | |_) | |_) |  __/ |
  \____|_| |_|_|_|  \__,_|_|  \____|\___| .__/| .__/| .__/ \___|_|
                                        |_|   |_|   |_|
```

# InfraScanner

**Enterprise Network Discovery & Reporting Platform**

* Copyright (c) ZXSPRD.COM — License: GNU GPL v3 — Maintained by: [zxsprd.com](https://zxsprd.com)
* Version: **1.0.0** · Classification-friendly reports · Distribution-agnostic Linux

InfraScanner discovers assets across your VLANs, performs configurable deep scans of live hosts
(ports, services, OS, SSL/TLS certificates, HTTP banners, SMB, databases), detects infrastructure
**changes between scans**, scores findings with **severity levels**, and delivers branded
**HTML / CSV / PDF / JSON** reports (packaged in a ZIP) via **SMTP email** and **Microsoft Teams**
lifecycle notifications. Everything is driven from one interactive menu or a cron-friendly CLI,
and every parameter lives in a single `config/config.yaml`.

---

## Table of Contents

1. [Features](#features)
2. [Architecture & Pipeline](#architecture--pipeline)
3. [Quick Start](#quick-start)
4. [Installation per Distribution](#installation-per-distribution)
5. [Directory Structure](#directory-structure)
6. [Configuration (`config/config.yaml`)](#configuration-configconfigyaml)
7. [The Menu](#the-menu)
8. [CLI Usage (non-interactive / cron)](#cli-usage-noninteractive--cron)
9. [Email Setup (SMTP + Receipt Emails)](#email-setup-smtp--receipt-emails)
10. [Microsoft Teams Notifications](#microsoft-teams-notifications)
11. [Scan Profiles & Performance Tuning](#scan-profiles--performance-tuning)
12. [Change Detection & Severity Levels](#change-detection--severity-levels)
13. [Reports](#reports)
14. [Scheduling](#scheduling)
15. [Retention & Maintenance](#retention--maintenance)
16. [Health Check](#health-check)
17. [Backup, Restore & Defaults](#backup-restore--defaults)
18. [Troubleshooting](#troubleshooting)
19. [Contributing](#contributing)
20. [License & Branding](#license--branding)

---

## Features

| Area | What you get |
|---|---|
| **Discovery** | Fast ping sweep of all configured VLANs/subnets, exclusion lists honored |
| **Deep scan** | Profiles: Quick / Standard (default, top-1000) / Deep (full TCP) / Extreme (+UDP top-100); `-sV -sC -O` on live hosts only |
| **Enumeration** | SSL cert subject/issuer/expiry/TLS version, HTTP title/server/headers, SMB version & signing, DB detection (Oracle, MSSQL, MySQL, PostgreSQL, MongoDB) |
| **Change detection** | NEW HOST / REMOVED HOST / NEW PORT / CLOSED PORT / OS CHANGED / HOSTNAME CHANGED + dedicated change report |
| **Severity scoring** | CRITICAL / HIGH / MEDIUM / LOW / INFO rules, fully editable in YAML |
| **Reports** | Executive dashboard HTML, asset-inventory CSV, split **Executive_Report.pdf** (1–2 pages) & **Technical_Report.pdf**, machine-readable JSON, ZIP bundle for email |
| **Notifications** | SMTP email (STARTTLS/SSL/auth) with ZIP attachment; Teams lifecycle cards: 🚀 started, ✅ completed (with full statistics), 🔔 changes detected, 📧 report sent, 🚨 failed |
| **Operations** | Resume interrupted scans, maintenance-window protection, host/subnet exclusions, retention cleanup, health check, config backup/import/export, restore-default-scan-settings |
| **Portability** | Runs on Oracle Linux, RHEL, Rocky, AlmaLinux, Ubuntu, Debian, Kali (dnf/yum/apt auto-detected). Root recommended; degrades gracefully without it |

---

## Architecture & Pipeline

Four stages, each independently runnable (re-report or re-email without rescanning):

```text
Discovery ──► Deep Scan ──► Report Generation ──► Distribution
 (ping sweep)  (profiles)    HTML/CSV/PDF/JSON      Email (ZIP) + Teams
      │            │              │                     │
 scans/raw     scans/processed  reports/html|csv|pdf   logs/email.log
 hosts.txt      *.xml/.json     reports/latest|archive  Teams webhook
```

* Stage results are persisted, so **"Generate Reports"** rebuilds output from the last raw scan.
* A scan **state file** enables **"Resume Interrupted Scan"** (e.g., stopped at host 45/66).
* Every run archives inventory snapshots for change detection.

---

## Quick Start

```bash
git clone https://github.com/zxsprd/InfraScanner.git
cd InfraScanner
sudo ./install.sh          # detects dnf/yum/apt, installs nmap + Python deps
sudo ./infrascan           # opens the interactive menu
```

First run checklist:

1. Menu → **10. Configure → 3. SMTP Settings** — server, port, username, password, sender
2. Menu → **10. Configure → 4. Receipt Emails** — add/remove/modify report recipients
3. Menu → **10. Configure → 5. Teams Webhook Settings** — paste your Workflows webhook URL
4. Menu → **10. Configure → 1. Network Ranges** — replace the two example VLANs with yours
5. Menu → **13. Test Email** and **14. Test Teams Webhook**
6. Menu → **15. Health Check** — everything should be green
7. Menu → **1. Full Infrastructure Scan**

No-argument launch shows the menu; any subcommand runs non-interactively (see CLI section).

---

## Installation per Distribution

`install.sh` handles all of these automatically; manual equivalents:

| Family | Distributions | Packages installed |
|---|---|---|
| RPM | Oracle Linux 9/10, RHEL, Rocky, AlmaLinux | `nmap`, `python3-pip` (via `dnf`/`yum`) |
| DEB | Ubuntu, Debian, Kali | `nmap`, `python3-pip` (via `apt-get`) |

Then Python dependencies (from `requirements.txt`):

```bash
python3 -m pip install -r requirements.txt
```

Requirements: Python ≥ 3.9 (3.11+ recommended), Nmap ≥ 7.x. PDF generation uses **fpdf2**
(pure Python — no wkhtmltopdf/WeasyPrint system libraries needed). Optional: masscan for
faster discovery (auto-detected, not required).

Uninstall: `sudo ./uninstall.sh` (removes cron entries created by the scheduler; leaves your
data unless you pass `--purge`).

---

## Directory Structure

```text
InfraScanner/
├── infrascan               # launcher (menu + CLI)
├── install.sh / uninstall.sh
├── config/
│   ├── config.yaml         # ← ALL settings live here (single source of truth)
│   └── config.defaults.yaml# factory defaults (used by "Restore Default Scan Settings")
├── src/infrascan/          # scanner, enumerator, reporter, mailer, notifier,
│                           # change_detect, scheduler, maintenance, menu, ...
├── templates/              # HTML report template
├── scans/{raw,processed,archive}
├── reports/{html,csv,pdf,json,latest,archive}
├── logs/                   # scanner.log, email.log, teams.log, cron.log (rotating)
├── docs/ · examples/ · tests/
└── README.md LICENSE CHANGELOG.md CONTRIBUTING.md SECURITY.md
```

---

## Configuration (`config/config.yaml`)

One file controls everything. Top-level sections:

```yaml
project:                    # branding / context (no code changes needed)
  organization: "ZXSPRD.COM"
  environment: "Production"
  scanner_name: "InfraScanner"
  timezone: "Asia/Dubai"

reporting:                  # report header branding
  organization_name: "My Company"
  report_author: "InfraScanner"
  classification: "Internal"

networks:                   # example VLANs — edit via Configure menu
  - name: MGMT
    subnet: 192.168.4.0/24
  - name: DMZ
    subnet: 192.168.1.0/24

exclude:
  hosts:   []               # e.g. 192.168.4.1 (gateways/printers…)
  subnets: []               # e.g. 192.168.99.0/24

scan:
  profile: standard         # quick | standard | deep | extreme
  timing: normal            # paranoid|sneaky|polite|normal|aggressive|insane
  maintenance_window:
    enabled: false
    start: "22:00"
    end:   "06:00"

scan_profiles:              # what each profile actually runs
  quick:    { top_ports: 100 }
  standard: { top_ports: 1000, version_detection: true, os_detection: true, nse_default: true }
  deep:     { full_ports: true, os_detection: true, version_detection: true, nse_default: true }
  extreme:  { full_ports: true, udp_top100: true, version_intensity: 9, timing: aggressive }

performance:                # threads / packet rate / timeouts / retries / parallel jobs

email:                      # SMTP connection settings
  enabled: true
  smtp_server: "smtp.example.com"
  smtp_port: 587            # 465 = implicit SSL, 587 = STARTTLS
  use_tls: true
  username: "scanner@example.com"
  password: "CHANGE_ME"
  sender: "InfraScanner <scanner@example.com>"
  recipients:               # ← managed by "Receipt Emails" menu item
    - "abc@def.com"
  subject_prefix: "[Infrastructure Scan]"
  alert_subject_prefix: "[ALERT]"
  critical_severity_alert: true

teams:
  enabled: true
  webhook_url: "https://teams.webhook.example.com/hook"

notifications:              # which lifecycle events are sent
severity_rules:             # CRITICAL..INFO definitions (editable)
retention:                  # report_days / scan_days / monthly_keep
logging:                    # level, rotation
paths:                      # data directories (if relocated)
```

Rules of thumb:

* Never hand-edit passwords into shared copies — use **Configure → SMTP Settings** (stored locally)
  and keep the repo's `config.defaults.yaml` clean.
* **Configure → 11/12 Export/Import Config** migrates a whole setup to another scanner host.
* **Configure → 10 Restore Default Scan Settings** reverts only scan/performance knobs to
  factory values (your networks, email and Teams settings are preserved). Previous config is
  auto-backed-up first.

---

## The Menu

```text
============================================================
   1. Full Infrastructure Scan        10. Configure
   2. Scan Single VLAN                11. Install / Verify Requirements
   3. Scan Single IP                  12. Schedule Jobs
   4. Resume Interrupted Scan         13. Test Email
   5. Generate Reports (no scan)      14. Test Teams Webhook
   6. Send Latest Reports             15. Health Check
   7. View Last Report                16. Maintenance
   8. View Scan Statistics            17. About
   9. View Change Report               0. Exit
============================================================
```

**Configure submenu** (everything in one place):

```text
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
11. Export Config (backup copy)
12. Import Config (restore from backup)
```

Menu highlights:

* **2. Scan Single VLAN** — pick from your named VLAN list, scans only that subnet.
* **3. Scan Single IP** — investigation mode: ports + services + OS for one target.
* **5. Generate Reports** — rebuilds HTML/CSV/PDF/JSON from the latest stored scan; ideal when
  iterating on report format. No network traffic.
* **8. View Scan Statistics** — hosts/VLAN, OS distribution, top ports/services.
* **9. View Change Report** — diff vs previous scan (new/removed hosts, opened/closed ports).

---

## CLI Usage (non-interactive / cron)

```bash
./infrascan full-scan                 # discovery → deep scan → reports → email + Teams
./infrascan scan-vlan MGMT
./infrascan scan-ip 192.168.5.10
./infrascan scan-all                  # discovery only (fast daily job)
./infrascan report                    # regenerate reports from last scan
./infrascan send                      # email latest reports
./infrascan report-and-send           # cron favorite: generate + email
./infrascan test-email
./infrascan test-teams
./infrascan health
./infrascan stats
./infrascan cleanup
./infrascan about
./infrascan --config /path/to/other.yaml full-scan
```

All commands exit non-zero on failure and log to `logs/`.

---

## Email Setup (SMTP + Receipt Emails)

Two separate configuration areas — manage them independently:

### SMTP Settings (Configure → 3)

Connection details only: server, port, STARTTLS/SSL, username, password, sender (From),
subject prefix, enable/disable. Port `465` uses implicit SSL; `587` uses STARTTLS.
Verify anytime with main-menu **13. Test Email**.

### Receipt Emails (Configure → 4)

The recipient list for reports. Add / remove / modify addresses interactively
(`+` add, number deletes, `e<n>` edits an entry). Entries are trimmed and de-duplicated on
save. Stored as `email.recipients` in `config.yaml`:

```yaml
email:
  recipients:
    - "abc@def.com"
```

### Delivery behavior

* After a scan, reports are bundled into **one ZIP** (`Infrastructure_Report_YYYYMMDD.zip`)
  to stay under attachment-size limits, plus inline summary body.
* Subject: `[Infrastructure Scan] 66 Hosts Discovered | 2026-10-27`
* If CRITICAL findings exist: `[ALERT] Infrastructure Scan Found Critical Exposure`
  (toggle via `email.critical_severity_alert`).
* Every send attempt is logged to `logs/email.log`.

---

## Microsoft Teams Notifications

Create a **Workflows** webhook (Power Automate → *Post to a channel when a webhook request is
received*) and paste the URL into **Configure → 5** (`teams.webhook_url`).

Lifecycle cards sent automatically (`notifications:` section toggles each event):

| Event | Card content |
|---|---|
| 🚀 Scan Started | timestamp, networks, IPs, operator |
| ✅ Scan Complete | duration, networks/IPs scanned, live hosts, new/removed hosts, open ports, CRITICAL/HIGH counts, formats generated |
| 🔔 Changes Detected | new/removed hosts, new/closed ports, link to change report |
| 📧 Report Sent | recipients, attachments, status |
| 🚨 Failure | phase, reason, host |

Test with main-menu **14. Test Teams Webhook**. Slack/Telegram/Discord plug into the same
notifier interface in later releases (v1.1.0 roadmap).

---

## Scan Profiles & Performance Tuning

| Profile | Ports | Detections | Use case |
|---|---|---|---|
| quick | top 100 | version | rapid checks |
| **standard** (default) | top 1000 | version + scripts | daily/weekly routine |
| deep | all 65535 TCP | + OS detection | weekly inventory |
| extreme | all TCP + UDP top-100 | + full NSE, SSL/HTTP/SMB/DB enum | investigations |

> ⚠️ Do **not** run deep/extreme against every host every day — 100 hosts × 65535 ports turns
> into many hours of traffic. Recommended cadence: daily discovery/standard, weekly deep.

Performance keys (`performance:`): max threads/parallelism, packet rate, host timeout,
retries, min-RTT — mapped onto Nmap timing templates (`scan.timing`: paranoid → insane).
**Maintenance window** (`scan.maintenance_window`) blocks out-of-window deep scans entirely —
prevents accidental daytime traffic.

Privileges: root (or `sudo`) is **recommended** and required for SYN features, OS detection and
some NSE scripts; InfraScanner detects privileges and degrades gracefully instead of refusing
to run.

---

## Change Detection & Severity Levels

Each completed scan stores an inventory snapshot; the next scan is compared against it:

```text
NEW HOST · REMOVED HOST · NEW PORT · CLOSED PORT · OS CHANGED · HOSTNAME CHANGED
```

Results appear in `change_report.html`, in the email summary, and as a Teams 🔔 card.

Findings are scored with editable rules (`severity_rules:`):

| Level | Example rule |
|---|---|
| CRITICAL | RDP exposed in DMZ |
| HIGH | SMBv1 detected, expired SSL certificate |
| MEDIUM | Unencrypted management service |
| LOW | HTTP (non-TLS) detected |
| INFO | New Linux host discovered |

---

## Reports

Generated per scan into `reports/` (copies promoted to `reports/latest/`, older archived):

| Format | Audience | Content |
|---|---|---|
| **HTML** | Security team | Executive dashboard + per-host technical detail, severity badges |
| **CSV** | Excel analysts | One row per open port: host, IP, VLAN, OS, port, service, product, version |
| **PDF (×2)** | Management / Engineers | `Executive_Report.pdf` (1–2 pages summary) and `Technical_Report.pdf` (full inventory) |
| **JSON** | Integrations | Machine-readable inventory + findings (future dashboards/API) |
| **ZIP** | Email | All of the above bundled for a single attachment |

Common sections: scan date/timezone, VLAN count, IPs scanned, live hosts, open ports, hosts per
VLAN, OS distribution, top ports/services, security findings by severity, change summary. Your
`reporting.organization_name` and `classification` print in every header/footer.

---

## Scheduling

Main menu **12. Schedule Jobs**: view / add / modify / remove / enable / disable crontab
entries (root's crontab). Templates provided:

| Job | Schedule | Command |
|---|---|---|
| Daily discovery | `0 1 * * *` | `./infrascan scan-all` |
| Weekly deep scan | `0 2 * * 0` | `./infrascan full-scan` |
| Monthly management report | `0 8 1 * *` | `./infrascan report-and-send` |

Cron output is appended to `logs/cron.log`.

---

## Retention & Maintenance

Menu **16. Maintenance** (also `./infrascan cleanup`, and automatic after each scan):

* Raw scans & reports kept for `retention.scan_days` / `retention.report_days` (default 90).
* Monthly archives kept for `retention.monthly_keep` months (default 12).
* Older data deleted; monthly rollups moved to `*/archive/`.

---

## Health Check

Menu **15. Health Check** validates the whole stack before you trust a scan:

```text
Python OK · Nmap OK · masscan optional · fpdf2 OK · SMTP OK (auth probe) ·
Teams OK (test card) · Disk Space OK · Cron OK · Writable dirs OK · Root status
```

---

## Backup, Restore & Defaults

| Need | Where |
|---|---|
| Back up entire configuration | Configure → 11 Export Config (timestamped copy in `backups/`) |
| Move setup to another host | Copy repo + `config/config.yaml`, run `install.sh` |
| Restore a previous config | Configure → 12 Import Config (current file auto-backed-up first) |
| Undo bad scan tuning | Configure → 10 **Restore Default Scan Settings** (networks/email/Teams untouched) |
| Factory reset of everything | Re-copy `config/config.defaults.yaml` over `config/config.yaml` |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Nmap execution failed` during deep scan | Re-run with root/sudo; check `logs/scanner.log`; lower profile or packet rate |
| No email received | `Test Email`; verify port 465 vs 587/TLS; app-password/OAuth notes for O365/Gmail; check `logs/email.log` |
| Teams card not delivered | Webhook must be a current **Workflows** URL (legacy Connector deprecated); test via menu 14 |
| Scan takes forever | You're on `deep`/`extreme` — switch to `standard`; enable maintenance window; raise `discovery_parallelism` |
| PDF missing | `pip install fpdf2` (install.sh does this); HTML/CSV still generated regardless |
| False "new host" alerts | DHCP devices — expected; excluded ranges via Configure → 2 |
| Permission errors writing reports/logs | Run as root or fix ownership of `reports/`, `scans/`, `logs/` |
| Interrupted/power loss mid-scan | Menu → 4 Resume Interrupted Scan (skips already-completed hosts) |
| `nmap -sn` shows hosts up but InfraScanner reports **0 live hosts** | Enable **Configure → 13 Verbose Debug Mode**, re-run discovery, then inspect `logs/scanner.log`: it logs the exact nmap command, its stdout/stderr, and counters (`raw_hosts=N up_hosts=M parsed_live=K`). Raw XML + GNMAP files are saved under `scans/raw/` for comparison. If `up_hosts>0` but `parsed_live=0`, check exclusions (Configure → 2). Deep scans now always run with `-Pn` against discovered hosts, so firewalled ping responses can no longer hide live systems. |

Logs: `logs/scanner.log` (pipeline), `logs/email.log`, `logs/teams.log`, `logs/cron.log` —
all rotating, level set by `logging.level`. Set `logging.verbose_debug: true` in
`config/config.yaml` (or Configure → 13) to log every nmap command line, its full
stdout/stderr, raw-vs-parsed host/port counters, and keep all raw `.xml`/`.gnmap`
files in `scans/raw/` for parser post-mortems.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Branch → PR against `main`; run `pytest tests/`
before submitting. Please don't commit real subnets, SMTP credentials, or webhook URLs —
keep examples generic (`192.168.x.0/24`, `abc@def.com`, `teams.webhook.example.com`).

Security issues: report privately per [SECURITY.md](SECURITY.md).

### Release roadmap

| Version | Highlights |
|---|---|
| **v1.0.0** | This release: scans, profiles, change detection, severities, 4 report formats, ZIP email, Teams lifecycle cards, scheduler, resume, health check, retention |
| v1.1.0 | Telegram + Slack notifiers, REST API |
| v1.2.0 | Web dashboard, historical trends, host lifecycle tracking |
| v2.0.0 | OpenVAS integration, CVE correlation, vulnerability reporting |

---

## License & Branding

GNU GPL v3 — see [LICENSE](LICENSE).

```text
InfraScanner — Enterprise Network Discovery & Reporting Platform
Copyright (c) ZXSPRD.COM
Maintained by zxsprd.com
```

Responsible use: only scan networks you own or are explicitly authorized to assess.
