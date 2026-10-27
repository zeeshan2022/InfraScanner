# Changelog

All notable changes to InfraScanner are documented here.
Project format follows Keep a Changelog; versioning follows SemVer.
Copyright (c) ZXSPRD.COM — GPL v3.

## [Unreleased]

### Fixed
- **Discovery engine reported 0 live hosts** even when `nmap -sn` showed hosts
  up. Root causes addressed:
  - Discovery sweep now includes `--open` so hosts with only *filtered* ports
    are still counted as up, and uses explicit TCP SYN probe ports.
  - Invalid nmap option spellings corrected (`--host_timeout`,
    `--max_parallelism`, `--script_timeout`, `--min_rt_timeout` → hyphen form).
  - Deep scans always run with `-Pn` against already-discovered hosts, so a
    blocked ping response can no longer make a live host look dead
    (fixes single-IP scans returning `live=0 open_ports=0`).
  - XML parser hardened: handles multi-host files, logs parse errors instead
    of silently returning nothing, counts raw vs parsed hosts/ports.
  - Added GNMAP (`-oG`) cross-validation parser as a fallback source of truth.
- `masscan` health-check entry renamed from capitalized `Masscan` to the real
  binary name `masscan`; now shows detected version when installed.

### Added
- **Verbose debug mode** (`logging.verbose_debug: true` or Configure → 13):
  logs the exact nmap command line, full stdout/stderr, exit code and runtime
  for every scan invocation, plus parser counters such as
  `raw_hosts=N up_hosts=M parsed_live=K` and `open_ports_parsed=K`.
- Raw scan evidence retained in `scans/raw/`: discovery `.xml` + `.gnmap` and
  per-host deep-scan `.xml` + `.gnmap` files are no longer deleted, enabling
  post-mortem debugging of any "missing host" report.
- Single-IP workflow now emits Teams `scan_started` / `scan_completed` events
  and performs an automatic `/32` discovery cross-check if the direct scan
  parses zero results.
- Troubleshooting table entry for the 0-live-hosts symptom with step-by-step
  debug procedure (README).

## [1.0.0]
- Initial production release: menu-driven platform with full/VLAN/single-IP
  scans, four scan profiles (quick/standard/deep/extreme), resume support,
  exclusions, maintenance-window guard, HTML/CSV/PDF/JSON reports, executive +
  technical PDFs, ZIP packaging, SMTP email, Teams lifecycle notifications,
  asset change detection, severity-rated findings, statistics dashboard,
  cron schedule management, backup/restore, health check, retention cleanup,
  separate SMTP Settings and Receipt Emails configuration editors.
