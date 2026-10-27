"""Configuration manager for InfraScanner.

Everything the platform needs lives in a single YAML file: config/config.yaml
Provides load/save, dot-path get/set, backup/restore, and factory defaults
(Restore Default Scan Settings).
"""

from __future__ import annotations

import copy
import os
import shutil
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise SystemExit("PyYAML is required. Run ./install.sh or menu 11.") from exc

# Project root = directory containing config/, src/, etc.
ROOT = Path(os.environ.get("INFRASCAN_ROOT") or Path(__file__).resolve().parents[2])
CONFIG_DIR = ROOT / "config"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
DEFAULTS_FILE = CONFIG_DIR / "config.defaults.yaml"

# Default scan settings restored by "Restore Default Scan Settings"
DEFAULT_SCAN_SECTION = {
    "scan": {
        "profile": "standard",
        "maintenance_window": {"enabled": False, "start": "22:00", "end": "06:00"},
        "resume_enabled": True,
    },
    "scan_profiles": {
        "quick": {"top_ports": 100, "full_ports": False, "udp_top100": False,
                  "os_detection": False, "version_detection": True,
                  "nse_default": False, "timing": "aggressive"},
        "standard": {"top_ports": 1000, "full_ports": False, "udp_top100": False,
                     "os_detection": True, "version_detection": True,
                     "nse_default": True, "timing": "normal"},
        "deep": {"top_ports": 1000, "full_ports": True, "udp_top100": False,
                 "os_detection": True, "version_detection": True,
                 "nse_default": True, "timing": "normal"},
        "extreme": {"top_ports": 1000, "full_ports": True, "udp_top100": True,
                    "os_detection": True, "version_detection": True,
                    "nse_default": True, "version_intensity": 9,
                    "timing": "aggressive"},
    },
    "performance": {
        "max_parallel_hosts": 8, "packet_rate": "", "host_timeout": "15m",
        "script_timeout": "60s", "retries": 1, "min_rtt_timeout": "200ms",
        "discovery_parallelism": "300",
    },
}


class ConfigError(Exception):
    pass


def _deep_merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Config:
    """Loads config.yaml with sensible merge-on-defaults behaviour."""

    def __init__(self, path: Path | str = CONFIG_FILE):
        self.path = Path(path)
        self.data: dict = {}
        self.reload()

    # ------------------------------------------------------------------ io
    def reload(self) -> None:
        if not self.path.exists():
            raise ConfigError(f"Config file missing: {self.path}. "
                              f"Run install.sh or restore defaults.")
        with open(self.path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        defaults = {}
        if DEFAULTS_FILE.exists():
            with open(DEFAULTS_FILE, encoding="utf-8") as fh:
                defaults = yaml.safe_load(fh) or {}
        self.data = _deep_merge(defaults, loaded)

    def save(self) -> None:
        tmp = self.path.with_suffix(".yaml.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            yaml.safe_dump(self.data, fh, sort_keys=False, default_flow_style=False)
        os.replace(tmp, self.path)  # atomic write = rollback protection

    # ------------------------------------------------------------- accessors
    def get(self, dotted_key: str, default=None):
        node = self.data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted_key: str, value) -> None:
        parts = dotted_key.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    # ------------------------------------------------------------ validation
    def validate(self) -> list[str]:
        errs = []
        nets = self.get("networks", [])
        if not isinstance(nets, list) or not nets:
            errs.append("networks: must be a non-empty list of {name, subnet}")
        else:
            import ipaddress
            for n in nets:
                try:
                    ipaddress.ip_network(str(n.get("subnet", "")), strict=False)
                except ValueError:
                    errs.append(f"networks: invalid subnet in {n}")
        prof = self.get("scan.profile", "standard")
        if prof not in ("quick", "standard", "deep", "extreme"):
            errs.append(f"scan.profile '{prof}' unknown")
        port = self.get("email.smtp_port", 587)
        if not isinstance(port, int) or not (0 < port < 65536):
            errs.append("email.smtp_port invalid")
        return errs

    # ------------------------------------------------------------- backups
    def backup(self, dest_dir: Path | None = None) -> Path:
        dest_dir = dest_dir or (ROOT / "backups")
        dest_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = dest_dir / f"config_{stamp}.yaml"
        shutil.copy2(self.path, dest)
        return dest

    def restore_from(self, src: Path | str) -> None:
        src = Path(src)
        if not src.exists():
            raise ConfigError(f"Backup not found: {src}")
        with open(src, encoding="utf-8") as fh:
            yaml.safe_load(fh)  # verify parseable BEFORE overwriting
        self.backup()            # safety copy of current state
        shutil.copy2(src, self.path)
        self.reload()

    # ----------------------------------------------------- restore defaults
    def restore_scan_defaults(self) -> None:
        """Menu item: Restore Default Scan Settings (networks/email untouched)."""
        for section, values in DEFAULT_SCAN_SECTION.items():
            self.data[section] = copy.deepcopy(values)
        self.save()

    # -------------------------------------------------------------- helpers
    @property
    def root(self) -> Path:
        return ROOT

    def dir(self, key: str) -> Path:
        p = Path(self.get(f"paths.{key}", key))
        return p if p.is_absolute() else ROOT / p
