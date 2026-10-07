"""Configuration: defaults < config file (SSF_CONFIG, JSON) < environment variables."""
import json
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    db_path: str = "data/ssf.db"
    scan_root: str = "."
    log_level: str = "INFO"
    log_file: str = ""
    admin_key: str = ""
    alert_webhook: str = ""
    external_tools: bool = True
    tool_timeout: int = 120
    max_file_bytes: int = 1_000_000
    bruteforce_threshold: int = 5
    bruteforce_window: int = 300
    exclude_dirs: list = field(default_factory=lambda: [
        ".git", "node_modules", "__pycache__", ".venv", "venv", "data"])


def _bool(v):
    return str(v).lower() in ("1", "true", "yes", "on")


def load_config(overrides=None):
    cfg = Config()
    path = os.environ.get("SSF_CONFIG", "config/ssf.json")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            for k, v in json.load(fh).items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
    env = {
        "SSF_DB_PATH": ("db_path", str), "SSF_SCAN_ROOT": ("scan_root", str),
        "SSF_LOG_LEVEL": ("log_level", str), "SSF_LOG_FILE": ("log_file", str),
        "SSF_ADMIN_KEY": ("admin_key", str), "SSF_ALERT_WEBHOOK": ("alert_webhook", str),
        "SSF_EXTERNAL_TOOLS": ("external_tools", _bool),
        "SSF_TOOL_TIMEOUT": ("tool_timeout", int),
        "SSF_BRUTEFORCE_THRESHOLD": ("bruteforce_threshold", int),
        "SSF_BRUTEFORCE_WINDOW": ("bruteforce_window", int),
    }
    for name, (attr, conv) in env.items():
        if name in os.environ:
            setattr(cfg, attr, conv(os.environ[name]))
    for k, v in (overrides or {}).items():
        setattr(cfg, k, v)
    return cfg
