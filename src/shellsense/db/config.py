"""Configuration management for ShellSense."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redefine]


DEFAULT_CONFIG_DIR = os.path.expanduser("~/.shellsense")
DEFAULT_CONFIG_FILE = os.path.join(DEFAULT_CONFIG_DIR, "config.toml")


@dataclass(frozen=True)
class Config:
    """ShellSense configuration loaded from TOML."""

    risk_threshold_caution: int = 20
    risk_threshold_danger: int = 50
    auto_block_danger: bool = False
    allowlist: tuple[str, ...] = ()
    blocklist: tuple[str, ...] = ()
    custom_patterns: tuple[tuple[str, int, str], ...] = ()
    history_file: str = os.path.join(DEFAULT_CONFIG_DIR, "history.jsonl")
    max_history: int = 1000

    @classmethod
    def load(cls, path: Optional[str] = None) -> Config:
        """Load config from a TOML file, falling back to defaults."""
        config_path = path or DEFAULT_CONFIG_FILE

        if not os.path.exists(config_path):
            return cls()

        with open(config_path, "rb") as f:
            data = tomllib.load(f)

        general = data.get("general", {})
        patterns_raw = data.get("patterns", {})

        allowlist = tuple(general.get("allowlist", []))
        blocklist = tuple(general.get("blocklist", []))

        custom_patterns: list[tuple[str, int, str]] = []
        for p in patterns_raw.get("dangerous", []):
            if "regex" in p and "score" in p and "warning" in p:
                custom_patterns.append((p["regex"], p["score"], p["warning"]))

        return cls(
            risk_threshold_caution=general.get("risk_threshold_caution", 20),
            risk_threshold_danger=general.get("risk_threshold_danger", 50),
            auto_block_danger=general.get("auto_block_danger", False),
            allowlist=allowlist,
            blocklist=blocklist,
            custom_patterns=tuple(custom_patterns),
            history_file=general.get(
                "history_file", os.path.join(DEFAULT_CONFIG_DIR, "history.jsonl")
            ),
            max_history=general.get("max_history", 1000),
        )

    @classmethod
    def ensure_config_dir(cls) -> str:
        """Create the config directory if it doesn't exist, return its path."""
        os.makedirs(DEFAULT_CONFIG_DIR, exist_ok=True)
        return DEFAULT_CONFIG_DIR
