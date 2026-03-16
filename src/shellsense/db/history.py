"""Command history storage for ShellSense."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from shellsense.core.models import RiskLevel
from shellsense.db.config import Config


@dataclass(frozen=True)
class HistoryEntry:
    """A recorded command analysis."""

    timestamp: str
    command: str
    risk_level: str
    risk_score: int
    was_executed: bool
    predicted_changes_count: int
    warnings_count: int

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "command": self.command,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "was_executed": self.was_executed,
            "predicted_changes_count": self.predicted_changes_count,
            "warnings_count": self.warnings_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> HistoryEntry:
        return cls(
            timestamp=data["timestamp"],
            command=data["command"],
            risk_level=data["risk_level"],
            risk_score=data["risk_score"],
            was_executed=data.get("was_executed", True),
            predicted_changes_count=data.get("predicted_changes_count", 0),
            warnings_count=data.get("warnings_count", 0),
        )


class HistoryStore:
    """Manages command history persistence."""

    def __init__(self, config: Optional[Config] = None):
        self._config = config or Config()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        history_dir = os.path.dirname(self._config.history_file)
        if history_dir:
            os.makedirs(history_dir, exist_ok=True)

    def record(
        self,
        command: str,
        risk_level: RiskLevel,
        risk_score: int,
        was_executed: bool = True,
        predicted_changes_count: int = 0,
        warnings_count: int = 0,
    ) -> HistoryEntry:
        """Record a command analysis to history."""
        entry = HistoryEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            command=command,
            risk_level=risk_level.value,
            risk_score=risk_score,
            was_executed=was_executed,
            predicted_changes_count=predicted_changes_count,
            warnings_count=warnings_count,
        )

        with open(self._config.history_file, "a") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

        self._trim_history()
        return entry

    def load(self, limit: Optional[int] = None) -> list[HistoryEntry]:
        """Load history entries, most recent first."""
        if not os.path.exists(self._config.history_file):
            return []

        entries: list[HistoryEntry] = []
        with open(self._config.history_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(HistoryEntry.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, KeyError):
                        continue

        entries.reverse()
        if limit:
            entries = entries[:limit]
        return entries

    def _trim_history(self) -> None:
        """Trim history file to max_history entries."""
        if not os.path.exists(self._config.history_file):
            return

        entries: list[str] = []
        with open(self._config.history_file) as f:
            entries = f.readlines()

        if len(entries) > self._config.max_history:
            entries = entries[-self._config.max_history :]
            with open(self._config.history_file, "w") as f:
                f.writelines(entries)
