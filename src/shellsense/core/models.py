"""Data models for ShellSense analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    """Risk classification for shell commands."""

    SAFE = "safe"
    CAUTION = "caution"
    DANGER = "danger"

    @property
    def color(self) -> str:
        return {
            RiskLevel.SAFE: "green",
            RiskLevel.CAUTION: "yellow",
            RiskLevel.DANGER: "red",
        }[self]

    @property
    def emoji(self) -> str:
        return {
            RiskLevel.SAFE: "[green]OK[/green]",
            RiskLevel.CAUTION: "[yellow]!![/yellow]",
            RiskLevel.DANGER: "[red]XX[/red]",
        }[self]


class FileChangeType(Enum):
    """Types of filesystem changes a command can cause."""

    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    MOVE = "move"
    PERMISSION = "permission"
    OWNERSHIP = "ownership"


@dataclass(frozen=True)
class FileChange:
    """A predicted filesystem change."""

    path: str
    change_type: FileChangeType
    details: str = ""
    size_bytes: Optional[int] = None


@dataclass(frozen=True)
class Suggestion:
    """A suggested alternative or correction."""

    message: str
    suggested_command: Optional[str] = None


@dataclass(frozen=True)
class CommandInfo:
    """Parsed information about a shell command."""

    raw: str
    executable: str
    args: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    is_piped: bool = False
    pipe_commands: tuple[str, ...] = ()
    is_sudo: bool = False
    has_redirect: bool = False
    redirect_target: Optional[str] = None
    subshell_commands: tuple[str, ...] = ()


@dataclass(frozen=True)
class AnalysisResult:
    """Complete analysis of a shell command."""

    command: CommandInfo
    risk_level: RiskLevel
    risk_score: int  # 0-100
    predicted_changes: tuple[FileChange, ...] = ()
    reversible: bool = True
    reversibility_note: str = ""
    warnings: tuple[str, ...] = ()
    suggestions: tuple[Suggestion, ...] = ()
    dry_run_available: bool = False
    dry_run_command: Optional[str] = None
    matched_patterns: tuple[str, ...] = ()

    def with_changes(self, **kwargs) -> AnalysisResult:
        """Return a new AnalysisResult with specified fields replaced."""
        current = {
            "command": self.command,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "predicted_changes": self.predicted_changes,
            "reversible": self.reversible,
            "reversibility_note": self.reversibility_note,
            "warnings": self.warnings,
            "suggestions": self.suggestions,
            "dry_run_available": self.dry_run_available,
            "dry_run_command": self.dry_run_command,
            "matched_patterns": self.matched_patterns,
        }
        current.update(kwargs)
        return AnalysisResult(**current)
