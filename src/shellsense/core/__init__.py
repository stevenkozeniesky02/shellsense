"""Core engine for ShellSense command analysis."""

from shellsense.core.models import (
    AnalysisResult,
    CommandInfo,
    FileChange,
    FileChangeType,
    RiskLevel,
    Suggestion,
)
from shellsense.core.parser import CommandParser
from shellsense.core.predictor import FilesystemPredictor
from shellsense.core.risk import RiskScorer

__all__ = [
    "AnalysisResult",
    "CommandInfo",
    "CommandParser",
    "FileChange",
    "FileChangeType",
    "FilesystemPredictor",
    "RiskLevel",
    "RiskScorer",
    "Suggestion",
]
