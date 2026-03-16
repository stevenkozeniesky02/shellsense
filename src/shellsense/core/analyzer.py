"""Main analysis orchestrator for ShellSense."""

from __future__ import annotations

from typing import Optional

from shellsense.core.models import AnalysisResult
from shellsense.core.parser import CommandParser
from shellsense.core.predictor import FilesystemPredictor


class Analyzer:
    """Orchestrates command parsing, risk scoring, and filesystem prediction."""

    def __init__(self, working_dir: Optional[str] = None):
        self._parser = CommandParser()
        self._predictor = FilesystemPredictor(working_dir=working_dir)

    def analyze(self, command_str: str) -> AnalysisResult:
        """Analyze a shell command string and return full analysis."""
        cmd = self._parser.parse(command_str)
        return self._predictor.analyze(cmd)

    def analyze_multi(self, command_str: str) -> list[AnalysisResult]:
        """Analyze a command string that may contain && or ; separated commands."""
        commands = self._split_compound(command_str)
        return [self.analyze(c) for c in commands]

    def _split_compound(self, text: str) -> list[str]:
        """Split on && and ; while respecting quotes."""
        segments: list[str] = []
        current: list[str] = []
        in_single = False
        in_double = False
        i = 0

        while i < len(text):
            c = text[i]

            if c == "'" and not in_double:
                in_single = not in_single
                current.append(c)
            elif c == '"' and not in_single:
                in_double = not in_double
                current.append(c)
            elif not in_single and not in_double:
                if c == ";" or (c == "&" and i + 1 < len(text) and text[i + 1] == "&"):
                    segment = "".join(current).strip()
                    if segment:
                        segments.append(segment)
                    current = []
                    if c == "&":
                        i += 1  # skip second &
                else:
                    current.append(c)
            else:
                current.append(c)
            i += 1

        final = "".join(current).strip()
        if final:
            segments.append(final)

        return segments
