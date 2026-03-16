"""Risk scoring engine for ShellSense."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from shellsense.core.models import CommandInfo, RiskLevel, Suggestion


@dataclass(frozen=True)
class PatternMatch:
    """Result of matching a command against a dangerous pattern."""

    pattern_name: str
    risk_score: int
    warning: str
    suggestion: Optional[Suggestion] = None


# Base risk scores for known executables
EXECUTABLE_RISK: dict[str, int] = {
    # Safe - read-only / informational
    "ls": 0,
    "cat": 0,
    "head": 0,
    "tail": 0,
    "echo": 0,
    "pwd": 0,
    "whoami": 0,
    "date": 0,
    "which": 0,
    "whereis": 0,
    "file": 0,
    "wc": 0,
    "diff": 5,
    "grep": 0,
    "find": 0,
    "tree": 0,
    "du": 0,
    "df": 0,
    "ps": 0,
    "top": 0,
    "env": 0,
    "printenv": 0,
    "uname": 0,
    "man": 0,
    "history": 0,
    # Low risk - creates/modifies files in predictable ways
    "touch": 10,
    "mkdir": 10,
    "cp": 20,
    "tee": 15,
    "ln": 15,
    "tar": 20,
    "zip": 15,
    "unzip": 20,
    "gzip": 20,
    "wget": 25,
    "curl": 25,
    "git": 20,
    "pip": 30,
    "npm": 30,
    "yarn": 30,
    "brew": 30,
    "cargo": 25,
    # Medium risk - modifies system/file state
    "mv": 35,
    "chmod": 40,
    "chown": 40,
    "chgrp": 40,
    "sed": 30,
    "awk": 25,
    "rsync": 30,
    "apt": 40,
    "apt-get": 40,
    "yum": 40,
    "dnf": 40,
    "pacman": 40,
    "systemctl": 45,
    "service": 45,
    "launchctl": 45,
    # High risk - destructive or system-level
    "rm": 50,
    "rmdir": 35,
    "kill": 45,
    "killall": 55,
    "pkill": 55,
    "docker": 40,
    "kubectl": 45,
    "terraform": 45,
    "dd": 70,
    "mkfs": 90,
    "fdisk": 90,
    "mount": 50,
    "umount": 50,
    "iptables": 60,
    "reboot": 80,
    "shutdown": 80,
    "halt": 80,
    "poweroff": 80,
    "init": 85,
}


class RiskScorer:
    """Scores the risk level of parsed shell commands."""

    def __init__(self, custom_patterns: Optional[list[tuple[str, int, str]]] = None):
        self._dangerous_patterns = self._build_dangerous_patterns()
        if custom_patterns:
            for pattern_str, score, warning in custom_patterns:
                self._dangerous_patterns.append(
                    (re.compile(pattern_str), score, warning, None)
                )

    def score(self, cmd: CommandInfo) -> tuple[int, RiskLevel, tuple[PatternMatch, ...]]:
        """Calculate risk score and level for a command.

        Returns (score, level, matched_patterns).
        """
        base_score = EXECUTABLE_RISK.get(cmd.executable, 30)
        matches: list[PatternMatch] = []

        # Check dangerous patterns against the raw command
        for regex, score_add, warning, suggestion in self._dangerous_patterns:
            if regex.search(cmd.raw):
                matches.append(
                    PatternMatch(
                        pattern_name=regex.pattern,
                        risk_score=score_add,
                        warning=warning,
                        suggestion=suggestion,
                    )
                )

        # Apply flag-based modifiers
        flag_score = self._score_flags(cmd)

        # Sudo escalation
        sudo_score = 20 if cmd.is_sudo else 0

        # Pipe risk: piping to bash/sh is dangerous
        pipe_score = self._score_pipes(cmd)

        # Sum up
        total = base_score + flag_score + sudo_score + pipe_score
        for m in matches:
            total += m.risk_score

        total = min(total, 100)
        level = self._score_to_level(total)

        return total, level, tuple(matches)

    def _score_flags(self, cmd: CommandInfo) -> int:
        """Score risk contribution from command flags."""
        score = 0

        flag_set = set(cmd.flags)

        # Recursive flags increase risk
        if flag_set & {"-r", "-R", "--recursive"}:
            score += 15

        # Force flags bypass confirmation
        if flag_set & {"-f", "--force"}:
            score += 20

        # rm -rf is the classic danger combo
        if cmd.executable == "rm" and "-r" in flag_set and "-f" in flag_set:
            score += 15  # extra on top of individual flag scores
        elif cmd.executable == "rm" and "-rf" in flag_set:
            score += 50

        # chmod 777 is a security issue
        if cmd.executable == "chmod" and "777" in cmd.args:
            score += 30

        # git reset --hard is irreversible
        if cmd.executable == "git" and "--hard" in flag_set:
            score += 30

        # docker system prune
        if cmd.executable == "docker" and "system" in cmd.args and "prune" in cmd.args:
            score += 25
            if flag_set & {"-a", "--all", "-af"}:
                score += 15

        # kubectl delete
        if cmd.executable == "kubectl" and "delete" in cmd.args:
            score += 25
            if "--all" in flag_set:
                score += 20

        return score

    def _score_pipes(self, cmd: CommandInfo) -> int:
        """Score risk from piped commands."""
        if not cmd.is_piped:
            return 0

        score = 0
        dangerous_pipe_targets = {"bash", "sh", "zsh", "eval", "sudo"}

        for pipe_cmd in cmd.pipe_commands:
            tokens = pipe_cmd.strip().split()
            if tokens and tokens[0] in dangerous_pipe_targets:
                score += 40

        return score

    def _score_to_level(self, score: int) -> RiskLevel:
        if score <= 20:
            return RiskLevel.SAFE
        elif score <= 50:
            return RiskLevel.CAUTION
        else:
            return RiskLevel.DANGER

    def _build_dangerous_patterns(
        self,
    ) -> list[tuple[re.Pattern, int, str, Optional[Suggestion]]]:
        """Build the list of dangerous command patterns."""
        return [
            (
                re.compile(r"rm\s+(-\w*r\w*\s+.*)?/\s*$"),
                50,
                "Deleting root filesystem - this will destroy your system!",
                Suggestion(
                    message="Did you mean to delete a subdirectory?",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r"rm\s+-\w*r\w*f?\w*\s+/\s"),
                40,
                "Recursive delete from root - extremely dangerous!",
                Suggestion(
                    message="Use a specific path instead of /",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r":\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
                50,
                "Fork bomb detected - will crash your system!",
                None,
            ),
            (
                re.compile(r">\s*/dev/sda"),
                50,
                "Writing directly to disk device - will destroy all data!",
                None,
            ),
            (
                re.compile(r"mkfs\s"),
                40,
                "Formatting a filesystem - all data on the device will be lost!",
                None,
            ),
            (
                re.compile(r"dd\s+.*of=/dev/"),
                40,
                "Writing raw data to a device - this can destroy data!",
                None,
            ),
            (
                re.compile(r"chmod\s+(-R\s+)?777\s"),
                25,
                "Setting world-readable/writable permissions is a security risk",
                Suggestion(
                    message="Use more restrictive permissions",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r"curl\s+.*\|\s*(ba)?sh"),
                35,
                "Piping downloaded content directly to shell - could execute arbitrary code!",
                Suggestion(
                    message="Download first, inspect, then execute",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r"wget\s+.*\|\s*(ba)?sh"),
                35,
                "Piping downloaded content directly to shell - could execute arbitrary code!",
                Suggestion(
                    message="Download first, inspect, then execute",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r"git\s+push\s+.*--force(?!-with-lease)"),
                25,
                "Force pushing can overwrite others' work on the remote",
                Suggestion(
                    message="Use --force-with-lease for safer force pushes",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r"git\s+reset\s+--hard"),
                30,
                "Hard reset discards all uncommitted changes irreversibly",
                Suggestion(
                    message="Consider 'git stash' to save changes first",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r"docker\s+system\s+prune\s+-a"),
                30,
                "Will remove all unused Docker images, containers, and volumes",
                None,
            ),
            (
                re.compile(r"kubectl\s+delete\s+.*--all"),
                35,
                "Deleting all resources in namespace - potentially destructive!",
                None,
            ),
            (
                re.compile(r"pip\s+install\s+(?!-r)(?!--requirement)\S+.*--break-system-packages"),
                20,
                "Installing packages that may break system Python",
                Suggestion(
                    message="Use a virtual environment instead",
                    suggested_command=None,
                ),
            ),
            (
                re.compile(r"rm\s.*\s\.\s"),
                20,
                "Potential accidental space in rm path - may delete current directory contents",
                Suggestion(
                    message="Check for unintended spaces in the path",
                    suggested_command=None,
                ),
            ),
        ]
