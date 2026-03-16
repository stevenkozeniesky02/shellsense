"""Built-in safety knowledge base for dangerous command patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SafetyRule:
    """A rule in the safety database."""

    name: str
    pattern: re.Pattern
    category: str
    severity: str  # "info", "warning", "critical"
    description: str
    suggestion: Optional[str] = None


class SafetyDatabase:
    """Built-in knowledge base of dangerous command patterns."""

    def __init__(self) -> None:
        self._rules = self._build_rules()

    @property
    def rules(self) -> tuple[SafetyRule, ...]:
        return tuple(self._rules)

    def check(self, command: str) -> list[SafetyRule]:
        """Check a command string against all safety rules. Returns matched rules."""
        matched: list[SafetyRule] = []
        for rule in self._rules:
            if rule.pattern.search(command):
                matched.append(rule)
        return matched

    def _build_rules(self) -> list[SafetyRule]:
        return [
            # Filesystem destruction
            SafetyRule(
                name="rm_root",
                pattern=re.compile(r"rm\s+(-\w*r\w*\s+)?/\s*$"),
                category="filesystem",
                severity="critical",
                description="Attempting to remove root filesystem",
                suggestion="Specify the exact path you want to remove",
            ),
            SafetyRule(
                name="rm_recursive_force",
                pattern=re.compile(r"rm\s+-\w*rf\w*\s"),
                category="filesystem",
                severity="warning",
                description="Recursive forced deletion - no confirmation prompt",
                suggestion="Remove -f flag to get confirmation prompts, or use trash-cli",
            ),
            SafetyRule(
                name="rm_space_in_path",
                pattern=re.compile(r'rm\s+-\w*r\w*\s+[^"\']*\s+/'),
                category="filesystem",
                severity="critical",
                description="Possible unquoted space in rm path - may delete / by accident",
                suggestion="Quote paths with spaces: rm -rf 'my directory/'",
            ),
            SafetyRule(
                name="rm_home",
                pattern=re.compile(r"rm\s+-\w*r\w*\s+(~/|/home/|/Users/)"),
                category="filesystem",
                severity="warning",
                description="Recursive delete targeting home directory",
                suggestion="Double-check the path is correct",
            ),
            # Permission issues
            SafetyRule(
                name="chmod_777",
                pattern=re.compile(r"chmod\s+(-R\s+)?777\s"),
                category="permissions",
                severity="warning",
                description="Setting world-readable/writable permissions",
                suggestion="Use 755 for directories, 644 for files",
            ),
            SafetyRule(
                name="chmod_recursive_root",
                pattern=re.compile(r"chmod\s+-R\s+\d+\s+/\s*$"),
                category="permissions",
                severity="critical",
                description="Recursive permission change on root filesystem",
            ),
            # Download and execute
            SafetyRule(
                name="curl_pipe_bash",
                pattern=re.compile(r"curl\s+.*\|\s*(ba)?sh"),
                category="execution",
                severity="warning",
                description="Downloading and executing code without inspection",
                suggestion="Download the script first, review it, then execute",
            ),
            SafetyRule(
                name="wget_pipe_bash",
                pattern=re.compile(r"wget\s+.*-O\s*-\s*\|\s*(ba)?sh"),
                category="execution",
                severity="warning",
                description="Downloading and executing code without inspection",
                suggestion="Download the script first, review it, then execute",
            ),
            # Git dangers
            SafetyRule(
                name="git_force_push",
                pattern=re.compile(r"git\s+push\s+.*--force(?!-with-lease)"),
                category="git",
                severity="warning",
                description="Force push can overwrite remote history",
                suggestion="Use --force-with-lease instead",
            ),
            SafetyRule(
                name="git_hard_reset",
                pattern=re.compile(r"git\s+reset\s+--hard"),
                category="git",
                severity="warning",
                description="Hard reset discards all uncommitted changes",
                suggestion="Use 'git stash' first to save changes",
            ),
            SafetyRule(
                name="git_clean_force",
                pattern=re.compile(r"git\s+clean\s+-\w*f"),
                category="git",
                severity="warning",
                description="Force clean removes untracked files permanently",
                suggestion="Use 'git clean -n' (dry run) first",
            ),
            # Docker
            SafetyRule(
                name="docker_prune_all",
                pattern=re.compile(r"docker\s+system\s+prune\s+-a"),
                category="docker",
                severity="warning",
                description="Removes all unused Docker images, containers, networks, and volumes",
                suggestion="Use 'docker system prune' without -a to keep tagged images",
            ),
            SafetyRule(
                name="docker_privileged",
                pattern=re.compile(r"docker\s+run\s+.*--privileged"),
                category="docker",
                severity="warning",
                description="Running container in privileged mode - full host access",
                suggestion="Use specific --cap-add flags instead of --privileged",
            ),
            # System-level
            SafetyRule(
                name="dd_device",
                pattern=re.compile(r"dd\s+.*of=/dev/"),
                category="system",
                severity="critical",
                description="Writing raw data to a device - can destroy all data",
                suggestion="Triple-check the device path before proceeding",
            ),
            SafetyRule(
                name="fork_bomb",
                pattern=re.compile(r":\(\)\{.*\|.*&\}.*;.*:"),
                category="system",
                severity="critical",
                description="Fork bomb - will exhaust system resources",
            ),
            SafetyRule(
                name="sudo_pipe",
                pattern=re.compile(r"\|\s*sudo\s"),
                category="system",
                severity="warning",
                description="Piping to sudo - the piped content runs with elevated privileges",
                suggestion="Review what's being piped before running with sudo",
            ),
            # Kubernetes
            SafetyRule(
                name="kubectl_delete_all",
                pattern=re.compile(r"kubectl\s+delete\s+.*--all"),
                category="kubernetes",
                severity="warning",
                description="Deleting all resources of a type in the namespace",
                suggestion="Use --dry-run=client first to see what would be deleted",
            ),
            SafetyRule(
                name="kubectl_delete_namespace",
                pattern=re.compile(r"kubectl\s+delete\s+namespace"),
                category="kubernetes",
                severity="critical",
                description="Deleting an entire namespace removes all resources within it",
                suggestion="Verify the namespace and consider backing up resources first",
            ),
            # Package management
            SafetyRule(
                name="pip_sudo_install",
                pattern=re.compile(r"sudo\s+pip\s+install"),
                category="packages",
                severity="warning",
                description="Installing Python packages system-wide with sudo",
                suggestion="Use a virtual environment: python -m venv .venv",
            ),
            SafetyRule(
                name="npm_global_sudo",
                pattern=re.compile(r"sudo\s+npm\s+install\s+-g"),
                category="packages",
                severity="warning",
                description="Installing npm packages globally with sudo",
                suggestion="Configure npm to use a user-level prefix instead",
            ),
        ]
