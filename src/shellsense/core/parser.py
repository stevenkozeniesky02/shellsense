"""Shell command parser for ShellSense."""

from __future__ import annotations

import shlex
from typing import Optional

from shellsense.core.models import CommandInfo


class CommandParser:
    """Parses shell command strings into structured CommandInfo objects."""

    def parse(self, command_str: str) -> CommandInfo:
        """Parse a shell command string into a CommandInfo object.

        Handles pipes, redirects, sudo, subshells, and quoted arguments.
        """
        command_str = command_str.strip()
        if not command_str:
            return CommandInfo(raw=command_str, executable="", args=(), flags=())

        is_piped = "|" in command_str and not self._is_inside_quotes(command_str, "|")
        pipe_commands: tuple[str, ...] = ()

        if is_piped:
            segments = self._split_on_pipe(command_str)
            pipe_commands = tuple(s.strip() for s in segments[1:])
            first_segment = segments[0].strip()
        else:
            first_segment = command_str

        has_redirect, redirect_target = self._detect_redirect(first_segment)
        if has_redirect:
            first_segment = self._strip_redirect(first_segment)

        subshell_commands = self._extract_subshells(command_str)

        is_sudo = False
        working_str = first_segment

        if self._starts_with_sudo(working_str):
            is_sudo = True
            working_str = self._strip_sudo(working_str)

        tokens = self._safe_split(working_str)
        if not tokens:
            return CommandInfo(
                raw=command_str,
                executable="",
                args=(),
                flags=(),
                is_piped=is_piped,
                pipe_commands=pipe_commands,
                is_sudo=is_sudo,
                has_redirect=has_redirect,
                redirect_target=redirect_target,
                subshell_commands=subshell_commands,
            )

        executable = tokens[0]
        rest = tokens[1:]

        flags = tuple(t for t in rest if t.startswith("-"))
        args = tuple(t for t in rest if not t.startswith("-"))

        return CommandInfo(
            raw=command_str,
            executable=executable,
            args=args,
            flags=flags,
            is_piped=is_piped,
            pipe_commands=pipe_commands,
            is_sudo=is_sudo,
            has_redirect=has_redirect,
            redirect_target=redirect_target,
            subshell_commands=subshell_commands,
        )

    def _safe_split(self, command_str: str) -> list[str]:
        """Split a command string respecting quotes, with fallback."""
        try:
            return shlex.split(command_str)
        except ValueError:
            return command_str.split()

    def _is_inside_quotes(self, text: str, char: str) -> bool:
        """Check if all occurrences of char are inside quotes."""
        in_single = False
        in_double = False
        found_outside = False

        for c in text:
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif c == char and not in_single and not in_double:
                found_outside = True

        return not found_outside

    def _split_on_pipe(self, text: str) -> list[str]:
        """Split command on pipe characters, respecting quotes."""
        segments: list[str] = []
        current: list[str] = []
        in_single = False
        in_double = False

        for c in text:
            if c == "'" and not in_double:
                in_single = not in_single
                current.append(c)
            elif c == '"' and not in_single:
                in_double = not in_double
                current.append(c)
            elif c == "|" and not in_single and not in_double:
                segments.append("".join(current))
                current = []
            else:
                current.append(c)

        segments.append("".join(current))
        return segments

    def _detect_redirect(self, text: str) -> tuple[bool, Optional[str]]:
        """Detect output redirects (>, >>, 2>, &>)."""
        in_single = False
        in_double = False

        for i, c in enumerate(text):
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif c in (">",) and not in_single and not in_double:
                rest = text[i:].lstrip(">").strip()
                target = rest.split()[0] if rest.split() else None
                return True, target

        return False, None

    def _strip_redirect(self, text: str) -> str:
        """Remove redirect portion from command string."""
        in_single = False
        in_double = False

        for i, c in enumerate(text):
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif c in (">",) and not in_single and not in_double:
                return text[:i].rstrip()

        return text

    def _starts_with_sudo(self, text: str) -> bool:
        """Check if command starts with sudo."""
        tokens = text.strip().split()
        return len(tokens) > 0 and tokens[0] == "sudo"

    def _strip_sudo(self, text: str) -> str:
        """Remove sudo prefix, including sudo flags like -u."""
        tokens = self._safe_split(text)
        if not tokens or tokens[0] != "sudo":
            return text

        i = 1
        sudo_flags_with_args = {"-u", "-g", "-C", "-H", "-P"}
        sudo_flags_no_args = {"-i", "-s", "-b", "-n", "-k", "-K", "-v", "-l", "-E"}

        while i < len(tokens):
            if tokens[i] in sudo_flags_with_args:
                i += 2
            elif tokens[i] in sudo_flags_no_args or tokens[i].startswith("--"):
                i += 1
            elif tokens[i] == "--":
                i += 1
                break
            else:
                break

        return " ".join(tokens[i:])

    def _extract_subshells(self, text: str) -> tuple[str, ...]:
        """Extract commands from $(...) subshell expressions."""
        subshells: list[str] = []
        i = 0

        while i < len(text):
            if text[i] == "$" and i + 1 < len(text) and text[i + 1] == "(":
                depth = 1
                start = i + 2
                j = start
                while j < len(text) and depth > 0:
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        depth -= 1
                    j += 1
                if depth == 0:
                    subshells.append(text[start : j - 1])
                i = j
            else:
                i += 1

        return tuple(subshells)
