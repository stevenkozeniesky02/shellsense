"""Rich terminal output for ShellSense analysis results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from shellsense.core.models import (
    AnalysisResult,
    FileChange,
    FileChangeType,
    RiskLevel,
)
from shellsense.db.history import HistoryEntry


def _risk_badge(level: RiskLevel) -> str:
    color = level.color
    label = level.value.upper()
    return f"[bold {color}] {label} [/bold {color}]"


def _change_icon(change_type: FileChangeType) -> str:
    icons = {
        FileChangeType.CREATE: "[green]+[/green]",
        FileChangeType.MODIFY: "[yellow]~[/yellow]",
        FileChangeType.DELETE: "[red]-[/red]",
        FileChangeType.MOVE: "[blue]>[/blue]",
        FileChangeType.PERMISSION: "[magenta]P[/magenta]",
        FileChangeType.OWNERSHIP: "[magenta]O[/magenta]",
    }
    return icons.get(change_type, "?")


def _format_size(size_bytes: int | None) -> str:
    if size_bytes is None:
        return ""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


class ResultRenderer:
    """Renders analysis results to the terminal using Rich."""

    def __init__(self, console: Console | None = None):
        self._console = console or Console()

    def render(self, result: AnalysisResult) -> None:
        """Render a full analysis result."""
        self._render_header(result)
        self._render_risk_bar(result)

        if result.predicted_changes:
            self._render_changes(result.predicted_changes)

        self._render_reversibility(result)

        if result.warnings:
            self._render_warnings(result.warnings)

        if result.suggestions:
            self._render_suggestions(result)

        if result.dry_run_available and result.dry_run_command:
            self._render_dry_run(result.dry_run_command)

        self._console.print()

    def _render_header(self, result: AnalysisResult) -> None:
        badge = _risk_badge(result.risk_level)
        cmd_display = result.command.raw
        if len(cmd_display) > 80:
            cmd_display = cmd_display[:77] + "..."

        self._console.print()
        self._console.print(
            Panel(
                f"[bold]{cmd_display}[/bold]",
                title=f"{badge} ShellSense Analysis",
                border_style=result.risk_level.color,
            )
        )

    def _render_risk_bar(self, result: AnalysisResult) -> None:
        score = result.risk_score
        bar_width = 40
        filled = int(bar_width * score / 100)
        empty = bar_width - filled

        color = result.risk_level.color
        bar = f"[{color}]{'█' * filled}[/{color}]{'░' * empty}"

        self._console.print(f"  Risk Score: {bar} {score}/100")

    def _render_changes(self, changes: tuple[FileChange, ...]) -> None:
        self._console.print()
        tree = Tree("[bold]Predicted Changes[/bold]")

        total_size = 0
        for change in changes:
            icon = _change_icon(change.change_type)
            size_str = f" ({_format_size(change.size_bytes)})" if change.size_bytes else ""
            label = f"{icon} {change.path}{size_str}"
            branch = tree.add(label)
            if change.details:
                branch.add(f"[dim]{change.details}[/dim]")
            if change.size_bytes:
                total_size += change.size_bytes

        self._console.print(tree)

        if total_size > 0:
            # Check if mostly deletes
            deletes = [c for c in changes if c.change_type == FileChangeType.DELETE]
            creates = [c for c in changes if c.change_type == FileChangeType.CREATE]

            if deletes:
                freed = sum(c.size_bytes or 0 for c in deletes)
                if freed:
                    self._console.print(f"  [dim]Space freed: ~{_format_size(freed)}[/dim]")
            if creates:
                used = sum(c.size_bytes or 0 for c in creates)
                if used:
                    self._console.print(f"  [dim]Space used: ~{_format_size(used)}[/dim]")

    def _render_reversibility(self, result: AnalysisResult) -> None:
        self._console.print()
        if result.reversible:
            self._console.print(f"  [green]Reversible:[/green] {result.reversibility_note}")
        else:
            self._console.print(
                f"  [red]Not Reversible:[/red] {result.reversibility_note}"
            )

    def _render_warnings(self, warnings: tuple[str, ...]) -> None:
        self._console.print()
        for warning in warnings:
            self._console.print(f"  [bold yellow]Warning:[/bold yellow] {warning}")

    def _render_suggestions(self, result: AnalysisResult) -> None:
        self._console.print()
        for suggestion in result.suggestions:
            self._console.print(
                f"  [bold cyan]Suggestion:[/bold cyan] {suggestion.message}"
            )
            if suggestion.suggested_command:
                self._console.print(
                    f"    [dim]Try: {suggestion.suggested_command}[/dim]"
                )

    def _render_dry_run(self, dry_run_command: str) -> None:
        self._console.print()
        self._console.print(
            f"  [bold blue]Dry run available:[/bold blue] {dry_run_command}"
        )

    def render_history(self, entries: list[HistoryEntry]) -> None:
        """Render command history table."""
        if not entries:
            self._console.print("[dim]No history recorded yet.[/dim]")
            return

        table = Table(title="ShellSense History", show_lines=True)
        table.add_column("Time", style="dim", width=20)
        table.add_column("Command", max_width=50)
        table.add_column("Risk", justify="center", width=10)
        table.add_column("Score", justify="center", width=8)
        table.add_column("Changes", justify="center", width=8)
        table.add_column("Warnings", justify="center", width=8)

        for entry in entries:
            risk_color = {
                "safe": "green",
                "caution": "yellow",
                "danger": "red",
            }.get(entry.risk_level, "white")

            cmd_display = entry.command
            if len(cmd_display) > 47:
                cmd_display = cmd_display[:44] + "..."

            table.add_row(
                entry.timestamp[:19].replace("T", " "),
                cmd_display,
                f"[{risk_color}]{entry.risk_level.upper()}[/{risk_color}]",
                str(entry.risk_score),
                str(entry.predicted_changes_count),
                str(entry.warnings_count),
            )

        self._console.print(table)
