"""CLI entry point for ShellSense."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from shellsense.cli.output import ResultRenderer
from shellsense.core.analyzer import Analyzer
from shellsense.db.config import Config
from shellsense.db.history import HistoryStore
from shellsense.hooks.generator import HookGenerator


@click.group()
@click.version_option(package_name="shellsense")
def cli() -> None:
    """ShellSense: Predict the consequences of shell commands before you run them."""


@cli.command()
@click.argument("command")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--no-history", is_flag=True, help="Don't record to history")
def check(command: str, as_json: bool, no_history: bool) -> None:
    """Analyze a single shell command for safety."""
    config = Config.load()
    analyzer = Analyzer()
    renderer = ResultRenderer()

    # Handle compound commands (&&, ;)
    results = analyzer.analyze_multi(command)

    for result in results:
        if as_json:
            _print_json(result)
        else:
            renderer.render(result)

        if not no_history:
            history = HistoryStore(config)
            history.record(
                command=result.command.raw,
                risk_level=result.risk_level,
                risk_score=result.risk_score,
                predicted_changes_count=len(result.predicted_changes),
                warnings_count=len(result.warnings),
            )

    # Exit with non-zero if any command is dangerous
    if any(r.risk_level.value == "danger" for r in results):
        sys.exit(1)


@cli.command()
@click.option("--limit", "-n", default=20, help="Number of entries to show")
def history(limit: int) -> None:
    """Show past commands and their predicted impact."""
    config = Config.load()
    store = HistoryStore(config)
    entries = store.load(limit=limit)
    renderer = ResultRenderer()
    renderer.render_history(entries)


@cli.command()
@click.argument("shell", type=click.Choice(["bash", "zsh"]))
def hook(shell: str) -> None:
    """Generate shell hook script for automatic command checking.

    Usage: eval "$(shellsense hook zsh)"
    """
    generator = HookGenerator()
    script = generator.generate_shell_hook(shell)
    click.echo(script)


@cli.command()
def hooks_json() -> None:
    """Generate Claude Code hooks.json snippet for PreToolUse on Bash commands."""
    generator = HookGenerator()
    snippet = generator.generate_claude_code_hook()
    click.echo(snippet)


@cli.command()
def watch() -> None:
    """Interactive mode - analyze commands as you type them.

    Type commands and press Enter to see analysis.
    Type 'exit' or Ctrl+C to quit.
    """
    console = Console()
    analyzer = Analyzer()
    renderer = ResultRenderer()
    config = Config.load()
    history_store = HistoryStore(config)

    console.print("[bold]ShellSense Watch Mode[/bold]")
    console.print("[dim]Type commands to analyze. 'exit' or Ctrl+C to quit.[/dim]")
    console.print()

    while True:
        try:
            command = console.input("[bold green]shellsense>[/bold green] ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye![/dim]")
            break

        command = command.strip()
        if not command:
            continue
        if command in ("exit", "quit", "q"):
            console.print("[dim]Goodbye![/dim]")
            break

        results = analyzer.analyze_multi(command)
        for result in results:
            renderer.render(result)
            history_store.record(
                command=result.command.raw,
                risk_level=result.risk_level,
                risk_score=result.risk_score,
                was_executed=False,
                predicted_changes_count=len(result.predicted_changes),
                warnings_count=len(result.warnings),
            )


@cli.command()
def init() -> None:
    """Initialize ShellSense config directory with default config."""
    config_dir = Config.ensure_config_dir()
    config_file = f"{config_dir}/config.toml"

    import os

    if os.path.exists(config_file):
        click.echo(f"Config already exists at {config_file}")
        return

    default_config = """\
# ShellSense Configuration

[general]
# Risk thresholds (0-100)
risk_threshold_caution = 20
risk_threshold_danger = 50

# Block dangerous commands automatically
auto_block_danger = false

# Commands to always allow (bypass checking)
allowlist = []

# Commands to always block
blocklist = []

# History settings
max_history = 1000

# Custom dangerous patterns
# [[patterns.dangerous]]
# regex = "my-dangerous-command.*"
# score = 50
# warning = "This command is dangerous because..."
"""
    with open(config_file, "w") as f:
        f.write(default_config)

    click.echo(f"Created config at {config_file}")


def _print_json(result) -> None:
    """Print analysis result as JSON."""
    import json

    data = {
        "command": result.command.raw,
        "risk_level": result.risk_level.value,
        "risk_score": result.risk_score,
        "reversible": result.reversible,
        "reversibility_note": result.reversibility_note,
        "predicted_changes": [
            {
                "path": c.path,
                "type": c.change_type.value,
                "details": c.details,
                "size_bytes": c.size_bytes,
            }
            for c in result.predicted_changes
        ],
        "warnings": list(result.warnings),
        "suggestions": [
            {"message": s.message, "suggested_command": s.suggested_command}
            for s in result.suggestions
        ],
        "dry_run_available": result.dry_run_available,
        "dry_run_command": result.dry_run_command,
    }
    click.echo(json.dumps(data, indent=2))
