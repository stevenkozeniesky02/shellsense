# ShellSense

**Terminal safety tool that predicts the consequences of shell commands before you run them.**

ShellSense acts as a "what-if" engine for your terminal. It parses shell commands, predicts filesystem changes, scores risk levels, and warns you before you execute something dangerous.

## Features

- **Risk scoring** — Commands rated from safe (green) to danger (red) on a 0-100 scale
- **Filesystem prediction** — See what files will be created, modified, deleted, or permission-changed
- **Reversibility check** — Know if you can undo a command before running it
- **Pattern matching** — Built-in knowledge base of dangerous command patterns
- **Dry-run suggestions** — Automatically suggests dry-run alternatives when available
- **Shell hooks** — Automatic analysis as a Zsh/Bash preexec hook
- **Claude Code integration** — hooks.json snippet for PreToolUse on Bash commands
- **Command history** — Track analyzed commands and their predicted impact

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

### Check a single command

```bash
shellsense check "rm -rf ./build"
```

```
┌──── DANGER  ShellSense Analysis ────┐
│ rm -rf ./build                      │
└─────────────────────────────────────┘
  Risk Score: ████████████████████████░░░░░░░░░░░░░░░░ 72/100

  Predicted Changes
  - ./build (1.2 MB)
    Directory and all contents will be removed

  Not Reversible: Deleted files cannot be recovered without backups
```

### JSON output

```bash
shellsense check "rm -rf /" --json
```

### Interactive watch mode

```bash
shellsense watch
```

Type commands to see their analysis before running them.

### View history

```bash
shellsense history
shellsense history -n 50
```

### Shell hooks

Add automatic command checking to your shell:

```bash
# Zsh
eval "$(shellsense hook zsh)"

# Bash
eval "$(shellsense hook bash)"
```

Add to your `.zshrc` or `.bashrc` for persistence.

### Claude Code integration

Generate a hooks.json snippet:

```bash
shellsense hooks-json
```

### Initialize config

```bash
shellsense init
```

Creates `~/.shellsense/config.toml` with default settings.

## Configuration

Edit `~/.shellsense/config.toml`:

```toml
[general]
risk_threshold_caution = 20
risk_threshold_danger = 50
auto_block_danger = false
allowlist = ["ls", "cat"]
blocklist = ["rm -rf /"]

[[patterns.dangerous]]
regex = "terraform destroy"
score = 60
warning = "Will remove all managed infrastructure"
```

## Supported Commands

ShellSense understands: `rm`, `mv`, `cp`, `chmod`, `chown`, `mkdir`, `touch`, `git`, `docker`, `kubectl`, `pip`, `brew`, `apt`, `systemctl`, `rsync`, and more.

## Risk Levels

| Level | Score | Color | Meaning |
|-------|-------|-------|---------|
| SAFE | 0-20 | Green | Read-only or minimal-impact commands |
| CAUTION | 21-50 | Yellow | Modifies files or system state |
| DANGER | 51-100 | Red | Destructive, irreversible, or system-critical |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=shellsense --cov-report=term-missing

# Lint
ruff check src/ tests/
```

## Project Structure

```
shellsense/
├── src/shellsense/
│   ├── core/           # Parser, risk scorer, filesystem predictor
│   │   ├── analyzer.py # Main orchestrator
│   │   ├── models.py   # Data models (immutable dataclasses)
│   │   ├── parser.py   # Shell command parser
│   │   ├── predictor.py# Filesystem change predictor
│   │   └── risk.py     # Risk scoring engine
│   ├── cli/            # Click CLI and Rich output
│   │   ├── main.py     # CLI entry point
│   │   └── output.py   # Rich terminal renderer
│   ├── db/             # Safety database and config
│   │   ├── config.py   # TOML config management
│   │   ├── history.py  # Command history storage
│   │   └── safety.py   # Dangerous pattern knowledge base
│   └── hooks/          # Shell hook generators
│       └── generator.py
├── tests/
├── examples/
│   ├── config.toml     # Example configuration
│   ├── hooks.json      # Claude Code hook example
│   └── zsh-setup.sh    # Zsh setup script
├── pyproject.toml
└── README.md
```

## License

MIT
