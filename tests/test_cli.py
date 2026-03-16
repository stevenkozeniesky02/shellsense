"""Tests for the CLI interface."""

import json

import pytest
from click.testing import CliRunner

from shellsense.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCheckCommand:
    def test_check_safe_command(self, runner):
        result = runner.invoke(cli, ["check", "ls -la", "--no-history"])
        assert result.exit_code == 0

    def test_check_dangerous_command_exits_nonzero(self, runner):
        result = runner.invoke(cli, ["check", "rm -rf /", "--no-history"])
        assert result.exit_code == 1

    def test_check_json_output(self, runner):
        result = runner.invoke(cli, ["check", "ls -la", "--json", "--no-history"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "risk_level" in data
        assert data["risk_level"] == "safe"

    def test_check_json_dangerous(self, runner):
        result = runner.invoke(cli, ["check", "rm -rf /", "--json", "--no-history"])
        data = json.loads(result.output)
        assert data["risk_level"] == "danger"


class TestHistoryCommand:
    def test_history_empty(self, runner, tmp_path, monkeypatch):
        monkeypatch.setenv("SHELLSENSE_CONFIG", str(tmp_path / "config.toml"))
        result = runner.invoke(cli, ["history"])
        assert result.exit_code == 0


class TestHookCommand:
    def test_hook_zsh(self, runner):
        result = runner.invoke(cli, ["hook", "zsh"])
        assert result.exit_code == 0
        assert "preexec" in result.output

    def test_hook_bash(self, runner):
        result = runner.invoke(cli, ["hook", "bash"])
        assert result.exit_code == 0

    def test_hook_invalid_shell(self, runner):
        result = runner.invoke(cli, ["hook", "fish"])
        assert result.exit_code != 0


class TestHooksJsonCommand:
    def test_hooks_json(self, runner):
        result = runner.invoke(cli, ["hooks-json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "hooks" in data


class TestInitCommand:
    def test_init_creates_config(self, runner, tmp_path, monkeypatch):
        import shellsense.db.config as cfg_module

        monkeypatch.setattr(cfg_module, "DEFAULT_CONFIG_DIR", str(tmp_path / ".shellsense"))
        monkeypatch.setattr(
            cfg_module, "DEFAULT_CONFIG_FILE", str(tmp_path / ".shellsense" / "config.toml")
        )

        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0
        assert "Created config" in result.output
