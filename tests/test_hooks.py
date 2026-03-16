"""Tests for hook generation."""

import json

import pytest

from shellsense.hooks.generator import HookGenerator


@pytest.fixture
def generator():
    return HookGenerator()


class TestShellHooks:
    def test_zsh_hook_generation(self, generator):
        script = generator.generate_shell_hook("zsh")
        assert "preexec" in script
        assert "zsh" in script.lower()
        assert "shellsense check" in script

    def test_bash_hook_generation(self, generator):
        script = generator.generate_shell_hook("bash")
        assert "shellsense check" in script
        assert "DEBUG" in script or "preexec" in script

    def test_unsupported_shell_raises(self, generator):
        with pytest.raises(ValueError, match="Unsupported shell"):
            generator.generate_shell_hook("fish")

    def test_zsh_hook_has_confirmation(self, generator):
        script = generator.generate_shell_hook("zsh")
        assert "Proceed" in script or "proceed" in script

    def test_bash_hook_has_confirmation(self, generator):
        script = generator.generate_shell_hook("bash")
        assert "Proceed" in script or "proceed" in script


class TestClaudeCodeHook:
    def test_generates_valid_json(self, generator):
        snippet = generator.generate_claude_code_hook()
        data = json.loads(snippet)
        assert "hooks" in data

    def test_has_pre_tool_use(self, generator):
        snippet = generator.generate_claude_code_hook()
        data = json.loads(snippet)
        assert "PreToolUse" in data["hooks"]

    def test_matches_bash_tool(self, generator):
        snippet = generator.generate_claude_code_hook()
        data = json.loads(snippet)
        hooks = data["hooks"]["PreToolUse"]
        assert any(h["matcher"] == "Bash" for h in hooks)

    def test_hook_is_blocking(self, generator):
        snippet = generator.generate_claude_code_hook()
        data = json.loads(snippet)
        hook_entry = data["hooks"]["PreToolUse"][0]
        assert hook_entry["hooks"][0]["blocking"] is True
