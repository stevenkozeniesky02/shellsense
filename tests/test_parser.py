"""Tests for the command parser."""

import pytest

from shellsense.core.parser import CommandParser


@pytest.fixture
def parser():
    return CommandParser()


class TestBasicParsing:
    def test_empty_command(self, parser):
        result = parser.parse("")
        assert result.executable == ""
        assert result.args == ()
        assert result.flags == ()

    def test_simple_command(self, parser):
        result = parser.parse("ls")
        assert result.executable == "ls"
        assert result.args == ()
        assert result.flags == ()

    def test_command_with_flags(self, parser):
        result = parser.parse("ls -la")
        assert result.executable == "ls"
        assert "-la" in result.flags

    def test_command_with_args(self, parser):
        result = parser.parse("cat file.txt")
        assert result.executable == "cat"
        assert result.args == ("file.txt",)

    def test_command_with_flags_and_args(self, parser):
        result = parser.parse("rm -rf build/")
        assert result.executable == "rm"
        assert "-rf" in result.flags
        assert "build/" in result.args

    def test_raw_preserved(self, parser):
        cmd = "rm -rf /tmp/foo"
        result = parser.parse(cmd)
        assert result.raw == cmd


class TestQuotedPaths:
    def test_single_quoted_path(self, parser):
        result = parser.parse("rm 'my file.txt'")
        assert result.executable == "rm"
        assert "my file.txt" in result.args

    def test_double_quoted_path(self, parser):
        result = parser.parse('rm "my file.txt"')
        assert result.executable == "rm"
        assert "my file.txt" in result.args

    def test_path_with_spaces(self, parser):
        result = parser.parse("cp 'source dir/file' 'dest dir/'")
        assert result.executable == "cp"
        assert "source dir/file" in result.args
        assert "dest dir/" in result.args


class TestPipes:
    def test_simple_pipe(self, parser):
        result = parser.parse("cat file.txt | grep error")
        assert result.is_piped is True
        assert "grep error" in result.pipe_commands

    def test_multi_pipe(self, parser):
        result = parser.parse("ps aux | grep python | wc -l")
        assert result.is_piped is True
        assert len(result.pipe_commands) == 2

    def test_pipe_in_quotes_not_split(self, parser):
        result = parser.parse("echo 'hello | world'")
        assert result.is_piped is False

    def test_curl_pipe_bash(self, parser):
        result = parser.parse("curl https://example.com/script.sh | bash")
        assert result.is_piped is True
        assert "bash" in result.pipe_commands


class TestSudo:
    def test_sudo_detected(self, parser):
        result = parser.parse("sudo rm -rf /tmp")
        assert result.is_sudo is True
        assert result.executable == "rm"

    def test_sudo_with_flags(self, parser):
        result = parser.parse("sudo -u admin rm file.txt")
        assert result.is_sudo is True
        assert result.executable == "rm"

    def test_no_sudo(self, parser):
        result = parser.parse("rm file.txt")
        assert result.is_sudo is False


class TestRedirects:
    def test_output_redirect(self, parser):
        result = parser.parse("echo hello > output.txt")
        assert result.has_redirect is True
        assert result.redirect_target == "output.txt"

    def test_append_redirect(self, parser):
        result = parser.parse("echo hello >> log.txt")
        assert result.has_redirect is True

    def test_no_redirect(self, parser):
        result = parser.parse("ls -la")
        assert result.has_redirect is False


class TestSubshells:
    def test_subshell_extraction(self, parser):
        result = parser.parse("echo $(whoami)")
        assert "whoami" in result.subshell_commands

    def test_nested_subshell(self, parser):
        result = parser.parse("echo $(echo $(date))")
        assert len(result.subshell_commands) >= 1

    def test_no_subshell(self, parser):
        result = parser.parse("ls -la")
        assert result.subshell_commands == ()


class TestEdgeCases:
    def test_whitespace_only(self, parser):
        result = parser.parse("   ")
        assert result.executable == ""

    def test_multiple_spaces(self, parser):
        result = parser.parse("rm   -rf    /tmp")
        assert result.executable == "rm"
        assert "-rf" in result.flags

    def test_long_command(self, parser):
        result = parser.parse("find . -name '*.py' -type f")
        assert result.executable == "find"

    def test_command_with_equals(self, parser):
        result = parser.parse("git config user.name=foo")
        assert result.executable == "git"
