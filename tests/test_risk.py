"""Tests for the risk scoring engine."""

import pytest

from shellsense.core.models import CommandInfo, RiskLevel
from shellsense.core.risk import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


def _make_cmd(raw: str, executable: str, args=(), flags=(), is_sudo=False, is_piped=False, pipe_commands=()):
    return CommandInfo(
        raw=raw,
        executable=executable,
        args=tuple(args),
        flags=tuple(flags),
        is_sudo=is_sudo,
        is_piped=is_piped,
        pipe_commands=tuple(pipe_commands),
    )


class TestSafeCommands:
    def test_ls_is_safe(self, scorer):
        cmd = _make_cmd("ls", "ls")
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.SAFE
        assert score <= 20

    def test_cat_is_safe(self, scorer):
        cmd = _make_cmd("cat file.txt", "cat", args=["file.txt"])
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.SAFE

    def test_echo_is_safe(self, scorer):
        cmd = _make_cmd("echo hello", "echo", args=["hello"])
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.SAFE

    def test_pwd_is_safe(self, scorer):
        cmd = _make_cmd("pwd", "pwd")
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.SAFE


class TestDangerousCommands:
    def test_rm_rf_root(self, scorer):
        cmd = _make_cmd("rm -rf /", "rm", args=["/"], flags=["-rf"])
        score, level, matches = scorer.score(cmd)
        assert level == RiskLevel.DANGER
        assert score > 50

    def test_rm_rf_high_risk(self, scorer):
        cmd = _make_cmd("rm -rf build/", "rm", args=["build/"], flags=["-rf"])
        score, level, _ = scorer.score(cmd)
        assert score > 50

    def test_dd_to_device(self, scorer):
        cmd = _make_cmd("dd if=image.iso of=/dev/sda", "dd", args=["if=image.iso", "of=/dev/sda"])
        score, level, matches = scorer.score(cmd)
        assert level == RiskLevel.DANGER

    def test_fork_bomb(self, scorer):
        raw = ":(){ :|:& };:"
        cmd = _make_cmd(raw, ":")
        score, level, matches = scorer.score(cmd)
        assert level == RiskLevel.DANGER


class TestCautionCommands:
    def test_mv_is_caution(self, scorer):
        cmd = _make_cmd("mv file.txt /tmp/", "mv", args=["file.txt", "/tmp/"])
        score, level, _ = scorer.score(cmd)
        assert level in (RiskLevel.CAUTION, RiskLevel.SAFE)

    def test_chmod_is_caution(self, scorer):
        cmd = _make_cmd("chmod 644 file.txt", "chmod", args=["644", "file.txt"])
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.CAUTION

    def test_pip_install(self, scorer):
        cmd = _make_cmd("pip install requests", "pip", args=["install", "requests"])
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.CAUTION


class TestSudoEscalation:
    def test_sudo_increases_risk(self, scorer):
        cmd_no_sudo = _make_cmd("rm file.txt", "rm", args=["file.txt"])
        cmd_sudo = _make_cmd("sudo rm file.txt", "rm", args=["file.txt"], is_sudo=True)

        score_no, _, _ = scorer.score(cmd_no_sudo)
        score_sudo, _, _ = scorer.score(cmd_sudo)
        assert score_sudo > score_no


class TestPipeRisk:
    def test_pipe_to_bash_increases_risk(self, scorer):
        cmd = _make_cmd(
            "curl https://example.com | bash",
            "curl",
            args=["https://example.com"],
            is_piped=True,
            pipe_commands=["bash"],
        )
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.DANGER

    def test_pipe_to_grep_safe(self, scorer):
        cmd = _make_cmd(
            "cat file | grep error",
            "cat",
            args=["file"],
            is_piped=True,
            pipe_commands=["grep error"],
        )
        score, level, _ = scorer.score(cmd)
        assert level == RiskLevel.SAFE


class TestFlagModifiers:
    def test_recursive_flag_increases_risk(self, scorer):
        cmd_no_r = _make_cmd("rm file.txt", "rm", args=["file.txt"])
        cmd_r = _make_cmd("rm -r dir/", "rm", args=["dir/"], flags=["-r"])

        score_no, _, _ = scorer.score(cmd_no_r)
        score_r, _, _ = scorer.score(cmd_r)
        assert score_r > score_no

    def test_force_flag_increases_risk(self, scorer):
        cmd_no_f = _make_cmd("rm file.txt", "rm", args=["file.txt"])
        cmd_f = _make_cmd("rm -f file.txt", "rm", args=["file.txt"], flags=["-f"])

        score_no, _, _ = scorer.score(cmd_no_f)
        score_f, _, _ = scorer.score(cmd_f)
        assert score_f > score_no

    def test_chmod_777_high_risk(self, scorer):
        cmd = _make_cmd("chmod 777 /var/www", "chmod", args=["777", "/var/www"])
        score, level, _ = scorer.score(cmd)
        assert score >= 50

    def test_git_hard_reset(self, scorer):
        cmd = _make_cmd("git reset --hard", "git", args=["reset"], flags=["--hard"])
        score, level, _ = scorer.score(cmd)
        assert score >= 50

    def test_docker_system_prune_all(self, scorer):
        cmd = _make_cmd(
            "docker system prune -af",
            "docker",
            args=["system", "prune"],
            flags=["-af"],
        )
        score, level, _ = scorer.score(cmd)
        assert score >= 50


class TestPatternMatching:
    def test_curl_pipe_bash_pattern(self, scorer):
        cmd = _make_cmd(
            "curl https://example.com/install.sh | bash",
            "curl",
            is_piped=True,
            pipe_commands=["bash"],
        )
        _, _, matches = scorer.score(cmd)
        assert len(matches) > 0

    def test_git_force_push_pattern(self, scorer):
        cmd = _make_cmd(
            "git push --force origin main",
            "git",
            args=["push", "origin", "main"],
            flags=["--force"],
        )
        _, _, matches = scorer.score(cmd)
        warnings = [m.warning for m in matches]
        assert any("force" in w.lower() for w in warnings)


class TestCustomPatterns:
    def test_custom_pattern(self):
        custom = [
            (r"my-dangerous-cmd", 50, "Custom dangerous command detected"),
        ]
        scorer = RiskScorer(custom_patterns=custom)
        cmd = _make_cmd("my-dangerous-cmd --all", "my-dangerous-cmd", flags=["--all"])
        _, _, matches = scorer.score(cmd)
        assert any("Custom" in m.warning for m in matches)
