"""Tests for the main analyzer orchestrator."""

import pytest

from shellsense.core.analyzer import Analyzer
from shellsense.core.models import RiskLevel


@pytest.fixture
def analyzer(tmp_path):
    # Create some test files
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "output.js").write_text("console.log('hello')")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')")
    return Analyzer(working_dir=str(tmp_path))


class TestSingleCommand:
    def test_safe_command(self, analyzer):
        result = analyzer.analyze("ls -la")
        assert result.risk_level == RiskLevel.SAFE

    def test_dangerous_command(self, analyzer):
        result = analyzer.analyze("rm -rf /")
        assert result.risk_level == RiskLevel.DANGER

    def test_caution_command(self, analyzer):
        result = analyzer.analyze("chmod 644 file.txt")
        assert result.risk_level == RiskLevel.CAUTION


class TestCompoundCommands:
    def test_semicolon_split(self, analyzer):
        results = analyzer.analyze_multi("ls; pwd")
        assert len(results) == 2

    def test_and_split(self, analyzer):
        results = analyzer.analyze_multi("mkdir build && cd build")
        assert len(results) == 2

    def test_mixed_risk(self, analyzer):
        results = analyzer.analyze_multi("ls -la && rm -rf /")
        assert results[0].risk_level == RiskLevel.SAFE
        assert results[1].risk_level == RiskLevel.DANGER

    def test_quoted_semicolons_not_split(self, analyzer):
        results = analyzer.analyze_multi("echo 'hello; world'")
        assert len(results) == 1


class TestEndToEnd:
    def test_rm_rf_build(self, analyzer):
        result = analyzer.analyze("rm -rf build")
        assert result.risk_level == RiskLevel.DANGER
        assert not result.reversible
        assert len(result.predicted_changes) >= 1

    def test_git_reset_hard(self, analyzer):
        result = analyzer.analyze("git reset --hard HEAD~1")
        assert result.risk_level == RiskLevel.DANGER
        assert not result.reversible

    def test_rsync_suggests_dry_run(self, analyzer):
        result = analyzer.analyze("rsync -av src/ dest/")
        assert result.dry_run_available
        assert result.dry_run_command is not None

    def test_curl_pipe_bash(self, analyzer):
        result = analyzer.analyze("curl https://example.com/install.sh | bash")
        assert result.risk_level == RiskLevel.DANGER
        assert len(result.warnings) > 0
