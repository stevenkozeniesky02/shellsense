"""Tests for the filesystem predictor."""

import os
import tempfile

import pytest

from shellsense.core.models import FileChangeType, RiskLevel
from shellsense.core.parser import CommandParser
from shellsense.core.predictor import FilesystemPredictor


@pytest.fixture
def tmp_workspace(tmp_path):
    """Create a temporary workspace with some test files."""
    (tmp_path / "file1.txt").write_text("hello world")
    (tmp_path / "file2.txt").write_text("goodbye")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "nested.txt").write_text("nested content")
    return tmp_path


@pytest.fixture
def parser():
    return CommandParser()


@pytest.fixture
def predictor(tmp_workspace):
    return FilesystemPredictor(working_dir=str(tmp_workspace))


class TestRmPrediction:
    def test_rm_file(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("rm file1.txt")
        result = predictor.analyze(cmd)

        assert result.risk_level in (RiskLevel.CAUTION, RiskLevel.DANGER)
        assert not result.reversible
        assert len(result.predicted_changes) == 1
        assert result.predicted_changes[0].change_type == FileChangeType.DELETE

    def test_rm_rf_directory(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("rm -rf subdir")
        result = predictor.analyze(cmd)

        assert not result.reversible
        deletes = [c for c in result.predicted_changes if c.change_type == FileChangeType.DELETE]
        assert len(deletes) >= 1

    def test_rm_nonexistent(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("rm nonexistent.txt")
        result = predictor.analyze(cmd)
        assert len(result.predicted_changes) == 1  # still reports as predicted delete

    def test_rm_with_glob(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("rm *.txt")
        result = predictor.analyze(cmd)
        # Should expand glob and find file1.txt and file2.txt
        assert len(result.predicted_changes) >= 2


class TestMvPrediction:
    def test_mv_file(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("mv file1.txt file_renamed.txt")
        result = predictor.analyze(cmd)

        assert result.reversible
        moves = [c for c in result.predicted_changes if c.change_type == FileChangeType.MOVE]
        assert len(moves) == 1

    def test_mv_to_directory(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("mv file1.txt subdir/")
        result = predictor.analyze(cmd)

        moves = [c for c in result.predicted_changes if c.change_type == FileChangeType.MOVE]
        assert len(moves) == 1


class TestCpPrediction:
    def test_cp_file(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("cp file1.txt file_copy.txt")
        result = predictor.analyze(cmd)

        assert result.reversible
        creates = [c for c in result.predicted_changes if c.change_type == FileChangeType.CREATE]
        assert len(creates) == 1

    def test_cp_recursive(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("cp -r subdir subdir_copy")
        result = predictor.analyze(cmd)

        creates = [c for c in result.predicted_changes if c.change_type == FileChangeType.CREATE]
        assert len(creates) >= 1


class TestMkdirPrediction:
    def test_mkdir(self, parser, predictor):
        cmd = parser.parse("mkdir new_dir")
        result = predictor.analyze(cmd)

        assert result.reversible
        creates = [c for c in result.predicted_changes if c.change_type == FileChangeType.CREATE]
        assert len(creates) == 1


class TestTouchPrediction:
    def test_touch_new_file(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("touch new_file.txt")
        result = predictor.analyze(cmd)

        creates = [c for c in result.predicted_changes if c.change_type == FileChangeType.CREATE]
        assert len(creates) == 1

    def test_touch_existing_file(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("touch file1.txt")
        result = predictor.analyze(cmd)

        modifies = [c for c in result.predicted_changes if c.change_type == FileChangeType.MODIFY]
        assert len(modifies) == 1


class TestChmodPrediction:
    def test_chmod(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("chmod 644 file1.txt")
        result = predictor.analyze(cmd)

        perms = [c for c in result.predicted_changes if c.change_type == FileChangeType.PERMISSION]
        assert len(perms) == 1

    def test_chmod_777_warns(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("chmod 777 file1.txt")
        result = predictor.analyze(cmd)

        assert len(result.warnings) > 0


class TestChownPrediction:
    def test_chown(self, parser, predictor, tmp_workspace):
        cmd = parser.parse("chown user:group file1.txt")
        result = predictor.analyze(cmd)

        owns = [c for c in result.predicted_changes if c.change_type == FileChangeType.OWNERSHIP]
        assert len(owns) == 1


class TestGitPrediction:
    def test_git_reset_hard(self, parser, predictor):
        cmd = parser.parse("git reset --hard HEAD~1")
        result = predictor.analyze(cmd)

        assert not result.reversible
        assert result.risk_level == RiskLevel.DANGER

    def test_git_push_force(self, parser, predictor):
        cmd = parser.parse("git push --force origin main")
        result = predictor.analyze(cmd)

        assert not result.reversible
        assert len(result.warnings) > 0

    def test_git_add_safe(self, parser, predictor):
        cmd = parser.parse("git add .")
        result = predictor.analyze(cmd)
        assert result.reversible


class TestDryRunDetection:
    def test_rsync_dry_run_available(self, parser, predictor):
        cmd = parser.parse("rsync -av src/ dest/")
        result = predictor.analyze(cmd)

        assert result.dry_run_available
        assert result.dry_run_command is not None
        assert "--dry-run" in result.dry_run_command

    def test_kubectl_apply_dry_run(self, parser, predictor):
        cmd = parser.parse("kubectl apply -f manifest.yaml")
        result = predictor.analyze(cmd)

        assert result.dry_run_available
        assert "--dry-run" in result.dry_run_command

    def test_kubectl_delete_dry_run(self, parser, predictor):
        cmd = parser.parse("kubectl delete pod my-pod")
        result = predictor.analyze(cmd)

        assert result.dry_run_available


class TestDockerPrediction:
    def test_docker_system_prune(self, parser, predictor):
        cmd = parser.parse("docker system prune -a")
        result = predictor.analyze(cmd)

        assert not result.reversible

    def test_docker_run(self, parser, predictor):
        cmd = parser.parse("docker run -d nginx")
        result = predictor.analyze(cmd)
        assert result.reversible


class TestBrewPrediction:
    def test_brew_install(self, parser, predictor):
        cmd = parser.parse("brew install wget")
        result = predictor.analyze(cmd)
        assert result.reversible

    def test_brew_uninstall(self, parser, predictor):
        cmd = parser.parse("brew uninstall wget")
        result = predictor.analyze(cmd)
        assert result.reversible


class TestAptPrediction:
    def test_apt_install_dry_run(self, parser, predictor):
        cmd = parser.parse("apt install nginx")
        result = predictor.analyze(cmd)
        assert result.dry_run_available

    def test_apt_remove(self, parser, predictor):
        cmd = parser.parse("apt remove nginx")
        result = predictor.analyze(cmd)
        assert result.dry_run_available


class TestSystemctlPrediction:
    def test_systemctl_stop(self, parser, predictor):
        cmd = parser.parse("systemctl stop nginx")
        result = predictor.analyze(cmd)
        assert result.reversible
        assert "start" in result.reversibility_note


class TestPipPrediction:
    def test_pip_install(self, parser, predictor):
        cmd = parser.parse("pip install requests")
        result = predictor.analyze(cmd)
        assert result.reversible
