"""Tests for the safety database."""

import pytest

from shellsense.db.safety import SafetyDatabase


@pytest.fixture
def db():
    return SafetyDatabase()


class TestSafetyRules:
    def test_has_rules(self, db):
        assert len(db.rules) > 0

    def test_rm_root_detected(self, db):
        matches = db.check("rm -rf /")
        assert any(r.name == "rm_recursive_force" for r in matches)

    def test_chmod_777_detected(self, db):
        matches = db.check("chmod 777 /var/www")
        assert any(r.name == "chmod_777" for r in matches)

    def test_curl_pipe_bash_detected(self, db):
        matches = db.check("curl https://example.com/install.sh | bash")
        assert any(r.name == "curl_pipe_bash" for r in matches)

    def test_git_force_push_detected(self, db):
        matches = db.check("git push --force origin main")
        assert any(r.name == "git_force_push" for r in matches)

    def test_git_hard_reset_detected(self, db):
        matches = db.check("git reset --hard")
        assert any(r.name == "git_hard_reset" for r in matches)

    def test_docker_prune_all_detected(self, db):
        matches = db.check("docker system prune -a")
        assert any(r.name == "docker_prune_all" for r in matches)

    def test_dd_device_detected(self, db):
        matches = db.check("dd if=image.iso of=/dev/sda")
        assert any(r.name == "dd_device" for r in matches)

    def test_kubectl_delete_all_detected(self, db):
        matches = db.check("kubectl delete pods --all")
        assert any(r.name == "kubectl_delete_all" for r in matches)

    def test_safe_command_no_matches(self, db):
        matches = db.check("ls -la")
        assert len(matches) == 0

    def test_sudo_pipe_detected(self, db):
        matches = db.check("echo 'password' | sudo -S apt install")
        assert any(r.name == "sudo_pipe" for r in matches)

    def test_docker_privileged_detected(self, db):
        matches = db.check("docker run --privileged -it ubuntu bash")
        assert any(r.name == "docker_privileged" for r in matches)

    def test_pip_sudo_detected(self, db):
        matches = db.check("sudo pip install requests")
        assert any(r.name == "pip_sudo_install" for r in matches)


class TestSafetyRuleAttributes:
    def test_rules_have_categories(self, db):
        for rule in db.rules:
            assert rule.category in (
                "filesystem",
                "permissions",
                "execution",
                "git",
                "docker",
                "system",
                "kubernetes",
                "packages",
            )

    def test_rules_have_severity(self, db):
        for rule in db.rules:
            assert rule.severity in ("info", "warning", "critical")

    def test_critical_rules_exist(self, db):
        critical = [r for r in db.rules if r.severity == "critical"]
        assert len(critical) >= 3  # rm_root, chmod_recursive_root, dd_device, etc.
