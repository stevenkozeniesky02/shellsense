"""Tests for configuration management."""

import os
import tempfile

import pytest

from shellsense.db.config import Config


class TestDefaultConfig:
    def test_default_values(self):
        config = Config()
        assert config.risk_threshold_caution == 20
        assert config.risk_threshold_danger == 50
        assert config.auto_block_danger is False
        assert config.allowlist == ()
        assert config.blocklist == ()
        assert config.max_history == 1000

    def test_load_nonexistent_returns_defaults(self):
        config = Config.load("/nonexistent/path/config.toml")
        assert config.risk_threshold_caution == 20


class TestTomlConfig:
    def test_load_config(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("""\
[general]
risk_threshold_caution = 30
risk_threshold_danger = 60
auto_block_danger = true
allowlist = ["ls", "cat"]
blocklist = ["rm -rf /"]
max_history = 500

[[patterns.dangerous]]
regex = "my-cmd.*"
score = 40
warning = "Custom warning"
""")
        config = Config.load(str(config_file))
        assert config.risk_threshold_caution == 30
        assert config.risk_threshold_danger == 60
        assert config.auto_block_danger is True
        assert "ls" in config.allowlist
        assert "cat" in config.allowlist
        assert config.max_history == 500
        assert len(config.custom_patterns) == 1
        assert config.custom_patterns[0] == ("my-cmd.*", 40, "Custom warning")

    def test_partial_config(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("""\
[general]
auto_block_danger = true
""")
        config = Config.load(str(config_file))
        assert config.auto_block_danger is True
        assert config.risk_threshold_caution == 20  # default


class TestConfigDir:
    def test_ensure_config_dir(self, tmp_path, monkeypatch):
        import shellsense.db.config as cfg_module

        test_dir = str(tmp_path / ".shellsense")
        monkeypatch.setattr(cfg_module, "DEFAULT_CONFIG_DIR", test_dir)

        result = Config.ensure_config_dir()
        assert os.path.isdir(test_dir)
