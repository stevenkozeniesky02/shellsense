"""Tests for history storage."""

import os

import pytest

from shellsense.core.models import RiskLevel
from shellsense.db.config import Config
from shellsense.db.history import HistoryStore


@pytest.fixture
def history_store(tmp_path):
    config = Config(history_file=str(tmp_path / "history.jsonl"))
    return HistoryStore(config)


class TestHistoryRecording:
    def test_record_entry(self, history_store):
        entry = history_store.record(
            command="ls -la",
            risk_level=RiskLevel.SAFE,
            risk_score=0,
        )
        assert entry.command == "ls -la"
        assert entry.risk_level == "safe"

    def test_load_entries(self, history_store):
        history_store.record(command="ls", risk_level=RiskLevel.SAFE, risk_score=0)
        history_store.record(command="rm -rf /", risk_level=RiskLevel.DANGER, risk_score=90)

        entries = history_store.load()
        assert len(entries) == 2
        # Most recent first
        assert entries[0].command == "rm -rf /"

    def test_load_with_limit(self, history_store):
        for i in range(10):
            history_store.record(
                command=f"cmd{i}",
                risk_level=RiskLevel.SAFE,
                risk_score=0,
            )

        entries = history_store.load(limit=3)
        assert len(entries) == 3

    def test_empty_history(self, history_store):
        entries = history_store.load()
        assert entries == []


class TestHistoryTrimming:
    def test_trim_at_max(self, tmp_path):
        config = Config(
            history_file=str(tmp_path / "history.jsonl"),
            max_history=5,
        )
        store = HistoryStore(config)

        for i in range(10):
            store.record(command=f"cmd{i}", risk_level=RiskLevel.SAFE, risk_score=0)

        entries = store.load()
        assert len(entries) <= 5
