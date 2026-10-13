"""Unit tests for configuration persistence and recovery."""

import json

from smartshield.engine.models import Action
from smartshield.storage.config import ConfigManager


class TestConfigPersistence:
    """Test configuration saving, loading, corruption recovery, and atomic replacement."""

    def test_save_and_load_roundtrip(self, tmp_path):
        cfg_file = tmp_path / "firewall_rules.json"
        mgr = ConfigManager(cfg_file)

        ruleset = mgr.create_default_ruleset()
        ruleset.set_default_action(Action.ALLOW)
        mgr.save_ruleset(ruleset)

        assert cfg_file.exists()
        loaded = mgr.load_ruleset()
        assert loaded.default_action == Action.ALLOW
        assert len(loaded.rules) == len(ruleset.rules)
        assert loaded.rules[0].id == ruleset.rules[0].id

    def test_missing_file_generates_default_config(self, tmp_path):
        cfg_file = tmp_path / "non_existent.json"
        mgr = ConfigManager(cfg_file)

        loaded = mgr.load_ruleset()
        assert loaded.default_action == Action.BLOCK
        assert len(loaded.rules) > 0
        assert cfg_file.exists()  # Persisted automatically

    def test_corrupted_json_recovers_gracefully(self, tmp_path):
        cfg_file = tmp_path / "corrupt.json"
        with open(cfg_file, "w", encoding="utf-8") as f:
            f.write("{{ MALFORMED JSON !!!")

        mgr = ConfigManager(cfg_file)
        loaded = mgr.load_ruleset()
        # Should gracefully return default ruleset without raising exception
        assert loaded.default_action == Action.BLOCK
        assert len(loaded.rules) > 0
