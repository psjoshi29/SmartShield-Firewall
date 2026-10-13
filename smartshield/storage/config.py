"""Configuration persistence: atomic JSON storage and integrity validation."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from smartshield.engine.models import Action, Rule
from smartshield.engine.ruleset import RuleSet
from smartshield.engine.validator import RuleValidationError, validate_rule

logger = logging.getLogger(__name__)

DEFAULT_RULES_SEED: List[Dict[str, Any]] = [
    {
        "id": "RULE-001",
        "name": "Block Inbound Telnet",
        "description": "Drop unencrypted legacy Telnet management traffic from all WAN sources.",
        "priority": 10,
        "enabled": True,
        "src_ip": "*",
        "dst_ip": "*",
        "src_ports": "*",
        "dst_ports": "23",
        "protocol": "TCP",
        "direction": "INBOUND",
        "action": "BLOCK",
    },
    {
        "id": "RULE-002",
        "name": "Block Inbound SMB & NetBIOS",
        "description": "Prevent ransomware and worm lateral spread via SMB port 445.",
        "priority": 20,
        "enabled": True,
        "src_ip": "*",
        "dst_ip": "*",
        "src_ports": "*",
        "dst_ports": "445,137,138,139",
        "protocol": "TCP",
        "direction": "INBOUND",
        "action": "BLOCK",
    },
    {
        "id": "RULE-003",
        "name": "Block Inbound RDP from Internet",
        "description": "Block remote desktop brute-force access attempts.",
        "priority": 30,
        "enabled": True,
        "src_ip": "*",
        "dst_ip": "*",
        "src_ports": "*",
        "dst_ports": "3389",
        "protocol": "TCP",
        "direction": "INBOUND",
        "action": "BLOCK",
    },
    {
        "id": "RULE-004",
        "name": "Allow Outbound HTTPS & HTTP",
        "description": "Permit internal workstation egress web browsing to public web servers.",
        "priority": 100,
        "enabled": True,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "*",
        "src_ports": "1024-65535",
        "dst_ports": "80,443",
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "action": "ALLOW",
    },
    {
        "id": "RULE-005",
        "name": "Allow Outbound DNS Queries",
        "description": "Permit internal DNS name resolution to public/corporate resolvers.",
        "priority": 110,
        "enabled": True,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "*",
        "src_ports": "1024-65535",
        "dst_ports": "53",
        "protocol": "UDP",
        "direction": "OUTBOUND",
        "action": "ALLOW",
    },
    {
        "id": "RULE-006",
        "name": "Allow Admin Subnet Inbound SSH",
        "description": "Authorize internal network administration access via secure SSH.",
        "priority": 120,
        "enabled": True,
        "src_ip": "10.0.0.0/16",
        "dst_ip": "192.168.1.10",
        "src_ports": "*",
        "dst_ports": "22",
        "protocol": "TCP",
        "direction": "INBOUND",
        "action": "ALLOW",
    },
    {
        "id": "RULE-007",
        "name": "Allow Outbound NTP Time Sync",
        "description": "Permit host network time protocol synchronization.",
        "priority": 130,
        "enabled": True,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "*",
        "src_ports": "1024-65535",
        "dst_ports": "123",
        "protocol": "UDP",
        "direction": "OUTBOUND",
        "action": "ALLOW",
    },
]


class ConfigManager:
    """Safely manages configuration persistence with atomic updates."""

    def __init__(self, config_path: Path | str) -> None:
        self.config_path = Path(config_path).resolve()
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

    def load_ruleset(self) -> RuleSet:
        """Load and validate ruleset from JSON config file. Fall back to defaults on missing/corrupt."""
        if not self.config_path.exists():
            logger.info("Configuration file not found. Generating default seed ruleset at %s", self.config_path)
            ruleset = self.create_default_ruleset()
            self.save_ruleset(ruleset)
            return ruleset

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self._parse_and_validate_data(data)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.error("Failed to parse config file %s: %s. Using default fallback.", self.config_path, exc)
            fallback = self.create_default_ruleset()
            return fallback

    def save_ruleset(self, ruleset: RuleSet) -> None:
        """Atomically persist ruleset to disk using a temporary file and atomic replace."""
        data = ruleset.to_dict()
        parent_dir = self.config_path.parent
        parent_dir.mkdir(parents=True, exist_ok=True)

        # Atomic write pattern: create temp in same dir, flush, sync, replace
        temp_fd, temp_path = tempfile.mkstemp(prefix="smartshield_cfg_", suffix=".tmp", dir=str(parent_dir))
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, str(self.config_path))
        except Exception:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise

    def create_default_ruleset(self) -> RuleSet:
        """Instantiate seed default ruleset with strict default-deny (BLOCK) policy."""
        rules = [Rule.from_dict(d) for d in DEFAULT_RULES_SEED]
        return RuleSet(rules=rules, default_action=Action.BLOCK)

    def _parse_and_validate_data(self, data: Dict[str, Any]) -> RuleSet:
        """Validate deserialized dictionary and return validated RuleSet."""
        if not isinstance(data, dict):
            raise ValueError("Root configuration must be a JSON dictionary.")

        default_act_str = data.get("default_action", "BLOCK")
        default_act = Action.from_str(str(default_act_str))

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError("'rules' field must be a list.")

        validated_rules: List[Rule] = []
        for r_item in raw_rules:
            if not isinstance(r_item, dict):
                continue
            try:
                rule_obj = Rule.from_dict(r_item)
                validated_rules.append(rule_obj)
            except Exception as e:
                logger.warning("Skipping invalid rule definition in config: %s (%s)", r_item, e)

        return RuleSet(rules=validated_rules, default_action=default_act)
