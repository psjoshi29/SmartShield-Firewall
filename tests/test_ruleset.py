"""Unit tests for RuleSet collection management."""

import pytest

from smartshield.engine.models import Action, Direction, Protocol, Rule
from smartshield.engine.ruleset import RuleSet
from smartshield.engine.validator import RuleValidationError


def make_sample_rule(rule_id: str, priority: int = 100) -> Rule:
    return Rule(
        id=rule_id,
        name=f"Sample {rule_id}",
        description="Testing ruleset",
        priority=priority,
        enabled=True,
        src_ip="*",
        dst_ip="*",
        src_ports="*",
        dst_ports="80",
        protocol=Protocol.TCP,
        direction=Direction.OUTBOUND,
        action=Action.ALLOW,
    )


class TestRuleSet:
    """Test RuleSet manipulation and error checks."""

    def test_duplicate_id_rejected(self):
        rs = RuleSet()
        rs.add_rule(make_sample_rule("RULE-1", priority=10))
        with pytest.raises(RuleValidationError):
            rs.add_rule(make_sample_rule("RULE-1", priority=20))

    def test_priority_sorting(self):
        rs = RuleSet()
        rs.add_rule(make_sample_rule("RULE-LOW", priority=200))
        rs.add_rule(make_sample_rule("RULE-HIGH", priority=10))
        rs.add_rule(make_sample_rule("RULE-MED", priority=50))

        ordered = [r.id for r in rs.rules]
        assert ordered == ["RULE-HIGH", "RULE-MED", "RULE-LOW"]

    def test_update_rule(self):
        rs = RuleSet([make_sample_rule("RULE-1", priority=50)])
        updated = make_sample_rule("RULE-1", priority=10)
        updated.name = "Renamed Rule"
        rs.update_rule("RULE-1", updated)

        rule = rs.get_rule("RULE-1")
        assert rule is not None
        assert rule.priority == 10
        assert rule.name == "Renamed Rule"

    def test_delete_rule(self):
        rs = RuleSet([make_sample_rule("RULE-1"), make_sample_rule("RULE-2")])
        assert rs.delete_rule("RULE-1") is True
        assert rs.get_rule("RULE-1") is None
        assert rs.delete_rule("RULE-NONEXISTENT") is False

    def test_toggle_rule(self):
        rs = RuleSet([make_sample_rule("RULE-1")])
        assert rs.toggle_rule("RULE-1") is False
        assert rs.get_rule("RULE-1").enabled is False
        assert rs.toggle_rule("RULE-1") is True
        assert rs.get_rule("RULE-1").enabled is True

    def test_reorder_rules(self):
        rs = RuleSet([
            make_sample_rule("RULE-A", 10),
            make_sample_rule("RULE-B", 20),
            make_sample_rule("RULE-C", 30),
        ])
        rs.reorder_rules(["RULE-C", "RULE-A", "RULE-B"])
        assert [r.id for r in rs.rules] == ["RULE-C", "RULE-A", "RULE-B"]
        assert rs.get_rule("RULE-C").priority == 10
        assert rs.get_rule("RULE-A").priority == 20
        assert rs.get_rule("RULE-B").priority == 30

    def test_to_and_from_dict(self):
        rs = RuleSet([make_sample_rule("RULE-1", 10)], default_action=Action.BLOCK)
        serialized = rs.to_dict()
        assert serialized["default_action"] == "BLOCK"
        assert len(serialized["rules"]) == 1

        restored = RuleSet.from_dict(serialized)
        assert restored.default_action == Action.BLOCK
        assert len(restored.rules) == 1
        assert restored.rules[0].id == "RULE-1"
