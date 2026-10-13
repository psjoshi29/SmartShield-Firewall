"""Unit tests for the firewall rule evaluator engine."""

from smartshield.engine.evaluator import evaluate_packet
from smartshield.engine.models import Action, Direction, Packet, Protocol, Rule
from smartshield.engine.ruleset import RuleSet


class TestEvaluator:
    """Test deterministic packet evaluation and edge cases."""

    def test_first_match_priority_behavior(self):
        # Rule 1: Priority 10 -> BLOCK port 80
        rule1 = Rule(
            id="R-BLOCK-80",
            name="Block Port 80",
            description="High priority block",
            priority=10,
            enabled=True,
            src_ip="*",
            dst_ip="*",
            src_ports="*",
            dst_ports="80",
            protocol=Protocol.TCP,
            direction=Direction.OUTBOUND,
            action=Action.BLOCK,
        )
        # Rule 2: Priority 20 -> ALLOW all web ports 80,443
        rule2 = Rule(
            id="R-ALLOW-WEB",
            name="Allow Web Ports",
            description="Lower priority allow",
            priority=20,
            enabled=True,
            src_ip="*",
            dst_ip="*",
            src_ports="*",
            dst_ports="80,443",
            protocol=Protocol.TCP,
            direction=Direction.OUTBOUND,
            action=Action.ALLOW,
        )

        ruleset = RuleSet([rule2, rule1])  # Added out of order; ruleset sorts by priority

        pkt = Packet(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=52341,
            dst_port=80,
            protocol=Protocol.TCP,
            direction=Direction.OUTBOUND,
        )

        decision = evaluate_packet(pkt, ruleset)
        assert decision.action == Action.BLOCK
        assert decision.rule_id == "R-BLOCK-80"
        assert decision.matched is True

    def test_disabled_rules_are_skipped(self):
        rule = Rule(
            id="R-DISABLED",
            name="Disabled Rule",
            description="Should not trigger",
            priority=5,
            enabled=False,
            src_ip="*",
            dst_ip="*",
            src_ports="*",
            dst_ports="443",
            protocol=Protocol.TCP,
            direction=Direction.OUTBOUND,
            action=Action.BLOCK,
        )
        ruleset = RuleSet([rule], default_action=Action.ALLOW)

        pkt = Packet(
            src_ip="192.168.1.50",
            dst_ip="1.1.1.1",
            src_port=50000,
            dst_port=443,
            protocol=Protocol.TCP,
            direction=Direction.OUTBOUND,
        )

        decision = evaluate_packet(pkt, ruleset)
        assert decision.action == Action.ALLOW
        assert decision.matched is False
        assert decision.rule_name == "DEFAULT_POLICY"

    def test_cidr_subnet_matching(self):
        rule = Rule(
            id="R-CORP-SSH",
            name="Allow Corp SSH",
            description="Subnet allow",
            priority=50,
            enabled=True,
            src_ip="10.50.0.0/16",
            dst_ip="192.168.1.10",
            src_ports="*",
            dst_ports="22",
            protocol=Protocol.TCP,
            direction=Direction.INBOUND,
            action=Action.ALLOW,
        )
        ruleset = RuleSet([rule], default_action=Action.BLOCK)

        # In-subnet packet
        pkt_allowed = Packet(
            src_ip="10.50.2.14",
            dst_ip="192.168.1.10",
            src_port=49210,
            dst_port=22,
            protocol=Protocol.TCP,
            direction=Direction.INBOUND,
        )
        dec_allow = evaluate_packet(pkt_allowed, ruleset)
        assert dec_allow.action == Action.ALLOW
        assert dec_allow.rule_id == "R-CORP-SSH"

        # Out-of-subnet packet
        pkt_blocked = Packet(
            src_ip="10.51.2.14",
            dst_ip="192.168.1.10",
            src_port=49210,
            dst_port=22,
            protocol=Protocol.TCP,
            direction=Direction.INBOUND,
        )
        dec_block = evaluate_packet(pkt_blocked, ruleset)
        assert dec_block.action == Action.BLOCK
        assert dec_block.matched is False

    def test_default_deny_when_no_rules_match(self):
        ruleset = RuleSet([], default_action=Action.BLOCK)
        pkt = Packet(
            src_ip="8.8.8.8",
            dst_ip="192.168.1.10",
            src_port=53,
            dst_port=53,
            protocol=Protocol.UDP,
            direction=Direction.INBOUND,
        )
        decision = evaluate_packet(pkt, ruleset)
        assert decision.action == Action.BLOCK
        assert decision.matched is False
        assert "default firewall policy: BLOCK" in decision.reason

    def test_configured_default_allow(self):
        ruleset = RuleSet([], default_action=Action.ALLOW)
        pkt = Packet(
            src_ip="1.1.1.1",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=80,
            protocol=Protocol.TCP,
            direction=Direction.INBOUND,
        )
        decision = evaluate_packet(pkt, ruleset)
        assert decision.action == Action.ALLOW
        assert decision.matched is False
        assert "default firewall policy: ALLOW" in decision.reason

    def test_malformed_packet_safely_blocked_with_trace(self):
        ruleset = RuleSet([], default_action=Action.ALLOW)
        # Invalid packet with bad IP
        malformed = {
            "src_ip": "999.999.999.999",
            "dst_ip": "192.168.1.1",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": "TCP",
            "direction": "INBOUND",
        }
        decision = evaluate_packet(malformed, ruleset)  # type: ignore
        assert decision.action == Action.BLOCK
        assert decision.rule_name == "INTEGRITY_CHECK_FAILED"
        assert len(decision.steps) == 1
        assert "Header Integrity Checker" in decision.steps[0].rule_name
