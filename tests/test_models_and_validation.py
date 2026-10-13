"""Unit tests for models, IP/CIDR validation, and port boundaries."""

import pytest

from smartshield.engine.models import (
    Action,
    Direction,
    IPPattern,
    Packet,
    PortRange,
    Protocol,
    Rule,
)
from smartshield.engine.validator import (
    PacketValidationError,
    RuleValidationError,
    validate_action,
    validate_direction,
    validate_ip_pattern,
    validate_ipv4_address,
    validate_packet,
    validate_port_number,
    validate_port_range,
    validate_protocol,
    validate_rule,
)


class TestIPValidation:
    """Test IPv4 single host and CIDR subnet validation."""

    def test_valid_ipv4_addresses(self):
        assert validate_ipv4_address("192.168.1.1") == "192.168.1.1"
        assert validate_ipv4_address("10.0.0.1") == "10.0.0.1"
        assert validate_ipv4_address("172.16.254.1") == "172.16.254.1"
        assert validate_ipv4_address("255.255.255.255") == "255.255.255.255"
        assert validate_ipv4_address("0.0.0.0") == "0.0.0.0"

    def test_invalid_ipv4_addresses(self):
        with pytest.raises(PacketValidationError):
            validate_ipv4_address("256.0.0.1")
        with pytest.raises(PacketValidationError):
            validate_ipv4_address("192.168.1")
        with pytest.raises(PacketValidationError):
            validate_ipv4_address("192.168.1.1.1")
        with pytest.raises(PacketValidationError):
            validate_ipv4_address("not.an.ip.address")
        with pytest.raises(PacketValidationError):
            validate_ipv4_address("")

    def test_cidr_pattern_parsing_and_matching(self):
        pat = validate_ip_pattern("192.168.1.0/24")
        assert not pat.is_wildcard
        assert pat.matches("192.168.1.1")
        assert pat.matches("192.168.1.254")
        assert not pat.matches("192.168.2.1")
        assert not pat.matches("10.0.0.1")

    def test_wildcard_ip_patterns(self):
        for wildcard in ["*", "ANY", "any", "0.0.0.0/0"]:
            pat = validate_ip_pattern(wildcard)
            assert pat.is_wildcard
            assert pat.matches("1.2.3.4")
            assert pat.matches("192.168.100.200")

    def test_invalid_cidr_prefix(self):
        with pytest.raises(RuleValidationError):
            validate_ip_pattern("192.168.1.0/33")
        with pytest.raises(RuleValidationError):
            validate_ip_pattern("192.168.1.0/-1")
        with pytest.raises(RuleValidationError):
            validate_ip_pattern("192.168.1.0/abc")


class TestPortValidation:
    """Test TCP/UDP port boundary checks and range parsing."""

    def test_valid_single_port_numbers(self):
        assert validate_port_number(1) == 1
        assert validate_port_number(80) == 80
        assert validate_port_number(443) == 443
        assert validate_port_number(65535) == 65535

    def test_invalid_port_numbers(self):
        with pytest.raises(PacketValidationError):
            validate_port_number(0, allow_zero=False)
        with pytest.raises(PacketValidationError):
            validate_port_number(-1)
        with pytest.raises(PacketValidationError):
            validate_port_number(65536)
        with pytest.raises(PacketValidationError):
            validate_port_number("invalid")

    def test_port_ranges(self):
        pr = validate_port_range("80-443")
        assert not pr.is_wildcard
        assert pr.matches(80)
        assert pr.matches(443)
        assert pr.matches(8080) is False

        pr_list = validate_port_range("80, 443, 8080")
        assert pr_list.matches(80)
        assert pr_list.matches(443)
        assert pr_list.matches(8080)
        assert not pr_list.matches(22)

    def test_wildcard_port(self):
        pr = validate_port_range("*")
        assert pr.is_wildcard
        assert pr.matches(80)
        assert pr.matches(65535)

    def test_inverted_port_range(self):
        with pytest.raises(RuleValidationError):
            validate_port_range("443-80")

    def test_out_of_bound_range(self):
        with pytest.raises(RuleValidationError):
            validate_port_range("80-70000")


class TestProtocolDirectionActionValidation:
    """Test transport protocols, directions, and action enums."""

    def test_protocols(self):
        assert validate_protocol("TCP") == Protocol.TCP
        assert validate_protocol("udp") == Protocol.UDP
        assert validate_protocol("ICMP") == Protocol.ICMP
        assert validate_protocol("*") == Protocol.ANY
        with pytest.raises(RuleValidationError):
            validate_protocol("SCTP_UNKNOWN")

    def test_directions(self):
        assert validate_direction("INBOUND") == Direction.INBOUND
        assert validate_direction("outbound") == Direction.OUTBOUND
        assert validate_direction("*") == Direction.ANY
        with pytest.raises(RuleValidationError):
            validate_direction("INTERNAL_ONLY")

    def test_actions(self):
        assert validate_action("ALLOW") == Action.ALLOW
        assert validate_action("block") == Action.BLOCK
        assert validate_action("DENY") == Action.BLOCK
        assert validate_action("PASS") == Action.ALLOW
        with pytest.raises(RuleValidationError):
            validate_action("UNKNOWN_ACTION")


class TestPacketAndRuleValidation:
    """Test Packet and Rule structural integrity."""

    def test_valid_packet(self):
        pkt = validate_packet({
            "src_ip": "192.168.1.50",
            "dst_ip": "1.1.1.1",
            "src_port": 50000,
            "dst_port": 53,
            "protocol": "UDP",
            "direction": "OUTBOUND",
        })
        assert pkt.src_ip == "192.168.1.50"
        assert pkt.dst_port == 53
        assert pkt.protocol == Protocol.UDP

    def test_valid_rule(self):
        rule = validate_rule({
            "id": "RULE-TEST-01",
            "name": "Test Allow Web",
            "priority": 50,
            "enabled": True,
            "src_ip": "10.0.0.0/8",
            "dst_ip": "*",
            "src_ports": "*",
            "dst_ports": "80,443",
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "action": "ALLOW",
        })
        assert rule.id == "RULE-TEST-01"
        assert rule.priority == 50
        assert rule.action == Action.ALLOW

    def test_invalid_rule_id(self):
        with pytest.raises(RuleValidationError):
            validate_rule({
                "id": "RULE WITH SPACES!",
                "name": "Invalid ID",
            })

    def test_invalid_rule_priority(self):
        with pytest.raises(RuleValidationError):
            validate_rule({
                "id": "RULE-01",
                "name": "Bad Priority",
                "priority": 1001,
            })
