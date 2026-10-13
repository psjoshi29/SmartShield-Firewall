"""Strict input validation for IP addresses, CIDR blocks, ports, protocols, and rules."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Union

from smartshield.engine.models import (
    Action,
    Direction,
    IPPattern,
    Packet,
    PortRange,
    Protocol,
    Rule,
)


class RuleValidationError(ValueError):
    """Raised when firewall rule configuration violates validation constraints."""
    pass


class PacketValidationError(ValueError):
    """Raised when an inspected or synthetic packet fails network sanity checks."""
    pass


_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def validate_ipv4_address(ip_str: str) -> str:
    """Validate a strict single IPv4 address (host address, no CIDR prefix)."""
    if not isinstance(ip_str, str):
        raise PacketValidationError(f"IP address must be a string, got {type(ip_str).__name__}")
    
    clean_ip = ip_str.strip()
    if not clean_ip:
        raise PacketValidationError("IP address cannot be empty.")

    match = _IPV4_RE.match(clean_ip)
    if not match:
        raise PacketValidationError(f"Invalid IPv4 format: '{clean_ip}'. Must be 4 dot-separated octets.")

    for octet_str in match.groups():
        val = int(octet_str)
        if not (0 <= val <= 255):
            raise PacketValidationError(f"Octet '{octet_str}' out of range (0-255) in IP '{clean_ip}'.")

    try:
        addr = ipaddress.IPv4Address(clean_ip)
        return str(addr)
    except ValueError as exc:
        raise PacketValidationError(f"Invalid IPv4 address '{clean_ip}': {exc}") from exc


def validate_ip_pattern(pattern_str: str) -> IPPattern:
    """Validate an IP rule matching pattern: single IP, CIDR subnet, or wildcard ('*' or 'ANY')."""
    if not isinstance(pattern_str, str):
        raise RuleValidationError(f"IP pattern must be a string, got {type(pattern_str).__name__}")
    
    clean = pattern_str.strip()
    if not clean:
        raise RuleValidationError("IP pattern cannot be empty (use '*' for any).")

    if clean.upper() in ("*", "ANY", "0.0.0.0/0"):
        return IPPattern.parse(clean)

    # Check for CIDR mask
    if "/" in clean:
        parts = clean.split("/")
        if len(parts) != 2:
            raise RuleValidationError(f"Invalid CIDR notation '{clean}'.")
        ip_part, prefix_part = parts[0].strip(), parts[1].strip()
        try:
            prefix = int(prefix_part)
            if not (0 <= prefix <= 32):
                raise RuleValidationError(f"CIDR prefix '/{prefix}' out of range (0-32) in '{clean}'.")
        except ValueError as exc:
            raise RuleValidationError(f"Non-numeric CIDR prefix in '{clean}': {exc}") from exc

        try:
            # Validate IP part
            ipaddress.IPv4Address(ip_part)
            return IPPattern.parse(clean)
        except ValueError as exc:
            raise RuleValidationError(f"Malformed IP base in CIDR '{clean}': {exc}") from exc

    # Single host IP
    try:
        validate_ipv4_address(clean)
        return IPPattern.parse(clean)
    except PacketValidationError as exc:
        raise RuleValidationError(f"Invalid IP address pattern '{clean}': {exc}") from exc


def validate_port_number(port: Union[int, str], allow_zero: bool = False) -> int:
    """Validate a single network port number (1-65535, optionally 0 for ICMP/any)."""
    try:
        val = int(str(port).strip())
    except (ValueError, TypeError) as exc:
        raise PacketValidationError(f"Invalid port value '{port}': must be an integer.") from exc

    min_port = 0 if allow_zero else 1
    if not (min_port <= val <= 65535):
        raise PacketValidationError(f"Port '{val}' out of valid range ({min_port}-65535).")
    return val


def validate_port_range(port_spec: Union[str, int]) -> PortRange:
    """Validate a port rule specification: single port, ranges (e.g. 80-443), comma list, or '*'."""
    spec_str = str(port_spec).strip()
    if not spec_str:
        raise RuleValidationError("Port pattern cannot be empty (use '*' for any).")

    try:
        return PortRange.parse(spec_str)
    except ValueError as exc:
        raise RuleValidationError(str(exc)) from exc


def validate_protocol(proto: Union[str, Protocol]) -> Protocol:
    """Validate transport protocol."""
    if isinstance(proto, Protocol):
        return proto
    try:
        return Protocol.from_str(str(proto))
    except ValueError as exc:
        raise RuleValidationError(str(exc)) from exc


def validate_direction(direction: Union[str, Direction]) -> Direction:
    """Validate traffic direction."""
    if isinstance(direction, Direction):
        return direction
    try:
        return Direction.from_str(str(direction))
    except ValueError as exc:
        raise RuleValidationError(str(exc)) from exc


def validate_action(action: Union[str, Action]) -> Action:
    """Validate firewall action."""
    if isinstance(action, Action):
        return action
    try:
        return Action.from_str(str(action))
    except ValueError as exc:
        raise RuleValidationError(str(exc)) from exc


def validate_packet(packet_data: Union[Dict[str, Any], Packet]) -> Packet:
    """Validate an incoming or simulated packet against network invariants."""
    if isinstance(packet_data, Packet):
        data = packet_data.to_dict()
    else:
        data = packet_data

    src_ip = validate_ipv4_address(str(data.get("src_ip", "")))
    dst_ip = validate_ipv4_address(str(data.get("dst_ip", "")))
    proto = validate_protocol(data.get("protocol", "TCP"))
    direction = validate_direction(data.get("direction", "INBOUND"))

    allow_zero = (proto == Protocol.ICMP)
    src_port = validate_port_number(data.get("src_port", 0 if allow_zero else 1024), allow_zero=allow_zero)
    dst_port = validate_port_number(data.get("dst_port", 0 if allow_zero else 80), allow_zero=allow_zero)

    payload_size = int(data.get("payload_size", 64))
    if payload_size < 0 or payload_size > 65535:
        raise PacketValidationError(f"Payload size {payload_size} out of range (0-65535).")

    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        direction=direction,
        flags=str(data.get("flags", "")).strip().upper(),
        payload_size=payload_size,
        timestamp=str(data.get("timestamp", "")),
        is_simulated=bool(data.get("is_simulated", True)),
        description=str(data.get("description", "")),
    )


def validate_rule(rule_data: Union[Dict[str, Any], Rule]) -> Rule:
    """Validate rule dictionary or instance and return validated Rule object."""
    if isinstance(rule_data, Rule):
        data = rule_data.to_dict()
    else:
        data = dict(rule_data)

    rule_id = str(data.get("id", "")).strip()
    if not rule_id:
        raise RuleValidationError("Rule ID cannot be empty.")
    if not re.match(r"^[A-Za-z0-9_\-\.]+$", rule_id):
        raise RuleValidationError(f"Rule ID '{rule_id}' contains invalid characters (alphanumeric, -, _, . only).")

    name = str(data.get("name", "")).strip()
    if not name:
        raise RuleValidationError("Rule name cannot be empty.")

    try:
        priority = int(data.get("priority", 100))
        if not (1 <= priority <= 1000):
            raise RuleValidationError(f"Priority {priority} out of valid range (1-1000).")
    except (ValueError, TypeError) as exc:
        raise RuleValidationError(f"Priority must be an integer: {exc}") from exc

    src_ip_str = str(data.get("src_ip", "*")).strip()
    dst_ip_str = str(data.get("dst_ip", "*")).strip()
    validate_ip_pattern(src_ip_str)
    validate_ip_pattern(dst_ip_str)

    src_ports_str = str(data.get("src_ports", "*")).strip()
    dst_ports_str = str(data.get("dst_ports", "*")).strip()
    validate_port_range(src_ports_str)
    validate_port_range(dst_ports_str)

    protocol = validate_protocol(data.get("protocol", "ANY"))
    direction = validate_direction(data.get("direction", "ANY"))
    action = validate_action(data.get("action", "BLOCK"))

    return Rule(
        id=rule_id,
        name=name,
        description=str(data.get("description", "")).strip(),
        priority=priority,
        enabled=bool(data.get("enabled", True)),
        src_ip=src_ip_str,
        dst_ip=dst_ip_str,
        src_ports=src_ports_str,
        dst_ports=dst_ports_str,
        protocol=protocol,
        direction=direction,
        action=action,
        created_at=str(data.get("created_at", "")),
        modified_at=str(data.get("modified_at", "")),
    )
