"""Core data models and type definitions for SmartShield Firewall Engine."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Protocol(str, Enum):
    """Supported network transport protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ANY = "ANY"

    @classmethod
    def from_str(cls, val: str) -> Protocol:
        val_upper = val.strip().upper()
        if val_upper in cls.__members__:
            return cls[val_upper]
        if val_upper in ("*", "ALL"):
            return cls.ANY
        raise ValueError(f"Unsupported protocol: '{val}'. Expected TCP, UDP, ICMP, or ANY.")


class Direction(str, Enum):
    """Traffic flow direction relative to host/network boundary."""
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    ANY = "ANY"

    @classmethod
    def from_str(cls, val: str) -> Direction:
        val_upper = val.strip().upper()
        if val_upper in cls.__members__:
            return cls[val_upper]
        if val_upper in ("*", "ALL"):
            return cls.ANY
        raise ValueError(f"Unsupported direction: '{val}'. Expected INBOUND, OUTBOUND, or ANY.")


class Action(str, Enum):
    """Firewall filtering disposition."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"

    @classmethod
    def from_str(cls, val: str) -> Action:
        val_upper = val.strip().upper()
        if val_upper in cls.__members__:
            return cls[val_upper]
        if val_upper in ("DENY", "DROP", "REJECT"):
            return cls.BLOCK
        if val_upper in ("ACCEPT", "PASS"):
            return cls.ALLOW
        raise ValueError(f"Unsupported action: '{val}'. Expected ALLOW or BLOCK.")


@dataclass(frozen=True)
class IPPattern:
    """Represents an IP matching criteria: single IPv4, CIDR network, or wildcard."""
    raw: str
    is_wildcard: bool
    network: Optional[ipaddress.IPv4Network] = None

    @classmethod
    def parse(cls, pattern_str: str) -> IPPattern:
        raw_clean = pattern_str.strip()
        if raw_clean in ("*", "ANY", "any", "0.0.0.0/0", ""):
            return cls(raw=raw_clean or "*", is_wildcard=True, network=None)

        try:
            # Parse either a CIDR or host IP (strict=False normalizes host bits if CIDR has them)
            net = ipaddress.IPv4Network(raw_clean, strict=False)
            return cls(raw=raw_clean, is_wildcard=False, network=net)
        except ValueError as e:
            raise ValueError(f"Invalid IPv4 pattern '{raw_clean}': {e}") from e

    def matches(self, ip_str: str) -> bool:
        """Evaluate if an IPv4 address string matches this pattern."""
        if self.is_wildcard:
            return True
        try:
            addr = ipaddress.IPv4Address(ip_str.strip())
            return self.network is not None and addr in self.network
        except ValueError:
            return False


@dataclass(frozen=True)
class PortRange:
    """Represents port matching criteria: single port, ranges (e.g. 80-443), comma list, or wildcard."""
    raw: str
    is_wildcard: bool
    port_sets: List[Tuple[int, int]] = field(default_factory=list)

    @classmethod
    def parse(cls, port_str: str) -> PortRange:
        raw_clean = str(port_str).strip()
        if raw_clean in ("*", "ANY", "any", "0", ""):
            return cls(raw=raw_clean or "*", is_wildcard=True, port_sets=[])

        tokens = [t.strip() for t in raw_clean.split(",") if t.strip()]
        ranges: List[Tuple[int, int]] = []

        for token in tokens:
            if "-" in token:
                parts = token.split("-", 1)
                try:
                    start_p = int(parts[0].strip())
                    end_p = int(parts[1].strip())
                except ValueError as exc:
                    raise ValueError(f"Invalid numeric port range '{token}': {exc}") from exc
                if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535):
                    raise ValueError(f"Port range '{token}' exceeds valid TCP/UDP bounds (1-65535).")
                if start_p > end_p:
                    raise ValueError(f"Port range start ({start_p}) cannot exceed end ({end_p}).")
                ranges.append((start_p, end_p))
            else:
                try:
                    p = int(token)
                except ValueError as exc:
                    raise ValueError(f"Invalid numeric port '{token}': {exc}") from exc
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port '{p}' exceeds valid TCP/UDP bounds (1-65535).")
                ranges.append((p, p))

        return cls(raw=raw_clean, is_wildcard=False, port_sets=ranges)

    def matches(self, port: int) -> bool:
        """Evaluate whether a port integer satisfies this match specification."""
        if self.is_wildcard:
            return True
        for start, end in self.port_sets:
            if start <= port <= end:
                return True
        return False


@dataclass
class Packet:
    """Synthetic or inspected IP packet record."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    direction: Direction
    flags: str = ""
    payload_size: int = 64
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_simulated: bool = True
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value,
            "direction": self.direction.value,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "timestamp": self.timestamp,
            "is_simulated": self.is_simulated,
            "description": self.description,
        }


@dataclass
class EvaluationStep:
    """Trace log of a single rule evaluated against a packet."""
    rule_id: str
    rule_name: str
    priority: int
    matched: bool
    src_ip_match: bool
    dst_ip_match: bool
    src_port_match: bool
    dst_port_match: bool
    proto_match: bool
    dir_match: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "priority": self.priority,
            "matched": self.matched,
            "src_ip_match": self.src_ip_match,
            "dst_ip_match": self.dst_ip_match,
            "src_port_match": self.src_port_match,
            "dst_port_match": self.dst_port_match,
            "proto_match": self.proto_match,
            "dir_match": self.dir_match,
            "explanation": self.explanation,
        }


@dataclass
class EvaluationDecision:
    """Structured decision returned by the firewall evaluator."""
    action: Action
    rule_id: Optional[str]
    rule_name: str
    matched: bool
    timestamp: str
    reason: str
    steps: List[EvaluationStep] = field(default_factory=list)
    packet: Optional[Packet] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "matched": self.matched,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "steps": [s.to_dict() for s in self.steps],
            "packet": self.packet.to_dict() if self.packet else None,
        }


@dataclass
class Rule:
    """Firewall security policy rule definition."""
    id: str
    name: str
    description: str
    priority: int  # 1 (highest) to 1000 (lowest)
    enabled: bool
    src_ip: str  # IP / CIDR / *
    dst_ip: str
    src_ports: str  # Port / Range / *
    dst_ports: str
    protocol: Protocol
    direction: Direction
    action: Action
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    modified_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Pre-compiled matchers for maximum performance
    _src_ip_pat: Optional[IPPattern] = field(default=None, init=False, repr=False)
    _dst_ip_pat: Optional[IPPattern] = field(default=None, init=False, repr=False)
    _src_port_range: Optional[PortRange] = field(default=None, init=False, repr=False)
    _dst_port_range: Optional[PortRange] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.compile_matchers()

    def compile_matchers(self) -> None:
        """Compile string match criteria into validated IPPattern and PortRange objects."""
        self._src_ip_pat = IPPattern.parse(self.src_ip)
        self._dst_ip_pat = IPPattern.parse(self.dst_ip)
        self._src_port_range = PortRange.parse(self.src_ports)
        self._dst_port_range = PortRange.parse(self.dst_ports)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "enabled": self.enabled,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_ports": self.src_ports,
            "dst_ports": self.dst_ports,
            "protocol": self.protocol.value,
            "direction": self.direction.value,
            "action": self.action.value,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Rule:
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            description=str(data.get("description", "")),
            priority=int(data.get("priority", 100)),
            enabled=bool(data.get("enabled", True)),
            src_ip=str(data.get("src_ip", "*")),
            dst_ip=str(data.get("dst_ip", "*")),
            src_ports=str(data.get("src_ports", "*")),
            dst_ports=str(data.get("dst_ports", "*")),
            protocol=Protocol.from_str(str(data.get("protocol", "ANY"))),
            direction=Direction.from_str(str(data.get("direction", "ANY"))),
            action=Action.from_str(str(data.get("action", "BLOCK"))),
            created_at=str(data.get("created_at", datetime.now(timezone.utc).isoformat())),
            modified_at=str(data.get("modified_at", datetime.now(timezone.utc).isoformat())),
        )
