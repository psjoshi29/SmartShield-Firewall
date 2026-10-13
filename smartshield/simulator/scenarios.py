"""Predefined simulation scenarios and packet generation specifications."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class ScenarioDef:
    """Metadata describing a test traffic simulation scenario."""
    key: str
    name: str
    category: str
    description: str
    expected_outcome: str


SCENARIO_CATALOG: Dict[str, ScenarioDef] = {
    "web_browsing": ScenarioDef(
        key="web_browsing",
        name="Legitimate Web & DNS Egress",
        category="Authorized / Normal",
        description="Standard employee workstations generating outbound HTTPS (443), HTTP (80), and DNS (53) lookups.",
        expected_outcome="Majority ALLOWED by egress rules RULE-004 & RULE-005.",
    ),
    "untrusted_recon": ScenarioDef(
        key="untrusted_recon",
        name="External Port Scan & Reconnaissance",
        category="Threat Simulation",
        description="Inbound TCP connection probes against high-risk ports: Telnet (23), SMB (445), and RDP (3389) from external WAN IPs.",
        expected_outcome="BLOCKED by RULE-001, RULE-002, and RULE-003.",
    ),
    "admin_management": ScenarioDef(
        key="admin_management",
        name="Authorized Admin Inbound SSH",
        category="Authorized / Management",
        description="Internal systems engineering team accessing bastion host 192.168.1.10 from management subnet 10.0.0.0/16 on port 22.",
        expected_outcome="ALLOWED by RULE-006.",
    ),
    "untrusted_ssh": ScenarioDef(
        key="untrusted_ssh",
        name="External WAN Inbound SSH Brute-Force",
        category="Threat Simulation",
        description="Inbound SSH attempts to internal hosts from untrusted public IPs (e.g. 198.51.100.25).",
        expected_outcome="BLOCKED by Default Policy (no WAN SSH rule exists).",
    ),
    "malformed_traffic": ScenarioDef(
        key="malformed_traffic",
        name="Malformed & Boundary Header Packets",
        category="Edge Case / Integrity",
        description="Packets with out-of-spec ports, broadcast abuses, non-routable addresses, and fragmented or empty flags.",
        expected_outcome="BLOCKED by Integrity Validator or Default Policy.",
    ),
    "mixed_traffic": ScenarioDef(
        key="mixed_traffic",
        name="Enterprise Mixed Real-World Traffic Flow",
        category="Comprehensive Simulation",
        description="A heterogeneous mix of web egress, authorized admin traffic, external port sweeps, and DNS queries.",
        expected_outcome="Realistic mix of ALLOWED and BLOCKED outcomes.",
    ),
}
