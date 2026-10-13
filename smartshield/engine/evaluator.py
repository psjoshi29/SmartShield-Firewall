"""Core packet evaluation logic: deterministic first-match rule processor."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from smartshield.engine.models import (
    Action,
    EvaluationDecision,
    EvaluationStep,
    Packet,
    Protocol,
    Direction,
)
from smartshield.engine.ruleset import RuleSet
from smartshield.engine.validator import PacketValidationError, validate_packet


def evaluate_packet(packet_or_dict: Packet, ruleset: RuleSet) -> EvaluationDecision:
    """Evaluate a network packet against a RuleSet in deterministic priority order.

    Returns a structured EvaluationDecision with detailed step-by-step trace.
    If the packet is malformed or invalid, safely drops/blocks it with an explicit reason.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # Step 1: Invariant & integrity validation
    try:
        packet = validate_packet(packet_or_dict)
    except PacketValidationError as err:
        return EvaluationDecision(
            action=Action.BLOCK,
            rule_id=None,
            rule_name="INTEGRITY_CHECK_FAILED",
            matched=False,
            timestamp=now_iso,
            reason=f"Packet sanity check failed: {err}",
            steps=[
                EvaluationStep(
                    rule_id="SYS_VALIDATOR",
                    rule_name="Header Integrity Checker",
                    priority=0,
                    matched=False,
                    src_ip_match=False,
                    dst_ip_match=False,
                    src_port_match=False,
                    dst_port_match=False,
                    proto_match=False,
                    dir_match=False,
                    explanation=f"Malformed packet rejected: {err}",
                )
            ],
            packet=packet_or_dict if isinstance(packet_or_dict, Packet) else None,
        )

    steps: List[EvaluationStep] = []
    active_rules = ruleset.get_active_rules()

    # Step 2: Deterministic first-match evaluation
    for rule in active_rules:
        src_ip_ok = rule._src_ip_pat.matches(packet.src_ip) if rule._src_ip_pat else False
        dst_ip_ok = rule._dst_ip_pat.matches(packet.dst_ip) if rule._dst_ip_pat else False
        src_port_ok = rule._src_port_range.matches(packet.src_port) if rule._src_port_range else False
        dst_port_ok = rule._dst_port_range.matches(packet.dst_port) if rule._dst_port_range else False
        proto_ok = (rule.protocol == Protocol.ANY or rule.protocol == packet.protocol)
        dir_ok = (rule.direction == Direction.ANY or rule.direction == packet.direction)

        is_match = (src_ip_ok and dst_ip_ok and src_port_ok and dst_port_ok and proto_ok and dir_ok)

        mismatches = []
        if not src_ip_ok:
            mismatches.append(f"src_ip({packet.src_ip}!={rule.src_ip})")
        if not dst_ip_ok:
            mismatches.append(f"dst_ip({packet.dst_ip}!={rule.dst_ip})")
        if not src_port_ok:
            mismatches.append(f"src_port({packet.src_port}!={rule.src_ports})")
        if not dst_port_ok:
            mismatches.append(f"dst_port({packet.dst_port}!={rule.dst_ports})")
        if not proto_ok:
            mismatches.append(f"proto({packet.protocol.value}!={rule.protocol.value})")
        if not dir_ok:
            mismatches.append(f"dir({packet.direction.value}!={rule.direction.value})")

        explanation = (
            f"All conditions satisfied -> Action: {rule.action.value}"
            if is_match
            else f"Mismatches: {', '.join(mismatches)}"
        )

        step = EvaluationStep(
            rule_id=rule.id,
            rule_name=rule.name,
            priority=rule.priority,
            matched=is_match,
            src_ip_match=src_ip_ok,
            dst_ip_match=dst_ip_ok,
            src_port_match=src_port_ok,
            dst_port_match=dst_port_ok,
            proto_match=proto_ok,
            dir_match=dir_ok,
            explanation=explanation,
        )
        steps.append(step)

        if is_match:
            return EvaluationDecision(
                action=rule.action,
                rule_id=rule.id,
                rule_name=rule.name,
                matched=True,
                timestamp=now_iso,
                reason=f"Matched Rule [{rule.id}] '{rule.name}' (Priority {rule.priority}) -> {rule.action.value}",
                steps=steps,
                packet=packet,
            )

    # Step 3: Default policy fallback when no rules match
    default_act = ruleset.default_action
    return EvaluationDecision(
        action=default_act,
        rule_id=None,
        rule_name="DEFAULT_POLICY",
        matched=False,
        timestamp=now_iso,
        reason=f"No active rule matched across {len(active_rules)} evaluated policies. Applied default firewall policy: {default_act.value}",
        steps=steps,
        packet=packet,
    )
