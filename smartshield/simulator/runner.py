"""Simulation coordinator: executes scenarios, evaluates packets, and logs events."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from smartshield.engine.evaluator import evaluate_packet
from smartshield.engine.models import EvaluationDecision, Packet
from smartshield.engine.ruleset import RuleSet
from smartshield.simulator.generator import generate_scenario_packets
from smartshield.storage.db import EventDatabase

logger = logging.getLogger(__name__)


class SimulationRunner:
    """Orchestrates traffic simulation, engine evaluation, and audit logging."""

    def __init__(self, ruleset: RuleSet, db: EventDatabase) -> None:
        self.ruleset = ruleset
        self.db = db

    def run_scenario(
        self,
        scenario_key: str,
        count: int = 25,
        seed: Optional[int] = None,
    ) -> List[EvaluationDecision]:
        """Generate synthetic packets for scenario, evaluate via engine, and record audit logs."""
        packets = generate_scenario_packets(scenario_key=scenario_key, count=count, seed=seed)
        decisions: List[EvaluationDecision] = []

        for pkt in packets:
            dec = evaluate_packet(pkt, self.ruleset)
            decisions.append(dec)

        # Batch persist to SQLite database
        self.db.log_events_batch(decisions)
        return decisions

    def inspect_packet(self, packet: Packet, log_to_db: bool = True) -> EvaluationDecision:
        """Inspect a single custom packet, recording step-by-step trace and logging if requested."""
        decision = evaluate_packet(packet, self.ruleset)
        if log_to_db:
            self.db.log_event(decision)
        return decision

    def seed_demo_traffic(self, total_records: int = 60) -> int:
        """Generate an initial diverse baseline of synthetic traffic if database is empty."""
        current_count = self.db.count_events()
        if current_count > 0:
            return 0

        logger.info("Seeding baseline demo traffic (%d records)...", total_records)
        scenarios = ["web_browsing", "untrusted_recon", "admin_management", "untrusted_ssh", "malformed_traffic"]
        per_scenario = max(5, total_records // len(scenarios))

        total_seeded = 0
        for sc in scenarios:
            decs = self.run_scenario(sc, count=per_scenario)
            total_seeded += len(decs)

        return total_seeded
