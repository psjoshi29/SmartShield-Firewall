"""Unit tests for synthetic packet generator and simulation runner."""

from smartshield.engine.models import Direction, Packet, Protocol
from smartshield.engine.ruleset import RuleSet
from smartshield.simulator.generator import generate_scenario_packets
from smartshield.simulator.runner import SimulationRunner
from smartshield.simulator.scenarios import SCENARIO_CATALOG
from smartshield.storage.config import ConfigManager
from smartshield.storage.db import EventDatabase


class TestSimulator:
    """Test scenario catalog, deterministic generation, and runner pipeline."""

    def test_scenario_catalog_coverage(self):
        expected_scenarios = [
            "web_browsing",
            "untrusted_recon",
            "admin_management",
            "untrusted_ssh",
            "malformed_traffic",
            "mixed_traffic",
        ]
        for sc in expected_scenarios:
            assert sc in SCENARIO_CATALOG
            assert len(SCENARIO_CATALOG[sc].name) > 0

    def test_deterministic_seed_generation(self):
        pkts1 = generate_scenario_packets("web_browsing", count=10, seed=42)
        pkts2 = generate_scenario_packets("web_browsing", count=10, seed=42)

        assert len(pkts1) == 10
        assert len(pkts2) == 10
        for p1, p2 in zip(pkts1, pkts2):
            assert p1.src_ip == p2.src_ip
            assert p1.dst_ip == p2.dst_ip
            assert p1.src_port == p2.src_port
            assert p1.dst_port == p2.dst_port
            assert p1.protocol == p2.protocol
            assert p1.is_simulated is True

    def test_simulation_runner_pipeline(self, tmp_path):
        db = EventDatabase(tmp_path / "sim_pipeline.db")
        cfg = ConfigManager(tmp_path / "cfg.json")
        ruleset = cfg.create_default_ruleset()

        runner = SimulationRunner(ruleset=ruleset, db=db)
        decisions = runner.run_scenario("web_browsing", count=15, seed=123)

        assert len(decisions) == 15
        assert db.count_events() == 15

    def test_inspect_packet_with_trace(self, tmp_path):
        db = EventDatabase(tmp_path / "inspect.db")
        cfg = ConfigManager(tmp_path / "cfg.json")
        ruleset = cfg.create_default_ruleset()

        runner = SimulationRunner(ruleset=ruleset, db=db)
        custom_pkt = Packet(
            src_ip="203.0.113.55",
            dst_ip="192.168.1.10",
            src_port=49000,
            dst_port=23,
            protocol=Protocol.TCP,
            direction=Direction.INBOUND,
        )

        decision = runner.inspect_packet(custom_pkt)
        assert decision.action.value == "BLOCK"
        assert decision.rule_id == "RULE-001"
        assert len(decision.steps) > 0
        assert decision.steps[0].matched is True
