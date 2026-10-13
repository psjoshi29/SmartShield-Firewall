"""End-to-End integration test covering the entire SmartShield lifecycle."""

from smartshield.analytics.analyzer import (
    compute_kpis,
    get_direction_df,
    get_protocol_df,
    get_top_blocked_ports_df,
)
from smartshield.analytics.exporter import export_audit_log_csv
from smartshield.engine.models import Action, Direction, Packet, Protocol, Rule
from smartshield.engine.ruleset import RuleSet
from smartshield.engine.validator import validate_packet, validate_rule
from smartshield.simulator.runner import SimulationRunner
from smartshield.storage.config import ConfigManager
from smartshield.storage.db import EventDatabase


def test_full_firewall_lifecycle(tmp_path):
    # 1. Configuration & Ruleset
    cfg_path = tmp_path / "rules.json"
    cfg = ConfigManager(cfg_path)
    ruleset = cfg.load_ruleset()
    assert len(ruleset.rules) >= 7
    assert ruleset.default_action == Action.BLOCK

    # 2. Database Initialization
    db_path = tmp_path / "events.db"
    db = EventDatabase(db_path)
    assert db.count_events() == 0

    # 3. Simulator Pipeline
    runner = SimulationRunner(ruleset=ruleset, db=db)
    decisions = runner.run_scenario("web_browsing", count=20, seed=42)
    assert len(decisions) == 20
    assert db.count_events() == 20

    # 4. Recon threat simulation (verify blocks)
    recon_decisions = runner.run_scenario("untrusted_recon", count=10, seed=99)
    assert len(recon_decisions) == 10
    assert all(d.action == Action.BLOCK for d in recon_decisions)
    assert db.count_events() == 30

    # 5. Analytics & KPI verification
    kpis = compute_kpis(db)
    assert kpis["total"] == 30
    assert kpis["blocked"] >= 10
    assert kpis["allowed"] > 0
    assert kpis["block_rate"] > 0.0

    proto_df = get_protocol_df(db)
    assert not proto_df.empty
    dir_df = get_direction_df(db)
    assert not dir_df.empty
    ports_df = get_top_blocked_ports_df(db)
    assert not ports_df.empty

    # 6. Packet Inspector trace
    test_pkt = validate_packet({
        "src_ip": "10.0.1.25",
        "dst_ip": "192.168.1.10",
        "src_port": 54000,
        "dst_port": 22,
        "protocol": "TCP",
        "direction": "INBOUND",
    })
    insp_decision = runner.inspect_packet(test_pkt, log_to_db=True)
    assert insp_decision.action == Action.ALLOW
    assert insp_decision.rule_id == "RULE-006"
    assert len(insp_decision.steps) > 0

    # 7. Safe CSV Export
    csv_file = tmp_path / "export.csv"
    exported_path = export_audit_log_csv(db, csv_file)
    assert exported_path.exists()
    assert exported_path.stat().st_size > 0

    # 8. Rule addition & dynamic persistence
    new_rule = validate_rule({
        "id": "RULE-TEST-999",
        "name": "Block Custom Port 9999",
        "description": "Dynamic rule",
        "priority": 5,
        "enabled": True,
        "src_ip": "*",
        "dst_ip": "*",
        "src_ports": "*",
        "dst_ports": "9999",
        "protocol": "TCP",
        "direction": "ANY",
        "action": "BLOCK",
    })
    ruleset.add_rule(new_rule)
    cfg.save_ruleset(ruleset)

    reloaded_ruleset = cfg.load_ruleset()
    assert reloaded_ruleset.get_rule("RULE-TEST-999") is not None
    assert reloaded_ruleset.rules[0].id == "RULE-TEST-999"  # Priority 5 is top
