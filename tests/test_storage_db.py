"""Unit tests for SQLite event logging and CSV sanitization."""

from smartshield.engine.models import Action, Direction, EvaluationDecision, Packet, Protocol
from smartshield.storage.db import EventDatabase, sanitize_csv_field


class TestEventDatabase:
    """Test SQLite event logging, search/filter, and CSV security."""

    def test_log_and_query_event(self, tmp_path):
        db_path = tmp_path / "test_events.db"
        db = EventDatabase(db_path)

        pkt = Packet(
            src_ip="192.168.1.15",
            dst_ip="8.8.8.8",
            src_port=51234,
            dst_port=53,
            protocol=Protocol.UDP,
            direction=Direction.OUTBOUND,
            flags="",
            payload_size=64,
            is_simulated=True,
        )
        decision = EvaluationDecision(
            action=Action.ALLOW,
            rule_id="RULE-DNS",
            rule_name="Allow DNS",
            matched=True,
            timestamp="2026-10-13T10:00:00Z",
            reason="Matched Rule RULE-DNS",
            packet=pkt,
        )

        row_id = db.log_event(decision)
        assert row_id > 0

        events = db.query_events(limit=10)
        assert len(events) == 1
        ev = events[0]
        assert ev["src_ip"] == "192.168.1.15"
        assert ev["dst_ip"] == "8.8.8.8"
        assert ev["dst_port"] == 53
        assert ev["action"] == "ALLOW"
        assert ev["matched_rule_id"] == "RULE-DNS"

    def test_filter_and_search_events(self, tmp_path):
        db = EventDatabase(tmp_path / "test_filters.db")

        # Insert ALLOW and BLOCK events
        for i in range(5):
            pkt = Packet(
                src_ip="192.168.1.100",
                dst_ip="1.1.1.1",
                src_port=50000 + i,
                dst_port=443,
                protocol=Protocol.TCP,
                direction=Direction.OUTBOUND,
            )
            dec = EvaluationDecision(
                action=Action.ALLOW,
                rule_id="RULE-ALLOW-WEB",
                rule_name="Allow Web",
                matched=True,
                timestamp=f"2026-10-13T10:0{i}:00Z",
                reason="Allow HTTPS",
                packet=pkt,
            )
            db.log_event(dec)

        for i in range(3):
            pkt = Packet(
                src_ip="203.0.113.10",
                dst_ip="192.168.1.10",
                src_port=40000 + i,
                dst_port=23,
                protocol=Protocol.TCP,
                direction=Direction.INBOUND,
            )
            dec = EvaluationDecision(
                action=Action.BLOCK,
                rule_id="RULE-BLOCK-TELNET",
                rule_name="Block Telnet",
                matched=True,
                timestamp=f"2026-10-13T11:0{i}:00Z",
                reason="Block Telnet scan",
                packet=pkt,
            )
            db.log_event(dec)

        assert db.count_events() == 8
        assert db.count_events(action="ALLOW") == 5
        assert db.count_events(action="BLOCK") == 3
        assert db.count_events(direction="INBOUND") == 3
        assert db.count_events(direction="OUTBOUND") == 5
        assert db.count_events(port=23) == 3
        assert db.count_events(search="Telnet") == 3

    def test_csv_injection_sanitization(self, tmp_path):
        # Verify characters like =, +, -, @ are escaped
        assert sanitize_csv_field("=1+1") == "'=1+1"
        assert sanitize_csv_field("+12345") == "'+12345"
        assert sanitize_csv_field("-cmd|' /C calc'!A0") == "'-cmd|' /C calc'!A0"
        assert sanitize_csv_field("@SUM(1,2)") == "'@SUM(1,2)"
        assert sanitize_csv_field("Normal text") == "Normal text"
        assert sanitize_csv_field(443) == "443"

        # Verify CSV export string contains safe prefix
        db = EventDatabase(tmp_path / "csv_test.db")
        pkt = Packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol=Protocol.TCP,
            direction=Direction.INBOUND,
        )
        dec = EvaluationDecision(
            action=Action.BLOCK,
            rule_id="R1",
            rule_name="=MALICIOUS_FORMULA",
            matched=True,
            timestamp="2026-10-13T12:00:00Z",
            reason="+INJECTION_REASON",
            packet=pkt,
        )
        db.log_event(dec)

        csv_str = db.export_csv_string()
        assert "'=MALICIOUS_FORMULA" in csv_str
        assert "'+INJECTION_REASON" in csv_str

    def test_reset_database(self, tmp_path):
        db = EventDatabase(tmp_path / "reset_test.db")
        pkt = Packet("1.1.1.1", "2.2.2.2", 80, 80, Protocol.TCP, Direction.INBOUND)
        db.log_event(EvaluationDecision(Action.ALLOW, None, "D", False, "now", "reason", packet=pkt))
        assert db.count_events() == 1

        db.reset_database()
        assert db.count_events() == 0
