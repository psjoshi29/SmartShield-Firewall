"""Unit tests for analytics calculations and dashboard dataframes."""

from smartshield.analytics.analyzer import (
    compute_kpis,
    get_direction_df,
    get_protocol_df,
    get_timeline_df,
    get_top_blocked_ports_df,
)
from smartshield.engine.models import Action, Direction, EvaluationDecision, Packet, Protocol
from smartshield.storage.db import EventDatabase


class TestAnalytics:
    """Test KPI metrics, dataframe outputs, and empty database safety."""

    def test_kpi_with_empty_database(self, tmp_path):
        db = EventDatabase(tmp_path / "empty.db")
        kpis = compute_kpis(db)
        assert kpis["total"] == 0
        assert kpis["allowed"] == 0
        assert kpis["blocked"] == 0
        assert kpis["block_rate"] == 0.0

        assert len(get_protocol_df(db)) == 0
        assert len(get_direction_df(db)) == 0
        assert len(get_top_blocked_ports_df(db)) == 0
        assert len(get_timeline_df(db)) == 0

    def test_analytics_with_data(self, tmp_path):
        db = EventDatabase(tmp_path / "analytics.db")

        # 3 ALLOW TCP OUTBOUND, 1 BLOCK TCP INBOUND
        for _ in range(3):
            pkt = Packet("192.168.1.1", "1.1.1.1", 5000, 443, Protocol.TCP, Direction.OUTBOUND)
            db.log_event(EvaluationDecision(Action.ALLOW, "R1", "Allow", True, "2026-10-13T10:00:00Z", "ok", packet=pkt))

        pkt_blocked = Packet("203.0.113.1", "192.168.1.10", 6000, 445, Protocol.TCP, Direction.INBOUND)
        db.log_event(EvaluationDecision(Action.BLOCK, "R2", "Block SMB", True, "2026-10-13T10:00:00Z", "drop", packet=pkt_blocked))

        kpis = compute_kpis(db)
        assert kpis["total"] == 4
        assert kpis["allowed"] == 3
        assert kpis["blocked"] == 1
        assert kpis["block_rate"] == 25.0

        proto_df = get_protocol_df(db)
        assert "Protocol" in proto_df.columns
        assert len(proto_df) == 1
        assert proto_df.iloc[0]["Count"] == 4

        dir_df = get_direction_df(db)
        assert len(dir_df) == 2

        top_ports_df = get_top_blocked_ports_df(db)
        assert len(top_ports_df) == 1
        assert top_ports_df.iloc[0]["Port"] == "445"
