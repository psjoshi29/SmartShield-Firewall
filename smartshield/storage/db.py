"""SQLite database layer for persistent audit logging and secure CSV export."""

from __future__ import annotations

import csv
import io
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from smartshield.engine.models import Action, EvaluationDecision, Packet

logger = logging.getLogger(__name__)


def sanitize_csv_field(val: Any) -> Any:
    """Neutralize potential CSV formula injection characters (=, +, -, @, tab, CR)."""
    if val is None:
        return ""
    str_val = str(val)
    if str_val and str_val[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{str_val}"
    return str_val


class EventDatabase:
    """Manages SQLite storage of firewall evaluation logs."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing thread-safe SQLite connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize schema, pragmas, and indexing."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode = WAL;")
            cur.execute("PRAGMA synchronous = NORMAL;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    action TEXT NOT NULL,
                    matched_rule_id TEXT,
                    matched_rule_name TEXT,
                    reason TEXT NOT NULL,
                    flags TEXT DEFAULT '',
                    payload_size INTEGER DEFAULT 64,
                    is_simulated INTEGER DEFAULT 1
                );
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_direction ON events(direction);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(matched_rule_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_dst_port ON events(dst_port);")

    def log_event(self, decision: EvaluationDecision) -> int:
        """Log a single evaluation decision to SQLite using parameterized query."""
        pkt = decision.packet
        if not pkt:
            pkt = Packet(
                src_ip="0.0.0.0",
                dst_ip="0.0.0.0",
                src_port=0,
                dst_port=0,
                protocol=None,  # type: ignore
                direction=None,  # type: ignore
            )

        proto_val = pkt.protocol.value if hasattr(pkt.protocol, "value") else str(pkt.protocol or "ANY")
        dir_val = pkt.direction.value if hasattr(pkt.direction, "value") else str(pkt.direction or "ANY")
        action_val = decision.action.value if hasattr(decision.action, "value") else str(decision.action)

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO events (
                    timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, direction, action, matched_rule_id,
                    matched_rule_name, reason, flags, payload_size, is_simulated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    decision.timestamp,
                    pkt.src_ip,
                    pkt.dst_ip,
                    pkt.src_port,
                    pkt.dst_port,
                    proto_val,
                    dir_val,
                    action_val,
                    decision.rule_id,
                    decision.rule_name,
                    decision.reason,
                    pkt.flags,
                    pkt.payload_size,
                    1 if pkt.is_simulated else 0,
                ),
            )
            return cur.lastrowid or 0

    def log_events_batch(self, decisions: List[EvaluationDecision]) -> int:
        """Batch insert evaluation decisions in a single transaction."""
        if not decisions:
            return 0

        rows = []
        for dec in decisions:
            pkt = dec.packet
            if not pkt:
                continue
            proto_val = pkt.protocol.value if hasattr(pkt.protocol, "value") else str(pkt.protocol or "ANY")
            dir_val = pkt.direction.value if hasattr(pkt.direction, "value") else str(pkt.direction or "ANY")
            action_val = dec.action.value if hasattr(dec.action, "value") else str(dec.action)

            rows.append((
                dec.timestamp,
                pkt.src_ip,
                pkt.dst_ip,
                pkt.src_port,
                pkt.dst_port,
                proto_val,
                dir_val,
                action_val,
                dec.rule_id,
                dec.rule_name,
                dec.reason,
                pkt.flags,
                pkt.payload_size,
                1 if pkt.is_simulated else 0,
            ))

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.executemany(
                """
                INSERT INTO events (
                    timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, direction, action, matched_rule_id,
                    matched_rule_name, reason, flags, payload_size, is_simulated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )
            return len(rows)

    def query_events(
        self,
        limit: int = 100,
        offset: int = 0,
        action: Optional[str] = None,
        protocol: Optional[str] = None,
        direction: Optional[str] = None,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        port: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Query logged events with filtering, search, and pagination."""
        clauses, params = self._build_where_clause(
            action, protocol, direction, search, start_time, end_time, port
        )
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        sql = f"""
            SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
                   protocol, direction, action, matched_rule_id,
                   matched_rule_name, reason, flags, payload_size, is_simulated
            FROM events
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    def count_events(
        self,
        action: Optional[str] = None,
        protocol: Optional[str] = None,
        direction: Optional[str] = None,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        port: Optional[int] = None,
    ) -> int:
        """Count total events matching the filter parameters."""
        clauses, params = self._build_where_clause(
            action, protocol, direction, search, start_time, end_time, port
        )
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        sql = f"SELECT COUNT(*) FROM events {where_sql};"
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def _build_where_clause(
        self,
        action: Optional[str],
        protocol: Optional[str],
        direction: Optional[str],
        search: Optional[str],
        start_time: Optional[str],
        end_time: Optional[str],
        port: Optional[int],
    ) -> Tuple[List[str], List[Any]]:
        """Construct parameterized SQL WHERE clause conditions and parameters."""
        clauses: List[str] = []
        params: List[Any] = []

        if action and action != "ALL":
            clauses.append("action = ?")
            params.append(action.upper())

        if protocol and protocol != "ALL":
            clauses.append("protocol = ?")
            params.append(protocol.upper())

        if direction and direction != "ALL":
            clauses.append("direction = ?")
            params.append(direction.upper())

        if port is not None and port > 0:
            clauses.append("(dst_port = ? OR src_port = ?)")
            params.extend([port, port])

        if start_time:
            clauses.append("timestamp >= ?")
            params.append(start_time)

        if end_time:
            clauses.append("timestamp <= ?")
            params.append(end_time)

        if search:
            search_pattern = f"%{search.strip()}%"
            clauses.append(
                "(src_ip LIKE ? OR dst_ip LIKE ? OR matched_rule_name LIKE ? OR reason LIKE ? OR matched_rule_id LIKE ?)"
            )
            params.extend([search_pattern] * 5)

        return clauses, params

    def get_statistics(self) -> Dict[str, Any]:
        """Aggregate statistical metrics for dashboard analytics."""
        with self._get_connection() as conn:
            cur = conn.cursor()

            cur.execute("SELECT COUNT(*), SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END), SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) FROM events;")
            total_row = cur.fetchone()
            total = total_row[0] or 0
            allowed = total_row[1] or 0
            blocked = total_row[2] or 0
            block_rate = round((blocked / total * 100), 2) if total > 0 else 0.0

            # Protocol distribution
            cur.execute("SELECT protocol, COUNT(*) as cnt FROM events GROUP BY protocol ORDER BY cnt DESC;")
            protocols = {row["protocol"]: row["cnt"] for row in cur.fetchall()}

            # Direction distribution
            cur.execute("SELECT direction, COUNT(*) as cnt FROM events GROUP BY direction ORDER BY cnt DESC;")
            directions = {row["direction"]: row["cnt"] for row in cur.fetchall()}

            # Top blocked destination ports
            cur.execute("SELECT dst_port, COUNT(*) as cnt FROM events WHERE action = 'BLOCK' GROUP BY dst_port ORDER BY cnt DESC LIMIT 10;")
            top_blocked_ports = [{"port": row["dst_port"], "count": row["cnt"]} for row in cur.fetchall()]

            # Top blocked source IPs
            cur.execute("SELECT src_ip, COUNT(*) as cnt FROM events WHERE action = 'BLOCK' GROUP BY src_ip ORDER BY cnt DESC LIMIT 10;")
            top_blocked_ips = [{"ip": row["src_ip"], "count": row["cnt"]} for row in cur.fetchall()]

            # Hourly distribution (last 24 hours or general trend)
            cur.execute("SELECT substr(timestamp, 1, 13) as hr, action, COUNT(*) as cnt FROM events GROUP BY hr, action ORDER BY hr ASC;")
            timeline_rows = [dict(r) for r in cur.fetchall()]

            return {
                "total_events": total,
                "allowed_events": allowed,
                "blocked_events": blocked,
                "block_rate_percent": block_rate,
                "protocols": protocols,
                "directions": directions,
                "top_blocked_ports": top_blocked_ports,
                "top_blocked_ips": top_blocked_ips,
                "timeline": timeline_rows,
            }

    def reset_database(self) -> None:
        """Truncate all events with a transactional table clear."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM events;")
            cur.execute("DELETE FROM sqlite_sequence WHERE name='events';")

    def export_csv_string(
        self,
        action: Optional[str] = None,
        protocol: Optional[str] = None,
        direction: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 5000,
    ) -> str:
        """Export events to CSV string with formula injection protection."""
        events = self.query_events(
            limit=limit,
            offset=0,
            action=action,
            protocol=protocol,
            direction=direction,
            search=search,
        )

        output = io.StringIO()
        fieldnames = [
            "id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "direction", "action", "matched_rule_id",
            "matched_rule_name", "reason", "flags", "payload_size", "is_simulated"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for evt in events:
            sanitized_row = {k: sanitize_csv_field(evt.get(k, "")) for k in fieldnames}
            writer.writerow(sanitized_row)

        return output.getvalue()
