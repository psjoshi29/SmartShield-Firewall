"""Statistical analysis and data formatting for dashboard visualization."""

from __future__ import annotations

from typing import Any, Dict

import pandas as pd

from smartshield.storage.db import EventDatabase


def compute_kpis(db: EventDatabase) -> Dict[str, Any]:
    """Calculate core Key Performance Indicators for the firewall dashboard."""
    stats = db.get_statistics()
    return {
        "total": stats["total_events"],
        "allowed": stats["allowed_events"],
        "blocked": stats["blocked_events"],
        "block_rate": stats["block_rate_percent"],
    }


def get_protocol_df(db: EventDatabase) -> pd.DataFrame:
    """Return protocol distribution as a Pandas DataFrame."""
    stats = db.get_statistics()
    protocols = stats["protocols"]
    if not protocols:
        return pd.DataFrame(columns=["Protocol", "Count"])
    return pd.DataFrame(
        [{"Protocol": k, "Count": v} for k, v in protocols.items()]
    )


def get_direction_df(db: EventDatabase) -> pd.DataFrame:
    """Return traffic direction breakdown as a Pandas DataFrame."""
    stats = db.get_statistics()
    dirs = stats["directions"]
    if not dirs:
        return pd.DataFrame(columns=["Direction", "Count"])
    return pd.DataFrame(
        [{"Direction": k, "Count": v} for k, v in dirs.items()]
    )


def get_top_blocked_ports_df(db: EventDatabase) -> pd.DataFrame:
    """Return top 10 blocked destination ports."""
    stats = db.get_statistics()
    ports = stats["top_blocked_ports"]
    if not ports:
        return pd.DataFrame(columns=["Port", "Blocked Packets"])
    df = pd.DataFrame(
        [{"Port": str(p["port"]), "Blocked Packets": p["count"]} for p in ports]
    )
    return df


def get_timeline_df(db: EventDatabase) -> pd.DataFrame:
    """Return chronological event trend grouped by action."""
    stats = db.get_statistics()
    timeline = stats["timeline"]
    if not timeline:
        return pd.DataFrame(columns=["Hour", "Action", "Count"])
    return pd.DataFrame(
        [{"Hour": row["hr"], "Action": row["action"], "Count": row["cnt"]} for row in timeline]
    )
