"""Safe file export handlers for SmartShield audit logs."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from smartshield.storage.db import EventDatabase


def export_audit_log_csv(
    db: EventDatabase,
    output_path: Path | str,
    action: Optional[str] = None,
    protocol: Optional[str] = None,
    direction: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 10000,
) -> Path:
    """Export filtered events to a safe CSV file on disk with formula injection neutralization."""
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    csv_content = db.export_csv_string(
        action=action,
        protocol=protocol,
        direction=direction,
        search=search,
        limit=limit,
    )

    with open(out_file, "w", encoding="utf-8", newline="") as f:
        f.write(csv_content)

    return out_file
