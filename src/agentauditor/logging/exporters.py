"""Custom exporters for audit logs."""

from __future__ import annotations

import json
from pathlib import Path


def export_logs_to_json(logs: list[dict], path: str | Path) -> None:
    """Export audit log entries to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(logs, f, indent=2, default=str)
