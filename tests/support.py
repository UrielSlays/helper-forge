from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


BASE_SCENARIO: dict[str, Any] = {
    "schema_version": "hephaestus.prototype.scenario-pack/v0",
    "scenario_id": "test-port-noise-v1",
    "purpose": "Test bounded noise reduction.",
    "policy": {
        "mode": "air_gap",
        "admitted_source_labels": ["sensor.alpha"],
        "coalesce_window_seconds": 30,
        "coalesce_severities": ["low", "medium"],
        "preserve_severities": ["high", "critical"],
        "max_event_bytes": 8192,
        "max_total_event_bytes": 1048576,
        "max_event_count": 4096,
        "max_active_groups": 2048,
    },
    "playbooks": [
        {
            "playbook_id": "close-port-v1",
            "match_event_type": "network.exposed_port",
            "grouping_fields": ["asset", "destination_port", "protocol"],
            "action_type": "close_port",
            "bindings": {
                "host": "asset",
                "port": "destination_port",
                "protocol": "protocol",
            },
            "reason": "Reviewed test playbook; external approval is required.",
        }
    ],
}


def scenario_dict() -> dict[str, Any]:
    return deepcopy(BASE_SCENARIO)


def event_dict(
    event_id: str,
    observed_at: str,
    *,
    source: str = "sensor.alpha",
    severity: str = "low",
    event_type: str = "network.exposed_port",
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "hephaestus.prototype.event/v0",
        "event_id": event_id,
        "observed_at": observed_at,
        "source": source,
        "severity": severity,
        "event_type": event_type,
        "attributes": attributes
        if attributes is not None
        else {"asset": "host-01", "destination_port": 4444, "protocol": "tcp"},
    }
