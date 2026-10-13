"""Strict, versioned wire contracts for the first Hephaestus helper.

The contracts intentionally accept only JSON data.  They do not contain an
escape hatch for shell commands, executable arguments, or arbitrary action
parameters. All identifiers and action targets are validated as inert data;
the prototype runtime does not emit action proposals.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence


SCENARIO_PACK_VERSION = "hephaestus.prototype.scenario-pack/v0"
EVENT_VERSION = "hephaestus.prototype.event/v0"
SIGNAL_VERSION = "hephaestus.prototype.signal/v0"
ACTION_PROPOSAL_VERSION = "hephaestus.prototype.action-proposal/v0"
HELPER_MANIFEST_VERSION = "hephaestus.prototype.helper-manifest/v0"
EVENT_RESULT_VERSION = "hephaestus.prototype.event-result/v0"
RUN_SUMMARY_VERSION = "hephaestus.prototype.run-summary/v0"

HELPER_KIND = "deterministic.noise-dampener"
HELPER_IMPLEMENTATION_VERSION = "0"
HELPER_CAPABILITIES = (
    "coalesce-low-medium",
    "preserve-high-critical",
    "route-by-admitted-source-label",
    "withhold-actions-without-source-authentication",
)
_IMPLEMENTATION_FILES = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "contracts.py",
    "engine.py",
)

# RFC 8259 section 9 lets a parser bound nesting depth. The deepest record the
# contracts admit is an event whose attributes nest to the _json_value limit,
# which is well under this bound.
MAX_JSON_NESTING_DEPTH = 32

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_ASSET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESERVED_EXECUTION_FIELDS = frozenset(
    {
        "argv",
        "bash",
        "cmd",
        "command",
        "executable",
        "powershell",
        "script",
        "shell",
    }
)


class ContractError(ValueError):
    """Raised when data does not satisfy a Hephaestus wire contract."""


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SignalDisposition(str, Enum):
    FORWARDED = "forwarded"
    COALESCED = "coalesced"
    REJECTED = "rejected"


class ActionType(str, Enum):
    CLOSE_PORT = "close_port"
    ISOLATE_HOST = "isolate_host"
    BLOCK_ADDRESS = "block_address"


class ActionStatus(str, Enum):
    AUTHENTICATION_REQUIRED = "authentication_required"
    NO_PLAYBOOK = "no_playbook"
    INVALID_TARGET = "invalid_target"
    NOT_EVALUATED = "not_evaluated"


_ACTION_TARGET_FIELDS: dict[ActionType, tuple[str, ...]] = {
    ActionType.CLOSE_PORT: ("host", "port", "protocol"),
    ActionType.ISOLATE_HOST: ("host",),
    ActionType.BLOCK_ADDRESS: ("address",),
}


def _reject_json_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        try:
            key.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ContractError(
                "JSON object key contains a non-Unicode-scalar value"
            ) from exc
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_excessive_nesting(text: str) -> None:
    """Refuse JSON text nested deeper than MAX_JSON_NESTING_DEPTH.

    The count runs before parsing so the refusal never depends on the
    interpreter's recursion limit, which differs between Python versions.
    Brackets and braces inside a string are text, not structure. For
    well-formed JSON the count equals the nesting depth exactly; malformed
    text is left for the parser to refuse.
    """

    if text.count("[") + text.count("{") <= MAX_JSON_NESTING_DEPTH:
        return
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise ContractError(
                    "JSON nesting exceeds the maximum depth of "
                    f"{MAX_JSON_NESTING_DEPTH}"
                )
        elif character in "]}":
            depth -= 1


def strict_json_loads(text: str) -> Any:
    """Parse JSON text while rejecting duplicate keys, non-finite numbers,
    and nesting deeper than MAX_JSON_NESTING_DEPTH."""

    if not isinstance(text, str):
        # json.loads also decodes bytes, which would bypass the nesting bound.
        raise ContractError("JSON input must be text")
    _reject_excessive_nesting(text)
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
        raise ContractError(f"invalid JSON: {exc}") from exc


def canonical_json(value: Any) -> str:
    """Return the canonical representation used for every content address."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ContractError(f"value is not canonical JSON: {exc}") from exc


def content_digest(value: Any) -> str:
    try:
        payload = canonical_json(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError("value contains a non-Unicode-scalar string") from exc
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def implementation_digest(*, package_root: Path | None = None) -> str:
    """Bind a helper manifest to the exact installed prototype runtime bytes."""

    package_root = package_root or Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for filename in _IMPLEMENTATION_FILES:
        path = package_root / filename
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ContractError(
                f"cannot identify helper implementation file {filename!r}: {exc}"
            ) from exc
        encoded_name = filename.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{label} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ContractError(f"{label} keys must be strings")
    return value


def _strict_keys(
    value: Mapping[str, Any],
    label: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ContractError(f"{label} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ContractError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")


def _string(
    value: Any,
    label: str,
    *,
    minimum: int = 1,
    maximum: int = 256,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{label} must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{label} contains a non-Unicode-scalar value") from exc
    if not minimum <= len(value) <= maximum:
        raise ContractError(f"{label} length must be between {minimum} and {maximum}")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ContractError(f"{label} has an invalid format")
    return value


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ContractError(f"{label} must be between {minimum} and {maximum}")
    return value


def _enum(value: Any, enum_type: type[Enum], label: str) -> Any:
    if not isinstance(value, str):
        raise ContractError(f"{label} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise ContractError(f"{label} must be one of: {allowed}") from exc


def _timestamp(value: Any, label: str) -> str:
    value = _string(value, label, maximum=32, pattern=_UTC_TIMESTAMP)
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError(f"{label} is not a real UTC timestamp") from exc
    return value


def parse_timestamp(value: str) -> datetime:
    """Parse a timestamp previously accepted by the Event contract."""

    _timestamp(value, "timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _json_value(value: Any, label: str, *, depth: int = 0) -> Any:
    if depth > 8:
        raise ContractError(f"{label} exceeds the maximum nesting depth")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ContractError(
                    f"{label} contains a non-Unicode-scalar value"
                ) from exc
            if len(value) > 4096:
                raise ContractError(
                    f"{label} contains a string longer than 4096 characters"
                )
        return value
    if isinstance(value, int):
        if abs(value) > 2**63 - 1:
            raise ContractError(f"{label} contains an integer outside signed 64-bit range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError(f"{label} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise ContractError(f"{label} contains more than 256 object fields")
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ContractError(f"{label} contains an invalid object key")
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ContractError(
                    f"{label} contains a non-Unicode-scalar object key"
                ) from exc
            frozen[key] = _json_value(item, f"{label}.{key}", depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > 1024:
            raise ContractError(f"{label} contains more than 1024 list items")
        return tuple(
            _json_value(item, f"{label}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        )
    raise ContractError(f"{label} contains a non-JSON value")


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def _string_list(
    value: Any,
    label: str,
    *,
    minimum_items: int = 1,
    pattern: re.Pattern[str] = _IDENTIFIER,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    if len(value) < minimum_items:
        raise ContractError(f"{label} must contain at least {minimum_items} item(s)")
    parsed = tuple(
        _string(item, f"{label}[{index}]", maximum=128, pattern=pattern)
        for index, item in enumerate(value)
    )
    if len(set(parsed)) != len(parsed):
        raise ContractError(f"{label} must not contain duplicates")
    return parsed


@dataclass(frozen=True, slots=True)
class ScenarioPolicy:
    mode: str
    admitted_source_labels: tuple[str, ...]
    coalesce_window_seconds: int
    coalesce_severities: tuple[str, ...]
    preserve_severities: tuple[str, ...]
    max_event_bytes: int
    max_total_event_bytes: int
    max_event_count: int
    max_active_groups: int

    @classmethod
    def from_dict(cls, raw: Any) -> "ScenarioPolicy":
        value = _object(raw, "scenario.policy")
        _strict_keys(
            value,
            "scenario.policy",
            {
                "mode",
                "admitted_source_labels",
                "coalesce_window_seconds",
                "coalesce_severities",
                "preserve_severities",
                "max_event_bytes",
                "max_total_event_bytes",
                "max_event_count",
                "max_active_groups",
            },
        )
        mode = _string(value["mode"], "scenario.policy.mode", maximum=16)
        if mode != "air_gap":
            raise ContractError("scenario.policy.mode must be 'air_gap'")
        admitted_source_labels = _string_list(
            value["admitted_source_labels"],
            "scenario.policy.admitted_source_labels",
        )
        window = _integer(
            value["coalesce_window_seconds"],
            "scenario.policy.coalesce_window_seconds",
            minimum=1,
            maximum=86_400,
        )
        coalesce = _string_list(
            value["coalesce_severities"], "scenario.policy.coalesce_severities"
        )
        preserve = _string_list(
            value["preserve_severities"], "scenario.policy.preserve_severities"
        )
        if coalesce != (Severity.LOW.value, Severity.MEDIUM.value):
            raise ContractError(
                "scenario.policy.coalesce_severities must be ['low', 'medium']"
            )
        if preserve != (Severity.HIGH.value, Severity.CRITICAL.value):
            raise ContractError(
                "scenario.policy.preserve_severities must be ['high', 'critical']"
            )
        max_event_bytes = _integer(
            value["max_event_bytes"],
            "scenario.policy.max_event_bytes",
            minimum=256,
            maximum=65_536,
        )
        max_total_event_bytes = _integer(
            value["max_total_event_bytes"],
            "scenario.policy.max_total_event_bytes",
            minimum=256,
            maximum=16_777_216,
        )
        max_event_count = _integer(
            value["max_event_count"],
            "scenario.policy.max_event_count",
            minimum=1,
            maximum=50_000,
        )
        max_active_groups = _integer(
            value["max_active_groups"],
            "scenario.policy.max_active_groups",
            minimum=1,
            maximum=8_192,
        )
        if max_active_groups > max_event_count:
            raise ContractError(
                "scenario.policy.max_active_groups may not exceed max_event_count"
            )
        return cls(
            mode=mode,
            admitted_source_labels=admitted_source_labels,
            coalesce_window_seconds=window,
            coalesce_severities=coalesce,
            preserve_severities=preserve,
            max_event_bytes=max_event_bytes,
            max_total_event_bytes=max_total_event_bytes,
            max_event_count=max_event_count,
            max_active_groups=max_active_groups,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "admitted_source_labels": list(self.admitted_source_labels),
            "coalesce_window_seconds": self.coalesce_window_seconds,
            "coalesce_severities": list(self.coalesce_severities),
            "preserve_severities": list(self.preserve_severities),
            "max_event_bytes": self.max_event_bytes,
            "max_total_event_bytes": self.max_total_event_bytes,
            "max_event_count": self.max_event_count,
            "max_active_groups": self.max_active_groups,
        }


@dataclass(frozen=True, slots=True)
class Playbook:
    playbook_id: str
    match_event_type: str
    grouping_fields: tuple[str, ...]
    action_type: ActionType
    bindings: tuple[tuple[str, str], ...]
    reason: str

    @classmethod
    def from_dict(cls, raw: Any, *, index: int = 0) -> "Playbook":
        label = f"scenario.playbooks[{index}]"
        value = _object(raw, label)
        _strict_keys(
            value,
            label,
            {
                "playbook_id",
                "match_event_type",
                "grouping_fields",
                "action_type",
                "bindings",
                "reason",
            },
        )
        playbook_id = _string(
            value["playbook_id"], f"{label}.playbook_id", maximum=128, pattern=_IDENTIFIER
        )
        match_event_type = _string(
            value["match_event_type"],
            f"{label}.match_event_type",
            maximum=128,
            pattern=_IDENTIFIER,
        )
        grouping_fields = _string_list(
            value["grouping_fields"],
            f"{label}.grouping_fields",
            pattern=_FIELD_NAME,
        )
        if len(grouping_fields) > 16:
            raise ContractError(f"{label}.grouping_fields may contain at most 16 fields")
        action_type = _enum(value["action_type"], ActionType, f"{label}.action_type")
        raw_bindings = _object(value["bindings"], f"{label}.bindings")
        expected_fields = set(_ACTION_TARGET_FIELDS[action_type])
        if set(raw_bindings) != expected_fields:
            expected = ", ".join(sorted(expected_fields))
            raise ContractError(
                f"{label}.bindings must contain exactly these target fields: {expected}"
            )
        bindings: list[tuple[str, str]] = []
        for target_name in sorted(raw_bindings):
            event_field = _string(
                raw_bindings[target_name],
                f"{label}.bindings.{target_name}",
                maximum=64,
                pattern=_FIELD_NAME,
            )
            if event_field.lower() in _RESERVED_EXECUTION_FIELDS:
                raise ContractError(
                    f"{label}.bindings.{target_name} may not bind an execution field"
                )
            bindings.append((target_name, event_field))
        bound_fields = {event_field for _, event_field in bindings}
        if not bound_fields.issubset(set(grouping_fields)):
            raise ContractError(
                f"{label}.grouping_fields must include every action-bound event field"
            )
        reason = _string(value["reason"], f"{label}.reason", maximum=256)
        return cls(
            playbook_id=playbook_id,
            match_event_type=match_event_type,
            grouping_fields=grouping_fields,
            action_type=action_type,
            bindings=tuple(bindings),
            reason=reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "match_event_type": self.match_event_type,
            "grouping_fields": list(self.grouping_fields),
            "action_type": self.action_type.value,
            "bindings": dict(self.bindings),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ScenarioPack:
    schema_version: str
    scenario_id: str
    purpose: str
    policy: ScenarioPolicy
    playbooks: tuple[Playbook, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> "ScenarioPack":
        value = _object(raw, "scenario")
        _strict_keys(
            value,
            "scenario",
            {"schema_version", "scenario_id", "purpose", "policy", "playbooks"},
        )
        if value["schema_version"] != SCENARIO_PACK_VERSION:
            raise ContractError(
                f"scenario.schema_version must be {SCENARIO_PACK_VERSION!r}"
            )
        scenario_id = _string(
            value["scenario_id"], "scenario.scenario_id", maximum=128, pattern=_IDENTIFIER
        )
        purpose = _string(value["purpose"], "scenario.purpose", maximum=512)
        policy = ScenarioPolicy.from_dict(value["policy"])
        if not isinstance(value["playbooks"], list):
            raise ContractError("scenario.playbooks must be an array")
        if len(value["playbooks"]) > 128:
            raise ContractError("scenario.playbooks may not contain more than 128 entries")
        playbooks = tuple(
            Playbook.from_dict(item, index=index)
            for index, item in enumerate(value["playbooks"])
        )
        ids = [item.playbook_id for item in playbooks]
        matches = [item.match_event_type for item in playbooks]
        if len(set(ids)) != len(ids):
            raise ContractError("scenario.playbooks contains duplicate playbook_id values")
        if len(set(matches)) != len(matches):
            raise ContractError(
                "scenario.playbooks may contain at most one playbook per event type"
            )
        return cls(
            schema_version=SCENARIO_PACK_VERSION,
            scenario_id=scenario_id,
            purpose=purpose,
            policy=policy,
            playbooks=playbooks,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "purpose": self.purpose,
            "policy": self.policy.to_dict(),
            "playbooks": [playbook.to_dict() for playbook in self.playbooks],
        }

    @property
    def digest(self) -> str:
        return content_digest(self.to_dict())

    def playbook_for(self, event_type: str) -> Playbook | None:
        for playbook in self.playbooks:
            if playbook.match_event_type == event_type:
                return playbook
        return None


@dataclass(frozen=True, slots=True)
class Event:
    schema_version: str
    event_id: str
    observed_at: str
    source: str
    severity: Severity
    event_type: str
    attributes: Mapping[str, Any]

    @classmethod
    def from_dict(cls, raw: Any) -> "Event":
        value = _object(raw, "event")
        _strict_keys(
            value,
            "event",
            {
                "schema_version",
                "event_id",
                "observed_at",
                "source",
                "severity",
                "event_type",
                "attributes",
            },
        )
        if value["schema_version"] != EVENT_VERSION:
            raise ContractError(f"event.schema_version must be {EVENT_VERSION!r}")
        event_id = _string(
            value["event_id"], "event.event_id", maximum=128, pattern=_IDENTIFIER
        )
        observed_at = _timestamp(value["observed_at"], "event.observed_at")
        source = _string(value["source"], "event.source", maximum=128, pattern=_IDENTIFIER)
        severity = _enum(value["severity"], Severity, "event.severity")
        event_type = _string(
            value["event_type"], "event.event_type", maximum=128, pattern=_IDENTIFIER
        )
        raw_attributes = _object(value["attributes"], "event.attributes")
        attributes = _json_value(raw_attributes, "event.attributes")
        return cls(
            schema_version=EVENT_VERSION,
            event_id=event_id,
            observed_at=observed_at,
            source=source,
            severity=severity,
            event_type=event_type,
            attributes=attributes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "observed_at": self.observed_at,
            "source": self.source,
            "severity": self.severity.value,
            "event_type": self.event_type,
            "attributes": _plain_json(self.attributes),
        }

    @property
    def byte_size(self) -> int:
        return len(canonical_json(self.to_dict()).encode("utf-8"))

    @property
    def digest(self) -> str:
        """Content identity for the complete normalized source event."""

        return content_digest(self.to_dict())

    def grouping_fingerprint(self, fields: Sequence[str]) -> str:
        """Build a scenario-owned group key without attacker-chosen extra fields."""

        selected: dict[str, Any] = {}
        for field in fields:
            if field not in self.attributes:
                raise ContractError(f"event is missing grouping attribute {field!r}")
            selected[field] = _plain_json(self.attributes[field])
        return content_digest(
            {
                "source": self.source,
                "severity": self.severity.value,
                "event_type": self.event_type,
                "attributes": selected,
            }
        )


_SIGNAL_REASONS = frozenset(
    {
        "duplicate_within_window",
        "admitted_critical_passthrough",
        "admitted_high_passthrough",
        "admitted_low_medium_invalid_grouping_key",
        "admitted_low_medium_new",
        "admitted_low_medium_no_grouping_rule",
        "admitted_low_medium_out_of_order",
        "admitted_low_medium_window_expired",
        "unadmitted_source_label",
    }
)


@dataclass(frozen=True, slots=True)
class Signal:
    schema_version: str
    signal_id: str
    helper_id: str
    scenario_id: str
    event_id: str
    event_digest: str
    observed_at: str
    source: str
    severity: Severity
    disposition: SignalDisposition
    reason_code: str
    representative_event_id: str | None
    representative_event_digest: str | None
    occurrence_count: int
    action_status: ActionStatus

    @classmethod
    def build(
        cls,
        *,
        helper_id: str,
        scenario_id: str,
        event: Event,
        disposition: SignalDisposition,
        reason_code: str,
        representative_event_id: str | None,
        representative_event_digest: str | None,
        occurrence_count: int,
        action_status: ActionStatus,
    ) -> "Signal":
        body = {
            "schema_version": SIGNAL_VERSION,
            "helper_id": helper_id,
            "scenario_id": scenario_id,
            "event_id": event.event_id,
            "event_digest": event.digest,
            "observed_at": event.observed_at,
            "source": event.source,
            "severity": event.severity.value,
            "disposition": disposition.value,
            "reason_code": reason_code,
            "representative_event_id": representative_event_id,
            "representative_event_digest": representative_event_digest,
            "occurrence_count": occurrence_count,
            "action_status": action_status.value,
        }
        return cls.from_dict({**body, "signal_id": content_digest(body)})

    @classmethod
    def from_dict(cls, raw: Any) -> "Signal":
        value = _object(raw, "signal")
        required = {
            "schema_version",
            "signal_id",
            "helper_id",
            "scenario_id",
            "event_id",
            "event_digest",
            "observed_at",
            "source",
            "severity",
            "disposition",
            "reason_code",
            "representative_event_id",
            "representative_event_digest",
            "occurrence_count",
            "action_status",
        }
        _strict_keys(value, "signal", required)
        if value["schema_version"] != SIGNAL_VERSION:
            raise ContractError(f"signal.schema_version must be {SIGNAL_VERSION!r}")
        signal_id = _string(
            value["signal_id"], "signal.signal_id", maximum=71, pattern=_DIGEST
        )
        helper_id = _string(
            value["helper_id"], "signal.helper_id", maximum=71, pattern=_DIGEST
        )
        scenario_id = _string(
            value["scenario_id"], "signal.scenario_id", maximum=128, pattern=_IDENTIFIER
        )
        event_id = _string(
            value["event_id"], "signal.event_id", maximum=128, pattern=_IDENTIFIER
        )
        event_digest = _string(
            value["event_digest"], "signal.event_digest", maximum=71, pattern=_DIGEST
        )
        observed_at = _timestamp(value["observed_at"], "signal.observed_at")
        source = _string(value["source"], "signal.source", maximum=128, pattern=_IDENTIFIER)
        severity = _enum(value["severity"], Severity, "signal.severity")
        disposition = _enum(
            value["disposition"], SignalDisposition, "signal.disposition"
        )
        reason_code = _string(value["reason_code"], "signal.reason_code", maximum=64)
        if reason_code not in _SIGNAL_REASONS:
            raise ContractError("signal.reason_code is not recognized")
        representative = value["representative_event_id"]
        if representative is not None:
            representative = _string(
                representative,
                "signal.representative_event_id",
                maximum=128,
                pattern=_IDENTIFIER,
            )
        representative_digest = value["representative_event_digest"]
        if representative_digest is not None:
            representative_digest = _string(
                representative_digest,
                "signal.representative_event_digest",
                maximum=71,
                pattern=_DIGEST,
            )
        occurrence_count = _integer(
            value["occurrence_count"],
            "signal.occurrence_count",
            minimum=1,
            maximum=2**31 - 1,
        )
        action_status = _enum(
            value["action_status"], ActionStatus, "signal.action_status"
        )
        if disposition is SignalDisposition.REJECTED:
            if (
                representative is not None
                or representative_digest is not None
                or action_status is not ActionStatus.NOT_EVALUATED
            ):
                raise ContractError("rejected signals may not select a representative or action")
        elif disposition is SignalDisposition.COALESCED:
            if (
                representative is None
                or representative_digest is None
                or representative == event_id
                or occurrence_count < 2
            ):
                raise ContractError("coalesced signals require a prior representative and count >= 2")
            if action_status is not ActionStatus.NOT_EVALUATED:
                raise ContractError("coalesced signals may not propose an action")
        else:
            if (
                representative != event_id
                or representative_digest != event_digest
                or occurrence_count != 1
            ):
                raise ContractError(
                    "forwarded signals must represent themselves with occurrence_count 1"
                )
            if action_status is ActionStatus.NOT_EVALUATED:
                raise ContractError("forwarded signals must evaluate the scenario playbook")
        body = {key: value[key] for key in required if key != "signal_id"}
        if content_digest(body) != signal_id:
            raise ContractError("signal.signal_id does not match the signal content")
        return cls(
            schema_version=SIGNAL_VERSION,
            signal_id=signal_id,
            helper_id=helper_id,
            scenario_id=scenario_id,
            event_id=event_id,
            event_digest=event_digest,
            observed_at=observed_at,
            source=source,
            severity=severity,
            disposition=disposition,
            reason_code=reason_code,
            representative_event_id=representative,
            representative_event_digest=representative_digest,
            occurrence_count=occurrence_count,
            action_status=action_status,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "signal_id": self.signal_id,
            "helper_id": self.helper_id,
            "scenario_id": self.scenario_id,
            "event_id": self.event_id,
            "event_digest": self.event_digest,
            "observed_at": self.observed_at,
            "source": self.source,
            "severity": self.severity.value,
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "representative_event_id": self.representative_event_id,
            "representative_event_digest": self.representative_event_digest,
            "occurrence_count": self.occurrence_count,
            "action_status": self.action_status.value,
        }


def validate_action_target(action_type: ActionType, raw: Any) -> dict[str, Any]:
    value = _object(raw, "action_proposal.target")
    expected = set(_ACTION_TARGET_FIELDS[action_type])
    if set(value) != expected:
        fields = ", ".join(sorted(expected))
        raise ContractError(
            f"action_proposal.target for {action_type.value} must contain exactly: {fields}"
        )
    if action_type is ActionType.CLOSE_PORT:
        host = _string(
            value["host"], "action_proposal.target.host", maximum=128, pattern=_ASSET_NAME
        )
        port = _integer(
            value["port"], "action_proposal.target.port", minimum=1, maximum=65_535
        )
        protocol = _string(
            value["protocol"], "action_proposal.target.protocol", maximum=3
        ).lower()
        if protocol not in {"tcp", "udp"}:
            raise ContractError("action_proposal.target.protocol must be 'tcp' or 'udp'")
        return {"host": host, "port": port, "protocol": protocol}
    if action_type is ActionType.ISOLATE_HOST:
        return {
            "host": _string(
                value["host"],
                "action_proposal.target.host",
                maximum=128,
                pattern=_ASSET_NAME,
            )
        }
    if action_type is ActionType.BLOCK_ADDRESS:
        address = _string(
            value["address"], "action_proposal.target.address", maximum=45
        )
        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError as exc:
            raise ContractError("action_proposal.target.address must be an IP address") from exc
        return {"address": normalized}
    raise ContractError("unsupported action type")


@dataclass(frozen=True, slots=True)
class ActionProposal:
    schema_version: str
    proposal_id: str
    helper_id: str
    scenario_id: str
    event_id: str
    event_digest: str
    evidence_signal_id: str
    playbook_id: str
    action_type: ActionType
    target: Mapping[str, Any]
    reason: str
    proposed_at: str
    approval_state: str

    @classmethod
    def build(
        cls,
        *,
        helper_id: str,
        scenario_id: str,
        event: Event,
        signal_id: str,
        playbook: Playbook,
        target: Mapping[str, Any],
    ) -> "ActionProposal":
        normalized = validate_action_target(playbook.action_type, target)
        body = {
            "schema_version": ACTION_PROPOSAL_VERSION,
            "helper_id": helper_id,
            "scenario_id": scenario_id,
            "event_id": event.event_id,
            "event_digest": event.digest,
            "evidence_signal_id": signal_id,
            "playbook_id": playbook.playbook_id,
            "action_type": playbook.action_type.value,
            "target": normalized,
            "reason": playbook.reason,
            "proposed_at": event.observed_at,
            "approval_state": "requires_approval",
        }
        return cls.from_dict({**body, "proposal_id": content_digest(body)})

    @classmethod
    def from_dict(cls, raw: Any) -> "ActionProposal":
        value = _object(raw, "action_proposal")
        required = {
            "schema_version",
            "proposal_id",
            "helper_id",
            "scenario_id",
            "event_id",
            "event_digest",
            "evidence_signal_id",
            "playbook_id",
            "action_type",
            "target",
            "reason",
            "proposed_at",
            "approval_state",
        }
        _strict_keys(value, "action_proposal", required)
        if value["schema_version"] != ACTION_PROPOSAL_VERSION:
            raise ContractError(
                f"action_proposal.schema_version must be {ACTION_PROPOSAL_VERSION!r}"
            )
        proposal_id = _string(
            value["proposal_id"],
            "action_proposal.proposal_id",
            maximum=71,
            pattern=_DIGEST,
        )
        helper_id = _string(
            value["helper_id"],
            "action_proposal.helper_id",
            maximum=71,
            pattern=_DIGEST,
        )
        scenario_id = _string(
            value["scenario_id"],
            "action_proposal.scenario_id",
            maximum=128,
            pattern=_IDENTIFIER,
        )
        event_id = _string(
            value["event_id"],
            "action_proposal.event_id",
            maximum=128,
            pattern=_IDENTIFIER,
        )
        event_digest = _string(
            value["event_digest"],
            "action_proposal.event_digest",
            maximum=71,
            pattern=_DIGEST,
        )
        evidence_signal_id = _string(
            value["evidence_signal_id"],
            "action_proposal.evidence_signal_id",
            maximum=71,
            pattern=_DIGEST,
        )
        playbook_id = _string(
            value["playbook_id"],
            "action_proposal.playbook_id",
            maximum=128,
            pattern=_IDENTIFIER,
        )
        action_type = _enum(
            value["action_type"], ActionType, "action_proposal.action_type"
        )
        target = MappingProxyType(validate_action_target(action_type, value["target"]))
        reason = _string(value["reason"], "action_proposal.reason", maximum=256)
        proposed_at = _timestamp(value["proposed_at"], "action_proposal.proposed_at")
        if value["approval_state"] != "requires_approval":
            raise ContractError(
                "action_proposal.approval_state must be 'requires_approval'"
            )
        body = {key: value[key] for key in required if key != "proposal_id"}
        body["target"] = dict(target)
        if content_digest(body) != proposal_id:
            raise ContractError(
                "action_proposal.proposal_id does not match the proposal content"
            )
        return cls(
            schema_version=ACTION_PROPOSAL_VERSION,
            proposal_id=proposal_id,
            helper_id=helper_id,
            scenario_id=scenario_id,
            event_id=event_id,
            event_digest=event_digest,
            evidence_signal_id=evidence_signal_id,
            playbook_id=playbook_id,
            action_type=action_type,
            target=target,
            reason=reason,
            proposed_at=proposed_at,
            approval_state="requires_approval",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "helper_id": self.helper_id,
            "scenario_id": self.scenario_id,
            "event_id": self.event_id,
            "event_digest": self.event_digest,
            "evidence_signal_id": self.evidence_signal_id,
            "playbook_id": self.playbook_id,
            "action_type": self.action_type.value,
            "target": dict(self.target),
            "reason": self.reason,
            "proposed_at": self.proposed_at,
            "approval_state": self.approval_state,
        }


@dataclass(frozen=True, slots=True)
class HelperManifest:
    schema_version: str
    helper_id: str
    helper_kind: str
    implementation_version: str
    implementation_digest: str
    scenario_id: str
    scenario_digest: str
    capabilities: tuple[str, ...]
    playbook_ids: tuple[str, ...]

    @classmethod
    def forge(cls, scenario: ScenarioPack) -> "HelperManifest":
        body = {
            "schema_version": HELPER_MANIFEST_VERSION,
            "helper_kind": HELPER_KIND,
            "implementation_version": HELPER_IMPLEMENTATION_VERSION,
            "implementation_digest": implementation_digest(),
            "scenario_id": scenario.scenario_id,
            "scenario_digest": scenario.digest,
            "capabilities": list(HELPER_CAPABILITIES),
            "playbook_ids": [playbook.playbook_id for playbook in scenario.playbooks],
        }
        return cls.from_dict({**body, "helper_id": content_digest(body)})

    @classmethod
    def from_dict(cls, raw: Any) -> "HelperManifest":
        value = _object(raw, "helper_manifest")
        required = {
            "schema_version",
            "helper_id",
            "helper_kind",
            "implementation_version",
            "implementation_digest",
            "scenario_id",
            "scenario_digest",
            "capabilities",
            "playbook_ids",
        }
        _strict_keys(value, "helper_manifest", required)
        if value["schema_version"] != HELPER_MANIFEST_VERSION:
            raise ContractError(
                f"helper_manifest.schema_version must be {HELPER_MANIFEST_VERSION!r}"
            )
        helper_id = _string(
            value["helper_id"], "helper_manifest.helper_id", maximum=71, pattern=_DIGEST
        )
        if value["helper_kind"] != HELPER_KIND:
            raise ContractError(f"helper_manifest.helper_kind must be {HELPER_KIND!r}")
        if value["implementation_version"] != HELPER_IMPLEMENTATION_VERSION:
            raise ContractError(
                "helper_manifest.implementation_version is not supported by this runtime"
            )
        runtime_digest = _string(
            value["implementation_digest"],
            "helper_manifest.implementation_digest",
            maximum=71,
            pattern=_DIGEST,
        )
        if runtime_digest != implementation_digest():
            raise ContractError(
                "helper_manifest.implementation_digest does not match this runtime"
            )
        scenario_id = _string(
            value["scenario_id"],
            "helper_manifest.scenario_id",
            maximum=128,
            pattern=_IDENTIFIER,
        )
        scenario_digest = _string(
            value["scenario_digest"],
            "helper_manifest.scenario_digest",
            maximum=71,
            pattern=_DIGEST,
        )
        capabilities = _string_list(
            value["capabilities"], "helper_manifest.capabilities"
        )
        if capabilities != HELPER_CAPABILITIES:
            raise ContractError("helper_manifest.capabilities do not match this runtime")
        playbook_ids = _string_list(
            value["playbook_ids"],
            "helper_manifest.playbook_ids",
            minimum_items=0,
        )
        body = {key: value[key] for key in required if key != "helper_id"}
        if content_digest(body) != helper_id:
            raise ContractError(
                "helper_manifest.helper_id does not match the manifest content"
            )
        return cls(
            schema_version=HELPER_MANIFEST_VERSION,
            helper_id=helper_id,
            helper_kind=HELPER_KIND,
            implementation_version=HELPER_IMPLEMENTATION_VERSION,
            implementation_digest=runtime_digest,
            scenario_id=scenario_id,
            scenario_digest=scenario_digest,
            capabilities=capabilities,
            playbook_ids=playbook_ids,
        )

    def assert_matches(self, scenario: ScenarioPack) -> None:
        if self.implementation_digest != implementation_digest():
            raise ContractError(
                "helper manifest implementation_digest does not match this runtime"
            )
        if self.scenario_id != scenario.scenario_id:
            raise ContractError("helper manifest scenario_id does not match the scenario")
        if self.scenario_digest != scenario.digest:
            raise ContractError("helper manifest scenario_digest does not match the scenario")
        expected_playbooks = tuple(item.playbook_id for item in scenario.playbooks)
        if self.playbook_ids != expected_playbooks:
            raise ContractError("helper manifest playbook list does not match the scenario")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "helper_id": self.helper_id,
            "helper_kind": self.helper_kind,
            "implementation_version": self.implementation_version,
            "implementation_digest": self.implementation_digest,
            "scenario_id": self.scenario_id,
            "scenario_digest": self.scenario_digest,
            "capabilities": list(self.capabilities),
            "playbook_ids": list(self.playbook_ids),
        }
