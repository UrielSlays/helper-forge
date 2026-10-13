"""Deterministic air-gap noise dampener.

This module only transforms validated data into validated data. It has no
network client and no execution primitive. Prototype source labels are not
authenticated, so this runtime withholds action proposals entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .contracts import (
    ActionProposal,
    ActionStatus,
    ContractError,
    EVENT_RESULT_VERSION,
    Event,
    HelperManifest,
    Playbook,
    ScenarioPack,
    Severity,
    Signal,
    SignalDisposition,
    parse_timestamp,
    validate_action_target,
)


@dataclass(frozen=True, slots=True)
class ProcessingResult:
    signal: Signal
    action_proposals: tuple[ActionProposal, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EVENT_RESULT_VERSION,
            "record_type": "event_result",
            "signal": self.signal.to_dict(),
            "action_proposals": [proposal.to_dict() for proposal in self.action_proposals],
        }


@dataclass(slots=True)
class _WindowEntry:
    observed_at: datetime
    representative_event_id: str
    representative_event_digest: str
    occurrence_count: int


class NoiseDampener:
    """Coalesce admitted low/medium labels while preserving urgent events."""

    def __init__(self, scenario: ScenarioPack, manifest: HelperManifest) -> None:
        manifest.assert_matches(scenario)
        self._scenario = scenario
        self._manifest = manifest
        self._admitted_source_labels = frozenset(
            scenario.policy.admitted_source_labels
        )
        self._window_seconds = scenario.policy.coalesce_window_seconds
        self._windows: dict[str, _WindowEntry] = {}
        self._event_ids: set[str] = set()
        self._events_seen = 0
        self._event_bytes_seen = 0

    @property
    def helper_id(self) -> str:
        return self._manifest.helper_id

    @property
    def active_group_count(self) -> int:
        """Number of bounded duplicate groups currently retained in memory."""

        return len(self._windows)

    @property
    def events_seen(self) -> int:
        """Number of events admitted to this bounded helper session."""

        return self._events_seen

    def process(self, event: Event) -> ProcessingResult:
        """Process one validated event without executing any proposed action."""

        event_bytes = event.byte_size
        if event.event_id in self._event_ids:
            raise ContractError(f"event_id {event.event_id!r} was already processed")
        if self._events_seen >= self._scenario.policy.max_event_count:
            raise ContractError(
                "scenario.policy.max_event_count reached; processing stopped closed"
            )
        if (
            self._event_bytes_seen + event_bytes
            > self._scenario.policy.max_total_event_bytes
        ):
            raise ContractError(
                "scenario.policy.max_total_event_bytes reached; processing stopped closed"
            )
        if event_bytes > self._scenario.policy.max_event_bytes:
            raise ContractError(
                "event exceeds scenario.policy.max_event_bytes; processing stopped closed"
            )

        result = self._process_once(event)
        self._event_ids.add(event.event_id)
        self._events_seen += 1
        self._event_bytes_seen += event_bytes
        return result

    def _process_once(self, event: Event) -> ProcessingResult:
        """Transform one event; callers commit session accounting on success."""

        if event.source not in self._admitted_source_labels:
            signal = self._signal(
                event,
                disposition=SignalDisposition.REJECTED,
                reason_code="unadmitted_source_label",
                representative_event_id=None,
                representative_event_digest=None,
                occurrence_count=1,
                action_status=ActionStatus.NOT_EVALUATED,
            )
            return ProcessingResult(signal=signal, action_proposals=())

        if event.severity in (Severity.HIGH, Severity.CRITICAL):
            reason = (
                "admitted_high_passthrough"
                if event.severity is Severity.HIGH
                else "admitted_critical_passthrough"
            )
            return self._forward(event, reason_code=reason)

        playbook = self._scenario.playbook_for(event.event_type)
        if playbook is None:
            return self._forward(
                event, reason_code="admitted_low_medium_no_grouping_rule"
            )
        try:
            fingerprint = event.grouping_fingerprint(playbook.grouping_fields)
        except ContractError:
            return self._forward(
                event, reason_code="admitted_low_medium_invalid_grouping_key"
            )
        observed_at = parse_timestamp(event.observed_at)
        entry = self._windows.get(fingerprint)
        if entry is not None:
            elapsed = (observed_at - entry.observed_at).total_seconds()
            if 0 <= elapsed <= self._window_seconds:
                next_count = entry.occurrence_count + 1
                signal = self._signal(
                    event,
                    disposition=SignalDisposition.COALESCED,
                    reason_code="duplicate_within_window",
                    representative_event_id=entry.representative_event_id,
                    representative_event_digest=entry.representative_event_digest,
                    occurrence_count=next_count,
                    action_status=ActionStatus.NOT_EVALUATED,
                )
                entry.occurrence_count = next_count
                return ProcessingResult(signal=signal, action_proposals=())
            reason = (
                "admitted_low_medium_out_of_order"
                if elapsed < 0
                else "admitted_low_medium_window_expired"
            )
            if elapsed < 0:
                # A late event remains visible, but must not move the anchor
                # backwards and cause a newer duplicate to escape coalescing.
                return self._forward(event, reason_code=reason)
        else:
            reason = "admitted_low_medium_new"
            if len(self._windows) >= self._scenario.policy.max_active_groups:
                raise ContractError(
                    "scenario.policy.max_active_groups reached; processing stopped closed"
                )

        result = self._forward(event, reason_code=reason)
        self._windows[fingerprint] = _WindowEntry(
            observed_at=observed_at,
            representative_event_id=event.event_id,
            representative_event_digest=event.digest,
            occurrence_count=1,
        )
        return result

    def _forward(self, event: Event, *, reason_code: str) -> ProcessingResult:
        playbook = self._scenario.playbook_for(event.event_type)
        if playbook is None:
            action_status = ActionStatus.NO_PLAYBOOK
        else:
            try:
                self._target_from_event(playbook, event.attributes)
            except ContractError:
                action_status = ActionStatus.INVALID_TARGET
            else:
                # Source is only an admitted label in prototype/v0. Until a trusted
                # intake authenticates provenance, even a structurally valid target
                # cannot become an action proposal.
                action_status = ActionStatus.AUTHENTICATION_REQUIRED

        signal = self._signal(
            event,
            disposition=SignalDisposition.FORWARDED,
            reason_code=reason_code,
            representative_event_id=event.event_id,
            representative_event_digest=event.digest,
            occurrence_count=1,
            action_status=action_status,
        )
        return ProcessingResult(signal=signal, action_proposals=())

    @staticmethod
    def _target_from_event(
        playbook: Playbook, attributes: Mapping[str, Any]
    ) -> dict[str, Any]:
        target: dict[str, Any] = {}
        for target_name, event_field in playbook.bindings:
            if event_field not in attributes:
                raise ContractError(
                    f"event is missing playbook-bound attribute {event_field!r}"
                )
            target[target_name] = attributes[event_field]
        return validate_action_target(playbook.action_type, target)

    def _signal(
        self,
        event: Event,
        *,
        disposition: SignalDisposition,
        reason_code: str,
        representative_event_id: str | None,
        representative_event_digest: str | None,
        occurrence_count: int,
        action_status: ActionStatus,
    ) -> Signal:
        return Signal.build(
            helper_id=self._manifest.helper_id,
            scenario_id=self._scenario.scenario_id,
            event=event,
            disposition=disposition,
            reason_code=reason_code,
            representative_event_id=representative_event_id,
            representative_event_digest=representative_event_digest,
            occurrence_count=occurrence_count,
            action_status=action_status,
        )
