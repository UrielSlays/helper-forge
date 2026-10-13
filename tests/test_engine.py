from __future__ import annotations

import unittest

from tests.support import event_dict, scenario_dict

from hephaestus.contracts import (
    ActionStatus,
    ContractError,
    Event,
    HelperManifest,
    ScenarioPack,
    SignalDisposition,
)
from hephaestus.engine import NoiseDampener


class NoiseDampenerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = ScenarioPack.from_dict(scenario_dict())
        self.manifest = HelperManifest.forge(self.scenario)
        self.helper = NoiseDampener(self.scenario, self.manifest)

    @staticmethod
    def event(
        event_id: str,
        timestamp: str,
        **overrides: object,
    ) -> Event:
        return Event.from_dict(event_dict(event_id, timestamp, **overrides))

    def test_low_duplicate_is_coalesced_with_lineage(self) -> None:
        first_event = self.event("evt-1", "2026-08-14T10:00:00Z")
        second_event = self.event("evt-2", "2026-08-14T10:00:05Z")
        first = self.helper.process(first_event)
        second = self.helper.process(second_event)

        self.assertEqual(first.signal.disposition, SignalDisposition.FORWARDED)
        self.assertEqual(
            first.signal.action_status, ActionStatus.AUTHENTICATION_REQUIRED
        )
        self.assertEqual(first.action_proposals, ())
        self.assertEqual(second.signal.disposition, SignalDisposition.COALESCED)
        self.assertEqual(second.signal.representative_event_id, "evt-1")
        self.assertEqual(second.signal.event_digest, second_event.digest)
        self.assertEqual(
            second.signal.representative_event_digest, first_event.digest
        )
        self.assertEqual(second.signal.occurrence_count, 2)
        self.assertEqual(second.action_proposals, ())

    def test_window_is_anchored_and_expired_duplicate_is_forwarded(self) -> None:
        self.helper.process(self.event("evt-1", "2026-08-14T10:00:00Z"))
        self.helper.process(self.event("evt-2", "2026-08-14T10:00:29Z"))
        after_window = self.helper.process(
            self.event("evt-3", "2026-08-14T10:00:31Z")
        )
        self.assertEqual(after_window.signal.disposition, SignalDisposition.FORWARDED)
        self.assertEqual(
            after_window.signal.reason_code, "admitted_low_medium_window_expired"
        )

    def test_out_of_order_low_event_stays_visible(self) -> None:
        self.helper.process(self.event("evt-1", "2026-08-14T10:00:10Z"))
        late_arrival = self.helper.process(
            self.event("evt-2", "2026-08-14T10:00:05Z")
        )
        self.assertEqual(late_arrival.signal.disposition, SignalDisposition.FORWARDED)
        self.assertEqual(
            late_arrival.signal.reason_code, "admitted_low_medium_out_of_order"
        )
        next_duplicate = self.helper.process(
            self.event("evt-3", "2026-08-14T10:00:11Z")
        )
        self.assertEqual(next_duplicate.signal.disposition, SignalDisposition.COALESCED)
        self.assertEqual(next_duplicate.signal.representative_event_id, "evt-1")
        self.assertEqual(next_duplicate.signal.occurrence_count, 2)

    def test_active_group_limit_refuses_before_allocating_another_group(self) -> None:
        raw = scenario_dict()
        raw["policy"]["max_active_groups"] = 1
        scenario = ScenarioPack.from_dict(raw)
        helper = NoiseDampener(scenario, HelperManifest.forge(scenario))
        helper.process(self.event("evt-1", "2026-08-14T10:00:00Z"))
        self.assertEqual(helper.active_group_count, 1)

        distinct = self.event(
            "evt-2",
            "2026-08-14T10:00:01Z",
            attributes={
                "asset": "host-02",
                "destination_port": 5555,
                "protocol": "tcp",
            },
        )
        with self.assertRaisesRegex(ContractError, "max_active_groups"):
            helper.process(distinct)
        self.assertEqual(helper.active_group_count, 1)
        self.assertEqual(helper.events_seen, 1)

        critical = helper.process(
            self.event(
                "evt-3",
                "2026-08-14T10:00:02Z",
                severity="critical",
                attributes={
                    "asset": "host-03",
                    "destination_port": 6666,
                    "protocol": "tcp",
                },
            )
        )
        self.assertEqual(critical.signal.disposition, SignalDisposition.FORWARDED)
        self.assertEqual(helper.events_seen, 2)

    def test_direct_api_enforces_session_event_and_byte_limits(self) -> None:
        count_raw = scenario_dict()
        count_raw["policy"]["max_event_count"] = 1
        count_raw["policy"]["max_active_groups"] = 1
        count_scenario = ScenarioPack.from_dict(count_raw)
        count_helper = NoiseDampener(
            count_scenario, HelperManifest.forge(count_scenario)
        )
        count_helper.process(self.event("evt-1", "2026-08-14T10:00:00Z"))
        with self.assertRaisesRegex(ContractError, "max_event_count"):
            count_helper.process(
                self.event("evt-2", "2026-08-14T10:00:01Z", severity="critical")
            )
        self.assertEqual(count_helper.events_seen, 1)

        first = self.event("evt-1", "2026-08-14T10:00:00Z")
        bytes_raw = scenario_dict()
        bytes_raw["policy"]["max_total_event_bytes"] = max(256, first.byte_size)
        bytes_scenario = ScenarioPack.from_dict(bytes_raw)
        bytes_helper = NoiseDampener(
            bytes_scenario, HelperManifest.forge(bytes_scenario)
        )
        bytes_helper.process(first)
        with self.assertRaisesRegex(ContractError, "max_total_event_bytes"):
            bytes_helper.process(
                self.event("evt-2", "2026-08-14T10:00:01Z", severity="critical")
            )
        self.assertEqual(bytes_helper.events_seen, 1)

    def test_duplicate_event_id_rejection_does_not_mutate_group_state(self) -> None:
        first = self.event("evt-1", "2026-08-14T10:00:00Z")
        self.helper.process(first)
        with self.assertRaisesRegex(ContractError, "already processed"):
            self.helper.process(first)
        self.assertEqual(self.helper.events_seen, 1)

        next_event = self.event("evt-2", "2026-08-14T10:00:01Z")
        result = self.helper.process(next_event)
        self.assertEqual(result.signal.disposition, SignalDisposition.COALESCED)
        self.assertEqual(result.signal.occurrence_count, 2)
        self.assertEqual(self.helper.events_seen, 2)

    def test_high_and_critical_duplicates_are_never_coalesced(self) -> None:
        for severity in ("high", "critical"):
            helper = NoiseDampener(self.scenario, self.manifest)
            first = helper.process(
                self.event("evt-1", "2026-08-14T10:00:00Z", severity=severity)
            )
            second = helper.process(
                self.event("evt-2", "2026-08-14T10:00:01Z", severity=severity)
            )
            self.assertEqual(first.signal.disposition, SignalDisposition.FORWARDED)
            self.assertEqual(second.signal.disposition, SignalDisposition.FORWARDED)
            self.assertIn("passthrough", first.signal.reason_code)
            self.assertIn("passthrough", second.signal.reason_code)

    def test_unadmitted_source_label_is_rejected_before_action_evaluation(self) -> None:
        result = self.helper.process(
            self.event(
                "evt-1",
                "2026-08-14T10:00:00Z",
                source="sensor.attacker",
                severity="critical",
            )
        )
        self.assertEqual(result.signal.disposition, SignalDisposition.REJECTED)
        self.assertEqual(result.signal.reason_code, "unadmitted_source_label")
        self.assertEqual(result.signal.action_status, ActionStatus.NOT_EVALUATED)
        self.assertEqual(result.action_proposals, ())

    def test_invalid_target_fails_closed_without_hiding_signal(self) -> None:
        result = self.helper.process(
            self.event(
                "evt-1",
                "2026-08-14T10:00:00Z",
                attributes={
                    "asset": "host-01",
                    "destination_port": "4444; shutdown",
                    "protocol": "tcp",
                },
            )
        )
        self.assertEqual(result.signal.disposition, SignalDisposition.FORWARDED)
        self.assertEqual(result.signal.action_status, ActionStatus.INVALID_TARGET)
        self.assertEqual(result.action_proposals, ())

    def test_unverified_source_never_emits_a_proposal(self) -> None:
        injection = "powershell -Command Remove-Item C:\\*"
        result = self.helper.process(
            self.event(
                "evt-1",
                "2026-08-14T10:00:00Z",
                attributes={
                    "asset": "host-01",
                    "destination_port": 4444,
                    "protocol": "tcp",
                    "command": injection,
                    "nested": {"shell": injection},
                },
            )
        )
        self.assertEqual(
            result.signal.action_status, ActionStatus.AUTHENTICATION_REQUIRED
        )
        self.assertEqual(result.action_proposals, ())
        self.assertNotIn(injection, str(result.to_dict()))

    def test_unbound_nonce_fields_do_not_defeat_scenario_grouping(self) -> None:
        first = self.event(
            "evt-1",
            "2026-08-14T10:00:00Z",
            attributes={
                "asset": "host-01",
                "destination_port": 4444,
                "protocol": "tcp",
                "command": "nonce-one",
            },
        )
        second = self.event(
            "evt-2",
            "2026-08-14T10:00:01Z",
            attributes={
                "asset": "host-01",
                "destination_port": 4444,
                "protocol": "tcp",
                "command": "nonce-two",
            },
        )
        self.helper.process(first)
        result = self.helper.process(second)
        self.assertEqual(result.signal.disposition, SignalDisposition.COALESCED)

    def test_signal_identity_binds_complete_source_event_content(self) -> None:
        first = self.event("same-id", "2026-08-14T10:00:00Z")
        second = self.event(
            "same-id",
            "2026-08-14T10:00:00Z",
            attributes={
                "asset": "host-01",
                "destination_port": 443,
                "protocol": "tcp",
            },
        )
        first_result = NoiseDampener(self.scenario, self.manifest).process(first)
        second_result = NoiseDampener(self.scenario, self.manifest).process(second)
        self.assertNotEqual(first.digest, second.digest)
        self.assertNotEqual(first_result.signal.signal_id, second_result.signal.signal_id)

    def test_event_without_playbook_is_forwarded_without_proposal(self) -> None:
        result = self.helper.process(
            self.event(
                "evt-1",
                "2026-08-14T10:00:00Z",
                event_type="network.observation",
            )
        )
        self.assertEqual(result.signal.disposition, SignalDisposition.FORWARDED)
        self.assertEqual(result.signal.action_status, ActionStatus.NO_PLAYBOOK)
        self.assertEqual(result.action_proposals, ())

    def test_same_inputs_produce_byte_equivalent_records(self) -> None:
        events = [
            self.event("evt-1", "2026-08-14T10:00:00Z"),
            self.event("evt-2", "2026-08-14T10:00:05Z"),
            self.event("evt-3", "2026-08-14T10:00:06Z", severity="critical"),
        ]
        first = NoiseDampener(self.scenario, self.manifest)
        second = NoiseDampener(self.scenario, self.manifest)
        self.assertEqual(
            [first.process(event).to_dict() for event in events],
            [second.process(event).to_dict() for event in events],
        )

    def test_manifest_for_another_scenario_is_refused(self) -> None:
        other_raw = scenario_dict()
        other_raw["scenario_id"] = "other-scenario"
        other = ScenarioPack.from_dict(other_raw)
        with self.assertRaisesRegex(ContractError, "scenario_id"):
            NoiseDampener(other, self.manifest)

    def test_scenario_event_size_limit_stops_processing(self) -> None:
        raw = scenario_dict()
        raw["policy"]["max_event_bytes"] = 256
        scenario = ScenarioPack.from_dict(raw)
        helper = NoiseDampener(scenario, HelperManifest.forge(scenario))
        oversized = self.event(
            "evt-1",
            "2026-08-14T10:00:00Z",
            attributes={
                "asset": "host-01",
                "destination_port": 4444,
                "protocol": "tcp",
                "padding": "x" * 512,
            },
        )
        with self.assertRaisesRegex(ContractError, "processing stopped closed"):
            helper.process(oversized)


if __name__ == "__main__":
    unittest.main()
