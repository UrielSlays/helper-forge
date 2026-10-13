from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tests.support import event_dict, scenario_dict

from hephaestus.contracts import (
    MAX_JSON_NESTING_DEPTH,
    ActionType,
    ContractError,
    Event,
    HelperManifest,
    ScenarioPack,
    content_digest,
    implementation_digest,
    strict_json_loads,
    validate_action_target,
)


class ScenarioContractTests(unittest.TestCase):
    def test_round_trip_is_stable_and_content_addressed(self) -> None:
        scenario = ScenarioPack.from_dict(scenario_dict())
        round_trip = ScenarioPack.from_dict(scenario.to_dict())
        self.assertEqual(scenario.to_dict(), round_trip.to_dict())
        self.assertEqual(scenario.digest, round_trip.digest)

        first = HelperManifest.forge(scenario)
        second = HelperManifest.forge(round_trip)
        self.assertEqual(first.to_dict(), second.to_dict())
        body = first.to_dict()
        del body["helper_id"]
        self.assertEqual(first.helper_id, content_digest(body))
        HelperManifest.from_dict(first.to_dict())

    def test_manifest_tampering_is_rejected(self) -> None:
        manifest = HelperManifest.forge(ScenarioPack.from_dict(scenario_dict())).to_dict()
        manifest["scenario_id"] = "different-scenario"
        with self.assertRaisesRegex(ContractError, "helper_id does not match"):
            HelperManifest.from_dict(manifest)

    def test_unknown_fields_and_weakened_severity_policy_are_rejected(self) -> None:
        unknown = scenario_dict()
        unknown["surprise"] = True
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            ScenarioPack.from_dict(unknown)

        weakened = scenario_dict()
        weakened["policy"]["preserve_severities"] = ["critical"]
        with self.assertRaisesRegex(ContractError, "high.*critical"):
            ScenarioPack.from_dict(weakened)

    def test_playbook_cannot_bind_command_like_event_fields(self) -> None:
        raw = scenario_dict()
        raw["playbooks"][0]["bindings"]["host"] = "Command"
        with self.assertRaisesRegex(ContractError, "execution field"):
            ScenarioPack.from_dict(raw)

    def test_grouping_fields_must_cover_every_action_binding(self) -> None:
        raw = scenario_dict()
        raw["playbooks"][0]["grouping_fields"] = ["asset"]
        with self.assertRaisesRegex(ContractError, "every action-bound"):
            ScenarioPack.from_dict(raw)

    def test_implementation_identity_changes_when_runtime_bytes_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_root = Path(temporary)
            filenames = ("__init__.py", "__main__.py", "cli.py", "contracts.py", "engine.py")
            for filename in filenames:
                (package_root / filename).write_text(filename, encoding="utf-8")
            first = implementation_digest(package_root=package_root)
            (package_root / "engine.py").write_text("changed", encoding="utf-8")
            second = implementation_digest(package_root=package_root)
            self.assertNotEqual(first, second)

    def test_duplicate_playbook_matches_are_rejected(self) -> None:
        raw = scenario_dict()
        duplicate = dict(raw["playbooks"][0])
        duplicate["playbook_id"] = "another-playbook"
        duplicate["bindings"] = dict(duplicate["bindings"])
        raw["playbooks"].append(duplicate)
        with self.assertRaisesRegex(ContractError, "one playbook per event type"):
            ScenarioPack.from_dict(raw)

    def test_active_group_limit_cannot_exceed_event_count_limit(self) -> None:
        raw = scenario_dict()
        raw["policy"]["max_event_count"] = 2
        raw["policy"]["max_active_groups"] = 3
        with self.assertRaisesRegex(ContractError, "may not exceed max_event_count"):
            ScenarioPack.from_dict(raw)

    def test_prototype_resource_ceilings_are_conservative(self) -> None:
        cases = {
            "max_event_bytes": 65_537,
            "max_total_event_bytes": 16_777_217,
            "max_event_count": 50_001,
            "max_active_groups": 8_193,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                raw = scenario_dict()
                raw["policy"][field] = value
                with self.assertRaisesRegex(ContractError, field):
                    ScenarioPack.from_dict(raw)


class EventContractTests(unittest.TestCase):
    def test_event_grouping_key_uses_only_scenario_owned_fields(self) -> None:
        first = Event.from_dict(event_dict("evt-1", "2026-08-14T10:00:00Z"))
        second = Event.from_dict(event_dict("evt-2", "2026-08-14T10:00:20Z"))
        self.assertEqual(first.to_dict(), Event.from_dict(first.to_dict()).to_dict())
        fields = ("asset", "destination_port", "protocol")
        self.assertEqual(
            first.grouping_fingerprint(fields), second.grouping_fingerprint(fields)
        )
        self.assertNotEqual(first.digest, second.digest)

        with_nonce = Event.from_dict(
            event_dict(
                "evt-3",
                "2026-08-14T10:00:21Z",
                attributes={
                    "asset": "host-01",
                    "destination_port": 4444,
                    "protocol": "tcp",
                    "command": "attacker nonce",
                },
            )
        )
        self.assertEqual(
            first.grouping_fingerprint(fields), with_nonce.grouping_fingerprint(fields)
        )
        self.assertNotEqual(first.digest, with_nonce.digest)

    def test_event_rejects_unknown_top_level_command(self) -> None:
        raw = event_dict("evt-1", "2026-08-14T10:00:00Z")
        raw["command"] = "do something"
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            Event.from_dict(raw)

    def test_event_rejects_invalid_timestamp_and_nonfinite_number(self) -> None:
        bad_time = event_dict("evt-1", "not-a-time")
        with self.assertRaises(ContractError):
            Event.from_dict(bad_time)
        with self.assertRaisesRegex(ContractError, "non-finite"):
            strict_json_loads('{"value": NaN}')

    def test_strict_json_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(ContractError, "duplicate JSON object key"):
            strict_json_loads('{"event_id":"one","event_id":"two"}')

    def test_hostile_json_depth_and_integer_size_become_controlled_refusals(self) -> None:
        deeply_nested = "[" * 2000 + "0" + "]" * 2000
        with self.assertRaisesRegex(
            ContractError, "JSON nesting exceeds the maximum depth"
        ):
            strict_json_loads(deeply_nested)
        with self.assertRaisesRegex(ContractError, "invalid JSON"):
            strict_json_loads("9" * 5000)

    def test_json_nesting_bound_is_exact_for_arrays_and_objects(self) -> None:
        limit = MAX_JSON_NESTING_DEPTH
        for opener, closer in (("[", "]"), ('{"k":', "}")):
            with self.subTest(opener=opener):
                strict_json_loads(opener * limit + "0" + closer * limit)
                one_too_deep = opener * (limit + 1) + "0" + closer * (limit + 1)
                with self.assertRaisesRegex(
                    ContractError, "JSON nesting exceeds the maximum depth"
                ):
                    strict_json_loads(one_too_deep)

    def test_json_nesting_bound_counts_structure_not_text_or_siblings(self) -> None:
        many = MAX_JSON_NESTING_DEPTH + 1
        record = {
            "after_escaped_quote": '"' + "[{" * many,
            "ends_with_backslash": "\\",
            "plain_bracket_text": "[{" * many,
            "siblings": [[] for _ in range(many)],
        }
        self.assertEqual(strict_json_loads(json.dumps(record)), record)

    def test_event_contract_refuses_nesting_before_the_parser_bound_does(self) -> None:
        def event_text(list_levels: int) -> str:
            nested: list[object] = []
            for _ in range(list_levels - 1):
                nested = [nested]
            return json.dumps(
                event_dict(
                    "evt-1",
                    "2026-08-14T10:00:00Z",
                    attributes={"asset": "host-01", "deep": nested},
                )
            )

        Event.from_dict(strict_json_loads(event_text(8)))
        with self.assertRaisesRegex(
            ContractError, r"event\.attributes\.deep.* exceeds the maximum nesting depth"
        ):
            Event.from_dict(strict_json_loads(event_text(9)))

    def test_strict_json_accepts_text_only(self) -> None:
        for not_text in (b"[]", bytearray(b"[]"), None, 7):
            with self.subTest(value=not_text):
                with self.assertRaisesRegex(ContractError, "JSON input must be text"):
                    strict_json_loads(not_text)  # type: ignore[arg-type]

    def test_non_unicode_scalar_strings_are_rejected(self) -> None:
        event = event_dict(
            "evt-1",
            "2026-08-14T10:00:00Z",
            attributes={"asset": "host-01", "bad": "\ud800"},
        )
        with self.assertRaisesRegex(ContractError, "non-Unicode-scalar"):
            Event.from_dict(event)

        scenario = scenario_dict()
        scenario["purpose"] = "\ud800"
        with self.assertRaisesRegex(ContractError, "non-Unicode-scalar"):
            ScenarioPack.from_dict(scenario)

        with self.assertRaisesRegex(ContractError, "non-Unicode-scalar"):
            content_digest({"bad": "\ud800"})
        with self.assertRaisesRegex(ContractError, "non-Unicode-scalar"):
            strict_json_loads('{"\\ud800":true}')


class ActionTargetTests(unittest.TestCase):
    def test_close_port_target_is_exact_and_typed(self) -> None:
        target = validate_action_target(
            ActionType.CLOSE_PORT,
            {"host": "node-1", "port": 443, "protocol": "TCP"},
        )
        self.assertEqual(target, {"host": "node-1", "port": 443, "protocol": "tcp"})
        with self.assertRaises(ContractError):
            validate_action_target(
                ActionType.CLOSE_PORT,
                {
                    "host": "node-1",
                    "port": 443,
                    "protocol": "tcp",
                    "command": "shutdown",
                },
            )

    def test_block_address_is_parsed_not_executed(self) -> None:
        self.assertEqual(
            validate_action_target(ActionType.BLOCK_ADDRESS, {"address": "2001:0db8::1"}),
            {"address": "2001:db8::1"},
        )
        with self.assertRaises(ContractError):
            validate_action_target(
                ActionType.BLOCK_ADDRESS, {"address": "127.0.0.1; reboot"}
            )


if __name__ == "__main__":
    unittest.main()
