from __future__ import annotations

from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.support import ROOT, SRC, event_dict, scenario_dict

from hephaestus.cli import main
from hephaestus.contracts import HelperManifest


class CommandLineTests(unittest.TestCase):
    def test_forge_then_run_example_end_to_end(self) -> None:
        example = ROOT / "examples" / "airgap-port-noise"
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            results_path = Path(temporary) / "results.jsonl"
            self.assertEqual(
                main(
                    [
                        "forge",
                        "--scenario",
                        str(example / "scenario.json"),
                        "--output",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            manifest = HelperManifest.from_dict(
                json.loads(manifest_path.read_text(encoding="utf-8"))
            )
            self.assertTrue(manifest.helper_id.startswith("sha256:"))

            self.assertEqual(
                main(
                    [
                        "run",
                        "--scenario",
                        str(example / "scenario.json"),
                        "--manifest",
                        str(manifest_path),
                        "--events",
                        str(example / "events.jsonl"),
                        "--output",
                        str(results_path),
                    ]
                ),
                0,
            )
            text = results_path.read_text(encoding="utf-8")
            records = [json.loads(line) for line in text.splitlines()]
            self.assertEqual(len(records), 6)
            self.assertEqual(records[0]["signal"]["disposition"], "forwarded")
            self.assertEqual(records[1]["signal"]["disposition"], "coalesced")
            self.assertEqual(records[2]["signal"]["disposition"], "forwarded")
            self.assertEqual(records[3]["signal"]["disposition"], "rejected")
            self.assertEqual(records[4]["signal"]["disposition"], "forwarded")
            self.assertEqual(records[-1]["record_type"], "summary")
            self.assertEqual(
                records[0]["schema_version"],
                "hephaestus.prototype.event-result/v0",
            )
            self.assertEqual(
                records[-1]["schema_version"],
                "hephaestus.prototype.run-summary/v0",
            )
            self.assertEqual(
                records[-1]["dispositions"],
                {"forwarded": 3, "coalesced": 1, "rejected": 1},
            )
            self.assertNotIn("this text is inert", text)
            for result in records[:-1]:
                self.assertEqual(result["action_proposals"], [])
            self.assertEqual(records[-1]["action_proposals"], 0)

    def test_forge_is_deterministic(self) -> None:
        example = ROOT / "examples" / "airgap-port-noise" / "scenario.json"
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.json"
            second = Path(temporary) / "second.json"
            self.assertEqual(
                main(["forge", "--scenario", str(example), "-o", str(first)]), 0
            )
            self.assertEqual(
                main(["forge", "--scenario", str(example), "-o", str(second)]), 0
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_malformed_late_event_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scenario_path = directory / "scenario.json"
            manifest_path = directory / "manifest.json"
            events_path = directory / "events.jsonl"
            output_path = directory / "results.jsonl"
            scenario_path.write_text(json.dumps(scenario_dict()), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "forge",
                        "--scenario",
                        str(scenario_path),
                        "-o",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            good = json.dumps(event_dict("evt-1", "2026-08-14T10:00:00Z"))
            events_path.write_text(good + "\n{not-json}\n", encoding="utf-8")
            output_path.write_text("previous-known-good\n", encoding="utf-8")
            errors = StringIO()
            code = main(
                [
                    "run",
                    "--scenario",
                    str(scenario_path),
                    "--manifest",
                    str(manifest_path),
                    "--events",
                    str(events_path),
                    "-o",
                    str(output_path),
                ],
                stderr=errors,
            )
            self.assertEqual(code, 2)
            self.assertIn("event line 2", errors.getvalue())
            self.assertEqual(
                output_path.read_text(encoding="utf-8"), "previous-known-good\n"
            )

    def test_duplicate_event_identity_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scenario_path = directory / "scenario.json"
            manifest_path = directory / "manifest.json"
            events_path = directory / "events.jsonl"
            output_path = directory / "results.jsonl"
            scenario_path.write_text(json.dumps(scenario_dict()), encoding="utf-8")
            main(
                [
                    "forge",
                    "--scenario",
                    str(scenario_path),
                    "-o",
                    str(manifest_path),
                ]
            )
            event = json.dumps(event_dict("evt-1", "2026-08-14T10:00:00Z"))
            events_path.write_text(event + "\n" + event + "\n", encoding="utf-8")
            errors = StringIO()
            code = main(
                [
                    "run",
                    "--scenario",
                    str(scenario_path),
                    "--manifest",
                    str(manifest_path),
                    "--events",
                    str(events_path),
                    "-o",
                    str(output_path),
                ],
                stderr=errors,
            )
            self.assertEqual(code, 2)
            self.assertFalse(output_path.exists())
            self.assertIn("repeats event_id", errors.getvalue())

    def test_stream_byte_and_event_count_limits_preserve_existing_output(self) -> None:
        first_line = json.dumps(event_dict("evt-1", "2026-08-14T10:00:00Z"))
        second_line = json.dumps(event_dict("evt-2", "2026-08-14T10:00:01Z"))
        cases = (
            (
                "max_total_event_bytes",
                max(256, len((first_line + "\n").encode("utf-8"))),
            ),
            ("max_event_count", 1),
        )
        for limit_name, limit_value in cases:
            with self.subTest(limit=limit_name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                raw_scenario = scenario_dict()
                raw_scenario["policy"][limit_name] = limit_value
                if limit_name == "max_event_count":
                    raw_scenario["policy"]["max_active_groups"] = 1
                scenario_path = directory / "scenario.json"
                manifest_path = directory / "manifest.json"
                events_path = directory / "events.jsonl"
                output_path = directory / "results.jsonl"
                scenario_path.write_text(json.dumps(raw_scenario), encoding="utf-8")
                self.assertEqual(
                    main(
                        [
                            "forge",
                            "--scenario",
                            str(scenario_path),
                            "-o",
                            str(manifest_path),
                        ]
                    ),
                    0,
                )
                events_path.write_text(
                    first_line + "\n" + second_line + "\n", encoding="utf-8"
                )
                output_path.write_text("previous-known-good\n", encoding="utf-8")
                errors = StringIO()
                code = main(
                    [
                        "run",
                        "--scenario",
                        str(scenario_path),
                        "--manifest",
                        str(manifest_path),
                        "--events",
                        str(events_path),
                        "-o",
                        str(output_path),
                    ],
                    stderr=errors,
                )
                self.assertEqual(code, 2)
                self.assertIn(limit_name, errors.getvalue())
                self.assertEqual(
                    output_path.read_text(encoding="utf-8"), "previous-known-good\n"
                )

    def test_active_group_overflow_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw_scenario = scenario_dict()
            raw_scenario["policy"]["max_active_groups"] = 1
            scenario_path = directory / "scenario.json"
            manifest_path = directory / "manifest.json"
            events_path = directory / "events.jsonl"
            output_path = directory / "results.jsonl"
            scenario_path.write_text(json.dumps(raw_scenario), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "forge",
                        "--scenario",
                        str(scenario_path),
                        "-o",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            first = event_dict("evt-1", "2026-08-14T10:00:00Z")
            second = event_dict(
                "evt-2",
                "2026-08-14T10:00:01Z",
                attributes={
                    "asset": "host-02",
                    "destination_port": 5555,
                    "protocol": "tcp",
                },
            )
            events_path.write_text(
                json.dumps(first) + "\n" + json.dumps(second) + "\n",
                encoding="utf-8",
            )
            output_path.write_text("previous-known-good\n", encoding="utf-8")
            errors = StringIO()
            code = main(
                [
                    "run",
                    "--scenario",
                    str(scenario_path),
                    "--manifest",
                    str(manifest_path),
                    "--events",
                    str(events_path),
                    "-o",
                    str(output_path),
                ],
                stderr=errors,
            )
            self.assertEqual(code, 2)
            self.assertIn("max_active_groups", errors.getvalue())
            self.assertEqual(
                output_path.read_text(encoding="utf-8"), "previous-known-good\n"
            )

    def test_oversized_unterminated_line_is_refused_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw_scenario = scenario_dict()
            raw_scenario["policy"]["max_event_bytes"] = 256
            raw_scenario["policy"]["max_total_event_bytes"] = 1024
            scenario_path = directory / "scenario.json"
            manifest_path = directory / "manifest.json"
            events_path = directory / "events.jsonl"
            output_path = directory / "results.jsonl"
            scenario_path.write_text(json.dumps(raw_scenario), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "forge",
                        "--scenario",
                        str(scenario_path),
                        "-o",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            events_path.write_bytes(b"{" + (b"x" * 300))
            output_path.write_text("previous-known-good\n", encoding="utf-8")
            errors = StringIO()
            code = main(
                [
                    "run",
                    "--scenario",
                    str(scenario_path),
                    "--manifest",
                    str(manifest_path),
                    "--events",
                    str(events_path),
                    "-o",
                    str(output_path),
                ],
                stderr=errors,
            )
            self.assertEqual(code, 2)
            self.assertIn("max_event_bytes", errors.getvalue())
            self.assertNotIn("invalid JSON", errors.getvalue())
            self.assertEqual(
                output_path.read_text(encoding="utf-8"), "previous-known-good\n"
            )

    def test_invalid_utf8_is_refused_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scenario_path = directory / "scenario.json"
            manifest_path = directory / "manifest.json"
            events_path = directory / "events.jsonl"
            output_path = directory / "results.jsonl"
            scenario_path.write_text(json.dumps(scenario_dict()), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "forge",
                        "--scenario",
                        str(scenario_path),
                        "-o",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            good = json.dumps(event_dict("evt-1", "2026-08-14T10:00:00Z"))
            events_path.write_bytes(good.encode("utf-8") + b"\n\xff\n")
            output_path.write_text("previous-known-good\n", encoding="utf-8")
            errors = StringIO()
            code = main(
                [
                    "run",
                    "--scenario",
                    str(scenario_path),
                    "--manifest",
                    str(manifest_path),
                    "--events",
                    str(events_path),
                    "-o",
                    str(output_path),
                ],
                stderr=errors,
            )
            self.assertEqual(code, 2)
            self.assertIn("not valid UTF-8", errors.getvalue())
            self.assertEqual(
                output_path.read_text(encoding="utf-8"), "previous-known-good\n"
            )

    def test_hostile_json_failures_are_controlled_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scenario_path = directory / "scenario.json"
            manifest_path = directory / "manifest.json"
            events_path = directory / "events.jsonl"
            output_path = directory / "results.jsonl"
            scenario_path.write_text(json.dumps(scenario_dict()), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "forge",
                        "--scenario",
                        str(scenario_path),
                        "-o",
                        str(manifest_path),
                    ]
                ),
                0,
            )

            prefix = (
                '{"schema_version":"hephaestus.prototype.event/v0",'
                '"event_id":"evt-1","observed_at":"2026-08-14T10:00:00Z",'
                '"source":"sensor.alpha","severity":"low",'
                '"event_type":"network.exposed_port","attributes":{"bad":'
            )
            hostile_values = [
                ("[" * 1500 + "0" + "]" * 1500, "JSON nesting exceeds the maximum depth"),
                ("9" * 5000, "invalid JSON"),
            ]
            for hostile, expected_refusal in hostile_values:
                events_path.write_text(prefix + hostile + "}}\n", encoding="utf-8")
                output_path.write_text("previous-known-good\n", encoding="utf-8")
                errors = StringIO()
                code = main(
                    [
                        "run",
                        "--scenario",
                        str(scenario_path),
                        "--manifest",
                        str(manifest_path),
                        "--events",
                        str(events_path),
                        "-o",
                        str(output_path),
                    ],
                    stderr=errors,
                )
                self.assertEqual(code, 2)
                self.assertIn(expected_refusal, errors.getvalue())
                self.assertEqual(
                    output_path.read_text(encoding="utf-8"),
                    "previous-known-good\n",
                )

    def test_python_module_entrypoint_works_offline(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SRC)
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "hephaestus",
                "forge",
                "--scenario",
                str(ROOT / "examples" / "airgap-port-noise" / "scenario.json"),
                "--output",
                "-",
            ],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        manifest = HelperManifest.from_dict(json.loads(completed.stdout))
        self.assertTrue(manifest.helper_id.startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
