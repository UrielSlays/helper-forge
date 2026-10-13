"""Offline command-line interface for forging and running bounded helpers."""

from __future__ import annotations

import argparse
from collections import Counter
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Sequence, TextIO

from . import __version__
from .contracts import (
    ContractError,
    Event,
    HelperManifest,
    RUN_SUMMARY_VERSION,
    ScenarioPack,
    canonical_json,
    strict_json_loads,
)
from .engine import NoiseDampener, ProcessingResult


_MAX_CONTROL_DOCUMENT_BYTES = 1_048_576


def _read_text(path: str, label: str) -> str:
    try:
        with Path(path).open("rb") as handle:
            payload = handle.read(_MAX_CONTROL_DOCUMENT_BYTES + 1)
    except OSError as exc:
        raise ContractError(f"cannot read {label} {path!r}: {exc}") from exc
    if len(payload) > _MAX_CONTROL_DOCUMENT_BYTES:
        raise ContractError(
            f"{label} exceeds the {_MAX_CONTROL_DOCUMENT_BYTES}-byte control document limit"
        )
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{label} is not valid UTF-8: {exc}") from exc


def _load_object(path: str, label: str) -> Any:
    return strict_json_loads(_read_text(path, label))


def _load_scenario(path: str) -> ScenarioPack:
    return ScenarioPack.from_dict(_load_object(path, "scenario"))


def _load_manifest(path: str) -> HelperManifest:
    return HelperManifest.from_dict(_load_object(path, "manifest"))


def _load_events(path: str, scenario: ScenarioPack) -> list[Event]:
    events: list[Event] = []
    event_ids: set[str] = set()
    total_bytes = 0
    line_number = 0
    try:
        with Path(path).open("rb") as handle:
            while True:
                remaining_total = scenario.policy.max_total_event_bytes - total_bytes
                # The extra byte proves overflow. The per-event term prevents a
                # line without a newline from causing an unbounded allocation.
                read_limit = min(
                    scenario.policy.max_event_bytes + 3,
                    remaining_total + 1,
                )
                raw_line = handle.readline(read_limit)
                if not raw_line:
                    break
                line_number += 1
                total_bytes += len(raw_line)
                if total_bytes > scenario.policy.max_total_event_bytes:
                    raise ContractError(
                        "event stream exceeds scenario.policy.max_total_event_bytes"
                    )

                content = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
                if content.endswith(b"\r"):
                    content = content[:-1]
                if len(content) > scenario.policy.max_event_bytes:
                    raise ContractError(
                        f"event line {line_number} exceeds scenario.policy.max_event_bytes"
                    )
                if not content.strip():
                    continue
                if len(events) >= scenario.policy.max_event_count:
                    raise ContractError(
                        "event stream exceeds scenario.policy.max_event_count"
                    )
                try:
                    line = content.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ContractError(
                        f"event line {line_number} is not valid UTF-8: {exc}"
                    ) from exc
                try:
                    event = Event.from_dict(strict_json_loads(line))
                except ContractError as exc:
                    raise ContractError(f"event line {line_number}: {exc}") from exc
                if event.event_id in event_ids:
                    raise ContractError(
                        f"event line {line_number} repeats event_id {event.event_id!r}"
                    )
                if event.byte_size > scenario.policy.max_event_bytes:
                    raise ContractError(
                        f"event line {line_number} exceeds scenario.policy.max_event_bytes after normalization"
                    )
                event_ids.add(event.event_id)
                events.append(event)
    except OSError as exc:
        raise ContractError(f"cannot read event stream {path!r}: {exc}") from exc
    if not events:
        raise ContractError("event stream contains no events")
    return events


def _write_atomic(path: str, text: str) -> None:
    """Write a complete artifact or leave the prior destination untouched."""

    if path == "-":
        sys.stdout.write(text)
        return
    destination = Path(path)
    if not destination.parent.exists():
        raise ContractError(f"output directory does not exist: {destination.parent}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    except OSError as exc:
        raise ContractError(f"cannot write output {path!r}: {exc}") from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


def _manifest_text(manifest: HelperManifest) -> str:
    # Pretty-printing is for human inspection; helper_id uses canonical JSON.
    import json

    return json.dumps(
        manifest.to_dict(), ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"


def forge_command(args: argparse.Namespace) -> int:
    scenario = _load_scenario(args.scenario)
    manifest = HelperManifest.forge(scenario)
    _write_atomic(args.output, _manifest_text(manifest))
    return 0


def _result_lines(
    scenario: ScenarioPack,
    manifest: HelperManifest,
    results: Sequence[ProcessingResult],
) -> str:
    dispositions: Counter[str] = Counter()
    action_statuses: Counter[str] = Counter()
    proposal_count = 0
    lines: list[str] = []
    for result in results:
        dispositions[result.signal.disposition.value] += 1
        action_statuses[result.signal.action_status.value] += 1
        proposal_count += len(result.action_proposals)
        lines.append(canonical_json(result.to_dict()))
    summary = {
        "schema_version": RUN_SUMMARY_VERSION,
        "record_type": "summary",
        "helper_id": manifest.helper_id,
        "scenario_id": scenario.scenario_id,
        "events_processed": len(results),
        "dispositions": {
            key: dispositions.get(key, 0)
            for key in ("forwarded", "coalesced", "rejected")
        },
        "action_statuses": {
            key: action_statuses.get(key, 0)
            for key in (
                "authentication_required",
                "no_playbook",
                "invalid_target",
                "not_evaluated",
            )
        },
        "action_proposals": proposal_count,
    }
    lines.append(canonical_json(summary))
    return "\n".join(lines) + "\n"


def run_command(args: argparse.Namespace) -> int:
    # Validate every input before processing or touching the output.  A malformed
    # later line therefore cannot leave a plausible-looking partial result.
    scenario = _load_scenario(args.scenario)
    manifest = _load_manifest(args.manifest)
    manifest.assert_matches(scenario)
    events = _load_events(args.events, scenario)
    helper = NoiseDampener(scenario, manifest)
    results = [helper.process(event) for event in events]
    _write_atomic(args.output, _result_lines(scenario, manifest, results))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hephaestus",
        description="Forge and run bounded helpers without network access.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    forge = subparsers.add_parser(
        "forge", help="validate a Scenario Pack and emit a content-addressed manifest"
    )
    forge.add_argument("--scenario", required=True, help="Scenario Pack JSON path")
    forge.add_argument(
        "--output", "-o", required=True, help="manifest JSON path, or '-' for stdout"
    )
    forge.set_defaults(handler=forge_command)

    run = subparsers.add_parser(
        "run", help="run a forged noise-dampening helper over an event JSONL stream"
    )
    run.add_argument("--scenario", required=True, help="Scenario Pack JSON path")
    run.add_argument("--manifest", required=True, help="Helper Manifest JSON path")
    run.add_argument("--events", required=True, help="Event JSONL path")
    run.add_argument(
        "--output", "-o", required=True, help="result JSONL path, or '-' for stdout"
    )
    run.set_defaults(handler=run_command)
    return parser


def main(argv: Sequence[str] | None = None, *, stderr: TextIO | None = None) -> int:
    error_stream = stderr or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.handler(args))
    except ContractError as exc:
        error_stream.write(f"hephaestus: refused: {exc}\n")
        return 2
