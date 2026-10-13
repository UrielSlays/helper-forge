# Hephaestus

[![tests](https://github.com/UrielSlays/helper-forge/actions/workflows/tests.yml/badge.svg)](https://github.com/UrielSlays/helper-forge/actions/workflows/tests.yml)

**A local forge that builds small, bounded helpers for systems that cannot trust the network.**

## The idea

A system watching a busy environment drowns in repetitive observations. Hephaestus lets it build narrow helpers instead. Each helper takes one input stream and turns it into a smaller flow of signals that a parent system or an analyst can audit. Each one gets one job, one input contract, one bounded output contract, and no authority of its own.

The included example is security telemetry from an air-gapped network, where repetitive sensor noise buries the events that matter.

## The rule

**Generated helpers may reduce information. They may not grant themselves authority.**

Event payloads are data, never instructions. Helpers hold no credentials, never deploy themselves, never change their own policy, and never turn text into commands.

## What it does

Given a Scenario Pack and a stream of telemetry events, Hephaestus:

- builds a Helper Manifest, identified by a hash of its contents and bound to the exact runtime files that produced it;
- forwards high- and critical-severity events from admitted sources;
- coalesces repeated lower-severity events into summaries;
- rejects events from sources the scenario does not list, and refuses malformed input as a whole run;
- links every signal back to the events behind it by digest; and
- proposes no actions.

It runs on the Python standard library alone and installs offline.

## Run it

Python 3.11 or newer, and nothing to install. Run from the repository root; outputs go to their own directory.

PowerShell:

    $env:PYTHONPATH = (Resolve-Path .\src).Path
    $runDir = Join-Path ([System.IO.Path]::GetTempPath()) "hephaestus-run"
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null

    python -m hephaestus forge --scenario .\examples\airgap-port-noise\scenario.json --output "$runDir\manifest.json"
    python -m hephaestus run --scenario .\examples\airgap-port-noise\scenario.json --manifest "$runDir\manifest.json" --events .\examples\airgap-port-noise\events.jsonl --output "$runDir\results.jsonl"
    Get-Content "$runDir\results.jsonl"

bash or zsh:

    export PYTHONPATH="$PWD/src"
    run_dir="$(mktemp -d)"

    python3 -m hephaestus forge --scenario examples/airgap-port-noise/scenario.json --output "$run_dir/manifest.json"
    python3 -m hephaestus run --scenario examples/airgap-port-noise/scenario.json --manifest "$run_dir/manifest.json" --events examples/airgap-port-noise/events.jsonl --output "$run_dir/results.jsonl"
    cat "$run_dir/results.jsonl"

On the included five-event example, the run forwards three events, coalesces one, rejects one, and proposes no actions.

## Install offline

PowerShell:

    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install --no-index --no-deps .
    .\.venv\Scripts\hephaestus.exe --version

bash or zsh:

    python3 -m venv .venv
    .venv/bin/python -m pip install --no-index --no-deps .
    .venv/bin/hephaestus --version

Debian and Ubuntu package `venv` separately: `sudo apt install python3-venv`.

## Tests

    python -m unittest discover -s tests -t .

53 tests, standard library only. CI runs them on Linux and Windows against Python 3.11 through 3.15.

## Layout

```text
src/hephaestus/   forge, strict parser, and helper runtime
schemas/          JSON schemas for every record the forge reads or writes
examples/         a reviewed, non-sensitive scenario
tests/            the test suite
```

## License

Copyright (c) 2026 Clinton Cuzzort. All rights reserved. See `LICENSE`.
