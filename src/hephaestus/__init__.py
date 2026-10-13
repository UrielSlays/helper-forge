"""Hephaestus: an air-gap-first forge for bounded local helpers."""

from .contracts import (
    ActionProposal,
    ActionStatus,
    ActionType,
    ContractError,
    Event,
    HelperManifest,
    Playbook,
    ScenarioPack,
    ScenarioPolicy,
    Severity,
    Signal,
    SignalDisposition,
)
from .engine import NoiseDampener, ProcessingResult

__all__ = [
    "ActionProposal",
    "ActionStatus",
    "ActionType",
    "ContractError",
    "Event",
    "HelperManifest",
    "NoiseDampener",
    "Playbook",
    "ProcessingResult",
    "ScenarioPack",
    "ScenarioPolicy",
    "Severity",
    "Signal",
    "SignalDisposition",
]

__version__ = "0.0.0"
