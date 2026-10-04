"""Shared constants and tiny data holders (kept dependency-free)."""

from __future__ import annotations

from dataclasses import dataclass, field

# Ordered pipeline phases. Capture phases are interactive (a human uses the app).
PHASES = [
    "claims",
    "static",
    "capture_idle",
    "capture_use",
    "capture_optout",
    "classify",
    "score",
    "report",
]
CAPTURE_PHASES = ("capture_idle", "capture_use", "capture_optout")
CAPTURE_SHORT = {"capture_idle": "idle", "capture_use": "use", "capture_optout": "optout"}
SHORT_TO_PHASE = {v: k for k, v in CAPTURE_SHORT.items()}
OPTIONAL_PHASES = {"capture_optout"}

# Attempt statuses
RUNNING, DONE, PARTIAL, FAILED, INTERRUPTED = "running", "done", "partial", "failed", "interrupted"
USABLE_CAPTURE_STATUSES = (DONE, PARTIAL)

# Flow labels produced by the classifier
L_TELEMETRY_3P = "telemetry_third_party"
L_TELEMETRY_1P = "telemetry_first_party"
L_SUSPECT = "suspect"
L_FIRST_PARTY = "first_party"
L_ALLOWED = "allowed"
L_UNKNOWN = "unknown"
L_OPAQUE = "opaque_unknown"
TELEMETRY_LABELS = (L_TELEMETRY_3P, L_TELEMETRY_1P)

# Verdicts
V_CONTRADICTED = "CONTRADICTED"
V_WARNING = "WARNING"
V_NOT_CONTRADICTED = "NOT_CONTRADICTED"
V_INCONCLUSIVE = "INCONCLUSIVE"

# Claim kinds (what the marketing/docs promise)
CLAIM_KINDS = [
    "no_telemetry",
    "local_first",
    "privacy_friendly",
    "open_source",
    "no_third_party_sharing",
]


@dataclass
class PhaseResult:
    """Return value of a phase function."""

    status: str = DONE
    summary: dict = field(default_factory=dict)
    note: str = ""
