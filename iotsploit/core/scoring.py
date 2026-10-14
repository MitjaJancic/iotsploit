"""
scoring.py

Implements the Damage Score rubric as a runtime-configurable weighting,
plus pass-through CVSS for comparability with prior work.

Weights are NOT hardcoded constants: they're loaded from a weights
profile (default or user-supplied) so the same findings can be
re-scored under different household risk postures without re-running
any check. This is the "adjustable to different risk postures" design
point for your discussion chapter.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

DIMENSIONS = ["physical_safety", "privacy", "financial", "availability", "chaining_depth"]

DIMENSION_DESCRIPTIONS = {
    "chaining_depth": {
        0: "Isolated (Single Endpoint)",
        1: "Local Subnet (Adjacent Pivot)",
        2: "Multi-Service Pivot (Hub/Broker Compromise)",
        3: "Full Perimeter to Physical Breach",
    },
    "physical_safety": {
        0: "None (Digital Only)",
        1: "Environmental Nuisance / State Tampering",
        2: "Equipment Hazard / Actuator Control",
        3: "Physical Perimeter Breach (Door/Lock/Gate Actuated)",
    },
    "privacy": {
        0: "None",
        1: "Device Fingerprint / Metadata Leak",
        2: "Continuous Telemetry / Sensor Exposure",
        3: "Surveillance Feed / Identity Exfiltration",
    },
    "financial": {
        0: "Negligible",
        1: "Minor / Single Billing Anomaly",
        2: "High Consumption / Meter Fraud",
        3: "Direct Financial Extraction / Fraud",
    },
    "availability": {
        0: "Normal Operation",
        1: "Transient Degradation",
        2: "Service Denial / Daemon Crash",
        3: "Permanent Device Lockout / Bricked",
    },
}

DEFAULT_WEIGHTS = {
    "physical_safety": 1.0,
    "privacy": 1.0,
    "financial": 1.0,
    "availability": 1.0,
    "chaining_depth": 1.0,
}


@dataclass
class Finding:
    finding_id: str
    device_id: str
    check_name: str
    description: str
    cvss: float | None
    damage: dict  # raw 0-3 scores per dimension, from the check or CVE entry
    evidence_path: str | None = None

    def damage_score(self, weights: dict | None = None) -> float:
        w = weights or DEFAULT_WEIGHTS
        return sum(self.damage.get(dim, 0) * w.get(dim, 1.0) for dim in DIMENSIONS)

    def impact_levels(self) -> dict[str, str]:
        """Returns human-readable descriptive impact progression labels for each scored dimension."""
        levels = {}
        for dim in DIMENSIONS:
            val = int(self.damage.get(dim, 0))
            clamped = min(max(val, 0), 3)
            levels[dim] = DIMENSION_DESCRIPTIONS.get(dim, {}).get(clamped, str(val))
        return levels

    def chaining_description(self) -> str:
        depth = int(self.damage.get("chaining_depth", 0))
        clamped = min(max(depth, 0), 3)
        return DIMENSION_DESCRIPTIONS["chaining_depth"].get(clamped, "Isolated")

    def to_dict(self, weights: dict | None = None) -> dict:
        d = asdict(self)
        d["damage_score"] = self.damage_score(weights)
        d["impact_levels"] = self.impact_levels()
        d["chaining_level"] = self.chaining_description()
        return d


def load_weights(path: str | Path | None) -> dict:
    """Load a weights YAML file, e.g.:

    physical_safety: 2.0   # weight toward a safety-focused household
    privacy: 0.5
    financial: 1.0
    availability: 1.0
    chaining_depth: 1.5
    """
    if path is None:
        return dict(DEFAULT_WEIGHTS)
    import yaml
    raw = yaml.safe_load(Path(path).read_text())
    weights = dict(DEFAULT_WEIGHTS)
    weights.update(raw or {})
    return weights


def aggregate(findings: list[Finding], weights: dict) -> dict:
    """Roll findings up into per-device and overall summaries."""
    by_device: dict[str, list[Finding]] = {}
    for f in findings:
        by_device.setdefault(f.device_id, []).append(f)

    summary = {}
    for device_id, flist in by_device.items():
        summary[device_id] = {
            "finding_count": len(flist),
            "total_damage_score": sum(f.damage_score(weights) for f in flist),
            "max_damage_score": max((f.damage_score(weights) for f in flist), default=0),
            "max_cvss": max((f.cvss or 0 for f in flist), default=0),
        }
    return summary
