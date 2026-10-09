"""Detection-as-code engine: loads detections/*.yml and runs them against the store."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .store import Store

DETECTIONS_DIR = Path(__file__).resolve().parent.parent / "detections"
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Detection:
    id: str
    title: str
    severity: str
    description: str
    query: str
    response: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)
    tests: dict = field(default_factory=dict)


@dataclass
class DetectionRun:
    detection: Detection
    hits: list[dict]
    elapsed_ms: float


def load_detections(directory: Path = DETECTIONS_DIR) -> list[Detection]:
    out = []
    for path in sorted(directory.glob("*.yml")):
        raw = yaml.safe_load(path.read_text())
        known = {k: raw[k] for k in Detection.__dataclass_fields__ if k in raw}
        out.append(Detection(**known))
    return out


def run_all(store: Store, detections: list[Detection] | None = None) -> list[DetectionRun]:
    runs = []
    for d in detections or load_detections():
        res = store.query(d.query)
        runs.append(DetectionRun(d, res.rows, res.elapsed_ms))
    return runs


def group_incidents(runs: list[DetectionRun]) -> list[dict]:
    """Correlate detection hits into one incident per agent."""
    by_agent: dict[str, dict] = {}
    for run in runs:
        for hit in run.hits:
            inc = by_agent.setdefault(
                hit["agent_id"],
                {"agent_id": hit["agent_id"], "sessions": set(), "detections": [], "severity": "low",
                 "first_seen": hit["first_seen"], "last_seen": hit["last_seen"], "response": set()},
            )
            inc["sessions"].add(hit["session_id"])
            inc["detections"].append({
                "id": run.detection.id, "title": run.detection.title,
                "severity": run.detection.severity, "evidence": hit.get("evidence", []),
                "mitre_attack": run.detection.mitre_attack, "hits": hit.get("hits"),
                "first_seen": str(hit["first_seen"]),
            })
            inc["response"].update(run.detection.response)
            inc["first_seen"] = min(str(inc["first_seen"]), str(hit["first_seen"]))
            inc["last_seen"] = max(str(inc["last_seen"]), str(hit["last_seen"]))
            if SEVERITY_RANK[run.detection.severity] > SEVERITY_RANK[inc["severity"]]:
                inc["severity"] = run.detection.severity
    incidents = []
    for inc in by_agent.values():
        inc["sessions"] = sorted(inc["sessions"])
        inc["response"] = sorted(inc["response"])
        inc["detections"].sort(key=lambda d: d["first_seen"])
        incidents.append(inc)
    return sorted(incidents, key=lambda i: (-SEVERITY_RANK[i["severity"]], -len(i["detections"])))
