"""End-to-end demo: load -> detect -> triage -> contain -> verify -> guardrail.

    python -m agentwatch.demo --rows 20000000
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from . import simulator
from .detect import group_incidents, load_detections, run_all
from .hunt import ATTACKS, GuardrailViolation, hunt, run_sql
from .llm import LLM
from .remediate import contain, verify
from .store import Store
from .triage import triage

REPORT = Path("reports/latest.json")


def banner(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 70 - len(text)))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=20_000_000)
    ap.add_argument("--skip-load", action="store_true", help="reuse data already loaded")
    args = ap.parse_args()

    store, llm = Store(), LLM()
    print(f"backend={store.backend}  llm={llm.name}")

    if not args.skip_load:
        banner("1. LOAD fleet telemetry")
        stats = simulator.load(store, args.rows)
        print(f"{stats['rows']:,} events from {simulator.N_AGENTS} agents "
              f"(background loaded in {stats['background_load_s']}s)")

    banner("2. DETECT")
    t_pipeline = time.perf_counter()
    runs = run_all(store, load_detections())
    for r in runs:
        agents = ", ".join(h["agent_id"] for h in r.hits) or "-"
        print(f"{r.detection.id}  {r.elapsed_ms:7.1f} ms  {len(r.hits)} hit(s)  {agents:<14} {r.detection.title}")
    scan_ms = sum(r.elapsed_ms for r in runs)
    print(f"all detections: {scan_ms:.0f} ms over the full table")
    incidents = group_incidents(runs)
    if not incidents:
        print("no incidents")
        return

    inc = incidents[0]
    banner(f"3. TRIAGE {inc['agent_id']} ({inc['severity'].upper()}, {len(inc['detections'])} detections)")
    tri = triage(store, inc, llm)
    print(tri["summary"])

    banner("4. CONTAIN")
    controls = contain(store, inc)
    for c in controls:
        print(f"{c['control']:<20} scope={c['scope']:<24} ({c['reason']})")
    contain_s = time.perf_counter() - t_pipeline

    banner("5. VERIFY (compromised agent retries)")
    retries = simulator.enforce_and_retry(store)
    for a in retries:
        print(f"{a['action_type']:<15} {a['dest_host'] or a['target']:<40} -> {a['outcome'].upper()}")
    v = verify(store, inc["agent_id"])
    print(f"contained={v['contained']}  allowed_after={v['allowed_after']}  denied_after={v['denied_after']}")
    print(f"detection -> containment pipeline: {contain_s:.2f}s")

    banner("6. HUNT GUARDRAIL vs hostile LLM output")
    guard = []
    for name, sql in ATTACKS.items():
        try:
            run_sql(store, sql)
            outcome = "EXECUTED (guardrail failure!)"
        except GuardrailViolation as g:
            outcome = f"blocked {g.layer}: {g.reason}"
        except Exception as e:  # DB-side layer caught it
            outcome = f"blocked L3 (database): {str(e).splitlines()[0][:60]}"
        guard.append({"attack": name, "sql": sql, "outcome": outcome})
        print(f"{name:<22} {outcome}")
    h = hunt(store, "which agents touched the metadata service?", llm)
    print(f"\nlegit hunt: {h.question}\n  -> {h.rows[:3]}  ({h.elapsed_ms:.0f} ms)")

    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(json.dumps({
        "backend": store.backend, "llm": llm.name,
        "rows": store.scalar("SELECT count() FROM agent_events"),
        "detections": [{"id": r.detection.id, "title": r.detection.title,
                        "severity": r.detection.severity, "ms": round(r.elapsed_ms, 1),
                        "hits": len(r.hits), "attack": r.detection.mitre_attack,
                        "agents": [h["agent_id"] for h in r.hits]} for r in runs],
        "incident": inc, "triage": tri["summary"], "timeline": tri["timeline"],
        "controls": controls, "retries": retries, "verify": v, "guardrail": guard,
        "generated_at": time.strftime("%Y-%m-%d %H:%M"),
        "pipeline_s": round(contain_s, 2),
    }, default=str, indent=1))
    print(f"\nreport written to {REPORT}")


if __name__ == "__main__":
    main()
