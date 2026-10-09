"""Automated containment + verification. Acts only on the simulated control plane
(agent_controls table), never on real infrastructure."""
from __future__ import annotations

from datetime import datetime, timedelta

from .simulator import insert_rows
from .store import Store


def _parse(ts) -> datetime:
    return datetime.strptime(str(ts)[:23].ljust(23, "0"), "%Y-%m-%d %H:%M:%S.%f")


def exfil_hosts(store: Store, agent_id: str) -> list[str]:
    rows = store.query(f"""
        WITH pop AS (SELECT dest_host, uniqExact(agent_id) AS n FROM agent_events
                     WHERE action_type = 'http_request' GROUP BY dest_host)
        SELECT DISTINCT e.dest_host AS host FROM agent_events e
        INNER JOIN pop ON e.dest_host = pop.dest_host
        WHERE e.agent_id = '{agent_id}' AND e.action_type = 'http_request'
          AND pop.n <= 2 AND e.bytes_out > 100000
    """).rows
    return sorted(r["host"] for r in rows)


def contain(store: Store, incident: dict) -> list[dict]:
    agent = incident["agent_id"]
    at = _parse(incident["last_seen"]) + timedelta(seconds=30)
    det_ids = ",".join(d["id"] for d in incident["detections"])
    rows = []

    def add(control: str, scope: str, reason: str):
        rows.append({"ts": at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "agent_id": agent,
                     "control": control, "scope": scope, "detection_id": det_ids, "reason": reason})

    if "revoke_token" in incident["response"]:
        add("revoke_token", "*", "credential misuse or exposure")
    if "quarantine_session" in incident["response"]:
        add("quarantine_session", "*", "agent behavior outside sandbox")
    if "block_egress" in incident["response"]:
        for host in exfil_hosts(store, agent):
            add("block_egress", host, "bulk transfer to rare destination")
    insert_rows(store, "agent_controls", rows)
    return rows


def verify(store: Store, agent_id: str) -> dict:
    """Prove containment: after the earliest control, zero risky actions succeeded."""
    t = store.scalar(f"SELECT min(ts) FROM agent_controls WHERE agent_id = '{agent_id}'")
    r = store.query(f"""
        SELECT countIf(outcome = 'allowed') AS allowed_after,
               countIf(outcome = 'denied')  AS denied_after
        FROM agent_events
        WHERE agent_id = '{agent_id}' AND ts > toDateTime64('{t}', 3)
          AND action_type IN ('http_request', 'credential_use')
    """).rows[0]
    allowed, denied = int(r["allowed_after"]), int(r["denied_after"])
    return {"contained": allowed == 0 and denied > 0, "allowed_after": allowed,
            "denied_after": denied, "controls_since": str(t)}
