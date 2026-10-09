"""Every detection must fire on the attack chain and stay quiet on the decoys."""
import pytest

from agentwatch import simulator
from agentwatch.detect import group_incidents, load_detections, run_all
from agentwatch.hunt import ATTACKS, GuardrailViolation, run_sql, validate_sql
from agentwatch.remediate import contain, verify
from agentwatch.store import Store


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    s = Store(backend="embedded", path=str(tmp_path_factory.mktemp("db") / "t.chdb"))
    simulator.load(s, n_rows=200_000)
    return s


@pytest.mark.parametrize("det", load_detections(), ids=lambda d: d.id)
def test_detection_contract(store, det):
    hits = {h["agent_id"] for h in store.query(det.query).rows}
    for agent in det.tests.get("must_fire_on", []):
        assert agent in hits, f"{det.id} missed {agent}"
    for agent in det.tests.get("must_not_fire_on", []):
        assert agent not in hits, f"{det.id} false positive on {agent}"
    assert hits <= {simulator.VICTIM}, f"{det.id} fired on background noise: {hits}"


def test_contain_and_verify(store):
    incidents = group_incidents(run_all(store))
    assert incidents and incidents[0]["agent_id"] == simulator.VICTIM
    controls = contain(store, incidents[0])
    assert {c["control"] for c in controls} >= {"revoke_token", "quarantine_session", "block_egress"}
    simulator.enforce_and_retry(store)
    assert verify(store, simulator.VICTIM)["contained"]


@pytest.mark.parametrize("name", list(ATTACKS))
def test_guardrail_blocks_hostile_sql(store, name):
    with pytest.raises(GuardrailViolation):
        run_sql(store, ATTACKS[name])
    assert store.scalar("SELECT count() FROM agent_events") > 0


def test_guardrail_allows_legit_queries(store):
    for sql in [
        "SELECT agent_id, count() FROM agent_events GROUP BY agent_id",
        "WITH x AS (SELECT dest_host FROM agent_events) SELECT count() FROM x",
        "SELECT * FROM agent_events WHERE content_snippet LIKE '%drop table%' LIMIT 5",
    ]:
        validate_sql(sql)
        run_sql(store, sql)


def test_query_level_readonly_alone_is_bypassable(store):
    """Documents the finding that motivates layer 1: a later SETTINGS wins."""
    assert store.scalar("SELECT count() FROM agent_events SETTINGS readonly = 1, readonly = 0") > 0
