"""Telemetry schema for AI agent activity. One row per agent action."""

EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS agent_events
(
    ts              DateTime64(3),
    agent_id        LowCardinality(String),
    agent_role      LowCardinality(String),   -- research | support | coding | infra | data
    session_id      String,
    action_type     LowCardinality(String),   -- tool_call | file_read | file_write | http_request | credential_use
    tool            LowCardinality(String),
    target          String,                   -- file path, URL path, or tool argument
    dest_host       LowCardinality(String),   -- for http_request
    bytes_out       UInt64,
    token_scope     LowCardinality(String),   -- read | write | admin (credential_use)
    outcome         LowCardinality(String),   -- allowed | denied (denied = blocked by a control)
    prompt_hash     String,
    content_snippet String                    -- UNTRUSTED: text the agent ingested (web page, file, tool output)
)
ENGINE = MergeTree
PARTITION BY toStartOfHour(ts)
ORDER BY (agent_id, ts)
"""

CONTROLS_DDL = """
CREATE TABLE IF NOT EXISTS agent_controls
(
    ts           DateTime64(3),
    agent_id     LowCardinality(String),
    control      LowCardinality(String),      -- revoke_token | quarantine_session | block_egress
    scope        String,                      -- session_id, host, or '*'
    detection_id LowCardinality(String),
    reason       String
)
ENGINE = MergeTree
ORDER BY (agent_id, ts)
"""


def create_schema(store, reset: bool = False) -> None:
    if reset:
        store.command("DROP TABLE IF EXISTS agent_events")
        store.command("DROP TABLE IF EXISTS agent_controls")
    store.command(EVENTS_DDL)
    store.command(CONTROLS_DDL)
