# Guardrails for LLM-generated SQL

## Threat model

The hunt feature turns an analyst's question into SQL with an LLM. The model's output must be treated as untrusted:

- **Direct injection.** The question itself can carry instructions.
- **Indirect injection.** If triage or hunting ever puts log content in the prompt, attacker-written text (a web page an agent fetched, a file name, a user agent) reaches the model. AgentWatch stores exactly that kind of content in `content_snippet`.
- **Plain mistakes.** A model can write a destructive or very expensive query with no attacker involved.

Goal: the worst outcome of a malicious or wrong query is a refused query or an empty result.

## Finding: query-level readonly is not a boundary

Tested on chDB (embedded ClickHouse) during the hackathon:

| Query | Result |
|---|---|
| `INSERT ... SETTINGS readonly = 1` | blocked |
| `SELECT ... FROM file('/path') SETTINGS readonly = 1` | blocked |
| `SELECT count() FROM t SETTINGS readonly = 1, readonly = 0` | **executes**, last setting wins |
| `SELECT ... FROM file('/path') SETTINGS readonly = 2` | **executes**, reads the local file |

A guardrail that only appends `SETTINGS readonly = 1` to model output is bypassed by output that ends with its own `SETTINGS` clause, depending on how the strings are joined. On a ClickHouse server, `file()` is limited to `user_files_path`, but `url()`, `s3()` and `remote()` can still reach the network unless the user lacks those grants.

## Layers

1. **Static validation** (`hunt.validate_sql`) after stripping string literals:
   - exactly one statement, starting with `SELECT` or `WITH`
   - no comments (`--`, `/* */`, `#`)
   - no `SETTINGS`, DDL or DML keywords, no `SYSTEM`
   - no table functions (`file`, `url`, `s3`, `remote`, `mysql`, `executable`, `numbers`, ...)
   - every `FROM` / `JOIN` target is `agent_events`, `agent_controls`, or a CTE defined in the query
2. **Execution wrapper**: `SELECT * FROM (<query>) LIMIT 1000`.
3. **Database principal** (server mode): user `hunt` with profile `readonly = 1 CONST`, `max_execution_time = 10`, `SELECT` on two tables only. `CONST` means the query cannot change it. See `hunt_user.sql`.

Layer 1 is a denylist and will never be complete. Layer 3 is the real boundary; layer 1 exists to fail fast with a clear message and to protect embedded mode, which has no users.

## Tested attacks

All seven are in `hunt.ATTACKS` and covered by `tests/test_detections.py`:
drop table, read host files via `file()`, override readonly, exfiltrate via `url()`, enumerate `system.users`, stacked statements, comment smuggling.

## Known gaps

- Resource exhaustion through heavy but valid queries (cross joins) is only bounded by `max_execution_time` in server mode.
- The keyword denylist can false-positive on column aliases such as `set` or `use`.
