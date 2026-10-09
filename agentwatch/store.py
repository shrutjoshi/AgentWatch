"""Storage seam. Detections only ever see Store.query(); swap backends via AW_BACKEND.

embedded -> chDB (ClickHouse in-process, zero setup, used for local mode and tests)
server   -> clickhouse-connect (Docker compose or ClickHouse Cloud)
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class QueryResult:
    rows: list[dict]
    elapsed_ms: float


class Store:
    def __init__(self, backend: str | None = None, path: str | None = None):
        self.backend = backend or os.getenv("AW_BACKEND", "embedded")
        if self.backend == "embedded":
            from chdb import session

            path = path or os.getenv("AW_EMBEDDED_PATH", "./data/agentwatch.chdb")
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            self._sess = session.Session(path)
        elif self.backend == "server":
            import clickhouse_connect

            self._client = self._connect(
                os.getenv("CLICKHOUSE_USER", "default"), os.getenv("CLICKHOUSE_PASSWORD", "")
            )
            hunt_user = os.getenv("CLICKHOUSE_HUNT_USER")
            self._hunt_client = (
                self._connect(hunt_user, os.getenv("CLICKHOUSE_HUNT_PASSWORD", ""))
                if hunt_user
                else None
            )
        else:
            raise ValueError(f"unknown AW_BACKEND {self.backend!r}")

    @staticmethod
    def _connect(user: str, password: str):
        import clickhouse_connect

        return clickhouse_connect.get_client(
            host=os.getenv("CLICKHOUSE_HOST", "localhost"),
            port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            username=user,
            password=password,
            secure=os.getenv("CLICKHOUSE_SECURE", "false").lower() == "true",
        )

    def command(self, sql: str) -> None:
        if self.backend == "embedded":
            self._sess.query(sql)
        else:
            self._client.command(sql)

    def query(self, sql: str, hunt: bool = False) -> QueryResult:
        """Run a SELECT. hunt=True routes through the least-privileged path."""
        t0 = time.perf_counter()
        if self.backend == "embedded":
            if hunt:
                # chDB has no users, so the query-level setting is the only DB-side control here.
                # It is overridable by a later SETTINGS clause, which is why hunt.py validates first.
                sql = f"{sql}\nSETTINGS readonly = 1"  # nosemgrep: accepted in embedded mode; hunt.validate_sql rejects SETTINGS first (docs/guardrails.md)
            raw = self._sess.query(sql, "JSONEachRow").bytes().decode()
            rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        else:
            client = self._hunt_client if (hunt and self._hunt_client) else self._client
            settings = {"readonly": 1} if hunt and not self._hunt_client else None
            res = client.query(sql, settings=settings)
            rows = [dict(zip(res.column_names, r)) for r in res.result_rows]
        return QueryResult(rows=rows, elapsed_ms=(time.perf_counter() - t0) * 1000)

    def scalar(self, sql: str):
        rows = self.query(sql).rows
        return next(iter(rows[0].values())) if rows else None
