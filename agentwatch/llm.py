"""LLM seam. Any OpenAI-compatible chat endpoint (AkashML, OpenAI, vLLM, Ollama).
With no LLM_API_KEY set, a deterministic mock is used so the repo always runs offline.
"""
from __future__ import annotations

import os

import httpx
from dotenv import load_dotenv

load_dotenv()


class LLM:
    def __init__(self):
        self.base_url = os.getenv("LLM_BASE_URL", "").rstrip("/")
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "")
        self.mock = not (self.api_key and self.base_url and self.model)

    @property
    def name(self) -> str:
        return "mock" if self.mock else f"{self.model} @ {self.base_url}"

    def chat(self, system: str, user: str, max_tokens: int = 600) -> str | None:
        """Returns None in mock mode so callers can use their own deterministic fallback."""
        if self.mock:
            return None
        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}],
                "temperature": 0.1,
                "max_tokens": max_tokens,
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
