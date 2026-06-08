"""
Thin async client for the trustgraph-ai REST gateway.

All write paths go through the `knowledge` endpoint as RDF triples,
which trustgraph stores in Cassandra and embeds in Qdrant.

Reads happen via the `flow` endpoint against a `graph-query` interface
on a loaded flow (default flow id from settings, blueprint: graph-rag).
"""
from __future__ import annotations
from typing import Any, AsyncIterator
import httpx
import structlog

from .settings import get_settings

log = structlog.get_logger()


class TripleValue(dict):
    """Wire shape: {"v": <iri-or-literal>, "e": <True if IRI else False>}."""

    def __init__(self, value: str, is_iri: bool):
        super().__init__(v=value, e=is_iri)


def iri(value: str) -> TripleValue:
    return TripleValue(value, True)


def lit(value: Any) -> TripleValue:
    return TripleValue(str(value), False)


class TrustGraphClient:
    def __init__(self) -> None:
        s = get_settings()
        self._base = s.tg_api_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {s.tg_api_key}",
            "Content-Type": "application/json",
        }
        self._core_id = s.tg_knowledge_core
        self._collection = s.tg_collection
        self._flow_id = s.tg_flow_id
        self._client = httpx.AsyncClient(timeout=60)

    async def close(self) -> None:
        await self._client.aclose()

    async def health(self) -> bool:
        try:
            r = await self._client.get(f"{self._base}/api/v1/health", headers=self._headers)
            return r.status_code == 200
        except Exception:
            return False

    # ---------- knowledge core (write path) ----------

    async def put_triples(self, triples: list[dict]) -> dict:
        """
        Append triples to the security knowledge core. Triples are arrays of
        {s, p, o} where each side is a TripleValue (`iri()` or `lit()`).
        """
        body = {
            "operation": "put-kg-core",
            "triples": {
                "metadata": {
                    "id": self._core_id,
                    "collection": self._collection,
                    "metadata": [
                        {
                            "s": iri(f"https://trustgraph.security/core/{self._core_id}"),
                            "p": iri("https://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                            "o": iri("https://trustgraph.ai/e/knowledge-core"),
                        }
                    ],
                },
                "triples": triples,
            },
        }
        r = await self._client.post(
            f"{self._base}/api/v1/knowledge", json=body, headers=self._headers
        )
        r.raise_for_status()
        return r.json() if r.content else {"status": "ok"}

    async def delete_core(self) -> None:
        body = {"operation": "delete-kg-core", "id": self._core_id}
        await self._client.post(f"{self._base}/api/v1/knowledge",
                                json=body, headers=self._headers)

    async def get_triples_stream(self) -> AsyncIterator[dict]:
        """Stream the full security core back as parsed JSON chunks."""
        body = {"operation": "get-kg-core", "id": self._core_id}
        async with self._client.stream(
            "POST", f"{self._base}/api/v1/knowledge",
            json=body, headers=self._headers
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                import json
                msg = json.loads(line)
                if msg.get("eos"):
                    return
                yield msg

    # ---------- flow (read path: graph-rag query) ----------

    async def ensure_flow(self) -> None:
        """Idempotently ensure the security-rag flow is started and core loaded."""
        # Try to load core into flow; trustgraph is idempotent on already-loaded cores.
        try:
            await self._client.post(
                f"{self._base}/api/v1/flow",
                json={
                    "operation": "start-flow",
                    "flow-id": self._flow_id,
                    "blueprint-name": "graph-rag",
                },
                headers=self._headers,
            )
        except Exception as e:
            log.info("flow_start_skipped", error=str(e))

        await self._client.post(
            f"{self._base}/api/v1/knowledge",
            json={
                "operation": "load-kg-core",
                "id": self._core_id,
                "flow-id": self._flow_id,
                "collection": self._collection,
            },
            headers=self._headers,
        )

    async def graph_query(self, subject: str | None = None,
                          predicate: str | None = None,
                          obj: str | None = None,
                          limit: int = 1000) -> list[dict]:
        """
        Triple-pattern query against the loaded core via the flow's
        triples-query interface.
        """
        body = {
            "operation": "invoke",
            "flow-id": self._flow_id,
            "interface": "triples-query",
            "request": {
                "s": iri(subject) if subject else None,
                "p": iri(predicate) if predicate else None,
                "o": iri(obj) if obj else None,
                "limit": limit,
                "collection": self._collection,
            },
        }
        r = await self._client.post(
            f"{self._base}/api/v1/flow", json=body, headers=self._headers
        )
        r.raise_for_status()
        return r.json().get("triples", [])

    async def agent_question(self, question: str) -> dict:
        """Hand a natural language question to the loaded RAG agent flow."""
        body = {
            "operation": "invoke",
            "flow-id": self._flow_id,
            "interface": "agent",
            "request": {"question": question, "collection": self._collection},
        }
        r = await self._client.post(
            f"{self._base}/api/v1/flow", json=body, headers=self._headers
        )
        r.raise_for_status()
        return r.json()


_singleton: TrustGraphClient | None = None


def get_client() -> TrustGraphClient:
    global _singleton
    if _singleton is None:
        _singleton = TrustGraphClient()
    return _singleton
