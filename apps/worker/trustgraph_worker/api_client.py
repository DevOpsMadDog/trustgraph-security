"""Worker → tg-api client for writing scanner findings + evidence back."""
import os
import httpx


API_URL = os.environ.get("TG_API_INTERNAL_URL", "http://tg-api:8000")
SERVICE_TOKEN = os.environ.get("TG_SERVICE_TOKEN", "")


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {SERVICE_TOKEN}",
            "Content-Type": "application/json"}


def post_findings(findings: list[dict]) -> dict:
    r = httpx.post(f"{API_URL}/api/v1/enrich/findings",
                   json=findings, headers=_headers(), timeout=60)
    r.raise_for_status()
    return r.json()


def post_evidence(evidence: dict) -> dict:
    r = httpx.post(f"{API_URL}/api/v1/evidence",
                   json=evidence, headers=_headers(), timeout=60)
    r.raise_for_status()
    return r.json()
