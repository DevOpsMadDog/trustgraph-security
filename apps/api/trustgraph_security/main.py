from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Form, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import structlog

from .settings import get_settings
from .auth import (
    User, authenticate, issue_token, current_user, require_role,
)
from .schema import (
    ThreatModel, GitHubEnrichment, ScannerFinding, RuntimeAlert,
    PentestEvidence, PentestTask,
)
from .tg_client import get_client, TrustGraphClient
from .normalize import (
    threat_model_to_triples, github_enrichment_to_triples,
    scanner_findings_to_triples, runtime_alerts_to_triples,
    evidence_to_triples, push,
)
from .planner import run_planner, persist_tasks
from .feeds import pull as feed_pull, FeedSource
from .celery_app import celery_app

log = structlog.get_logger()

INGEST_COUNT = Counter("tgs_ingest_total", "Triples ingested", ["kind"])
PLAN_DURATION = Histogram("tgs_plan_seconds", "Planner duration")


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = get_client()
    # Best effort — TrustGraph may still be starting
    try:
        await client.ensure_flow()
        log.info("trustgraph_flow_ready")
    except Exception as e:
        log.warning("trustgraph_not_ready", error=str(e))
    yield
    await client.close()


app = FastAPI(title="TrustGraph Security", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


# ---------- ops ----------

@app.get("/api/v1/healthz")
async def healthz():
    return {"ok": True}


@app.get("/api/v1/readyz")
async def readyz():
    return {"ok": await get_client().health()}


@app.get("/api/v1/metrics")
def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ---------- auth ----------

@app.post("/api/v1/auth/login")
async def login(username: Annotated[str, Form()],
                password: Annotated[str, Form()]):
    user = authenticate(username, password)
    if not user:
        raise HTTPException(401, "invalid credentials")
    return {"access_token": issue_token(user), "token_type": "bearer",
            "user": user.model_dump()}


@app.get("/api/v1/auth/me")
async def me(user: Annotated[User, Depends(current_user)]):
    return user


# ---------- ingest ----------

@app.post("/api/v1/ingest/threat-model")
async def ingest_threat_model(
    tm: ThreatModel,
    user: Annotated[User, Depends(require_role("architect", "admin"))],
):
    client = get_client()
    triples = threat_model_to_triples(tm)
    n = await push(client, triples)
    INGEST_COUNT.labels(kind="threat_model").inc(n)
    return {"system": tm.system, "triples": n}


@app.post("/api/v1/ingest/feed/{source}")
async def ingest_feed(
    source: FeedSource,
    user: Annotated[User, Depends(require_role("architect", "admin"))],
    session_path: str | None = Query(None,
        description="Required when source=prior-session"),
):
    if source == "prior-session" and not session_path:
        raise HTTPException(400, "session_path required for prior-session source")

    result = feed_pull(source, session_path=session_path) \
        if source == "prior-session" else feed_pull(source)

    client = get_client()
    counts: dict[str, int] = {}
    if result.threat_model:
        n = await push(client, threat_model_to_triples(result.threat_model))
        counts["threat_model"] = n
        INGEST_COUNT.labels(kind="threat_model").inc(n)
    for g in result.github:
        n = await push(client, github_enrichment_to_triples(g))
        counts["github"] = counts.get("github", 0) + n
        INGEST_COUNT.labels(kind="github").inc(n)
    if result.findings:
        n = await push(client, scanner_findings_to_triples(result.findings))
        counts["findings"] = n
        INGEST_COUNT.labels(kind="findings").inc(n)
    if result.alerts:
        n = await push(client, runtime_alerts_to_triples(result.alerts))
        counts["alerts"] = n
        INGEST_COUNT.labels(kind="alerts").inc(n)

    return {"source": source, "counts": counts}


# ---------- enrich ----------

@app.post("/api/v1/enrich/github")
async def enrich_github(
    payload: GitHubEnrichment,
    user: Annotated[User, Depends(require_role("appsec", "admin"))],
):
    client = get_client()
    n = await push(client, github_enrichment_to_triples(payload))
    return {"service": payload.service_id, "triples": n}


@app.post("/api/v1/enrich/findings")
async def enrich_findings(
    findings: list[ScannerFinding],
    user: Annotated[User, Depends(require_role("appsec", "admin"))],
):
    client = get_client()
    n = await push(client, scanner_findings_to_triples(findings))
    return {"count": len(findings), "triples": n}


@app.post("/api/v1/enrich/alerts")
async def enrich_alerts(
    alerts: list[RuntimeAlert],
    user: Annotated[User, Depends(require_role("soc", "admin"))],
):
    client = get_client()
    n = await push(client, runtime_alerts_to_triples(alerts))
    return {"count": len(alerts), "triples": n}


# ---------- scanner dispatch (real Semgrep/Trivy/Gitleaks/Nuclei) ----------

@app.post("/api/v1/enrich/scan")
async def enrich_scan(
    user: Annotated[User, Depends(require_role("appsec", "admin"))],
    scanner: str = Body(..., embed=True),
    target_service: str = Body(..., embed=True),
    target: str = Body(..., embed=True,
        description="Repo URL for semgrep/gitleaks, image ref for trivy, URL for nuclei"),
):
    if scanner not in {"semgrep", "trivy", "gitleaks", "nuclei"}:
        raise HTTPException(400, "unknown scanner")
    task = celery_app.send_task(
        f"scanners.{scanner}",
        kwargs={"target_service": target_service, "target": target},
    )
    return {"job_id": task.id, "scanner": scanner, "target": target}


@app.get("/api/v1/jobs/{job_id}")
async def get_job(job_id: str,
                  user: Annotated[User, Depends(current_user)]):
    r = celery_app.AsyncResult(job_id)
    return {"id": job_id, "status": r.status,
            "result": r.result if r.ready() else None}


# ---------- planner ----------

@app.post("/api/v1/plan")
async def plan(
    user: Annotated[User, Depends(require_role("appsec", "admin"))],
    top_n: int = 20,
):
    client = get_client()
    with PLAN_DURATION.time():
        tasks = await run_planner(client, top_n=top_n)
        await persist_tasks(client, tasks)
    return {"count": len(tasks), "tasks": [t.model_dump() for t in tasks]}


@app.get("/api/v1/plan/tasks")
async def list_tasks(user: Annotated[User, Depends(current_user)]):
    client = get_client()
    tasks = await run_planner(client, top_n=50)
    return [t.model_dump() for t in tasks]


@app.post("/api/v1/plan/tasks/{task_id}/execute")
async def execute_task(
    task_id: str,
    user: Annotated[User, Depends(require_role("appsec", "admin"))],
):
    """Dispatch a CAI agent to validate the given pentest task."""
    client = get_client()
    tasks = await run_planner(client, top_n=200)
    chosen = next((t for t in tasks if t.id == task_id), None)
    if not chosen:
        raise HTTPException(404, "task not found")
    job = celery_app.send_task(
        "pentest.run_cai",
        kwargs={"task": chosen.model_dump()},
    )
    return {"job_id": job.id, "task_id": task_id}


# ---------- evidence write-back (worker calls this) ----------

@app.post("/api/v1/evidence")
async def write_evidence(
    ev: PentestEvidence,
    user: Annotated[User, Depends(require_role("appsec", "admin"))],
):
    client = get_client()
    n = await push(client, evidence_to_triples(ev))
    return {"evidence": ev.id, "triples": n}


# ---------- graph reads ----------

@app.get("/api/v1/graph/query")
async def graph_query(
    user: Annotated[User, Depends(current_user)],
    subject: str | None = None,
    predicate: str | None = None,
    obj: str | None = None,
    limit: int = 500,
):
    client = get_client()
    rows = await client.graph_query(subject=subject, predicate=predicate,
                                    obj=obj, limit=limit)
    return {"count": len(rows), "triples": rows}


@app.post("/api/v1/graph/ask")
async def graph_ask(
    user: Annotated[User, Depends(current_user)],
    question: str = Body(..., embed=True),
):
    client = get_client()
    return await client.agent_question(question)
