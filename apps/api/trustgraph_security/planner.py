"""
Pentest planner — queries trustgraph for current threats, scores them on
exposure / risk / control gap / recent change / runtime signal / criticality,
emits ranked PentestTask objects, and persists them back as triples.
"""
from __future__ import annotations
from typing import Any
import uuid

from .schema import (
    NodeType, EdgeType, PentestTask, PlannerSignals, Stride,
    TGS, TGSE, RDF_TYPE,
)
from .tg_client import TrustGraphClient, iri, lit
from .normalize import _typed, entity_iri, predicate, klass


RISK_WEIGHT = {"low": 4, "medium": 12, "high": 22, "critical": 28}
CRITICALITY_WEIGHT = {"low": 2, "medium": 4, "high": 7, "critical": 10}


async def _query_threats(client: TrustGraphClient) -> list[dict]:
    """Pull all open/in_progress threats with their props from trustgraph."""
    rows = await client.graph_query(predicate=RDF_TYPE,
                                    obj=klass(NodeType.Threat),
                                    limit=10000)
    out: list[dict] = []
    for r in rows:
        tid = r["s"]["v"].rsplit("/", 1)[-1]
        out.append({"id": tid, "iri": r["s"]["v"]})
    return out


async def _fetch_props(client: TrustGraphClient, iri_value: str) -> dict[str, Any]:
    rows = await client.graph_query(subject=iri_value, limit=200)
    props: dict[str, Any] = {}
    for r in rows:
        p = r["p"]["v"].rsplit("#", 1)[-1]
        v = r["o"]["v"]
        props.setdefault(p, []).append(v)
    return {k: (vs[0] if len(vs) == 1 else vs) for k, vs in props.items()}


async def _service_props(client: TrustGraphClient, service_id: str) -> dict[str, Any]:
    return await _fetch_props(client, entity_iri(NodeType.Service, service_id))


async def _count_recent_commits(client: TrustGraphClient, service_id: str) -> int:
    rows = await client.graph_query(
        subject=entity_iri(NodeType.Service, service_id),
        predicate=predicate(EdgeType.changed_by.value),
        limit=200,
    )
    return len(rows)


async def _count_runtime_alerts(client: TrustGraphClient, service_id: str) -> int:
    rows = await client.graph_query(
        predicate=predicate(EdgeType.observed_as.value),
        obj=entity_iri(NodeType.Service, service_id),
        limit=200,
    )
    return len(rows)


async def _count_controls(client: TrustGraphClient, threat_id: str) -> int:
    rows = await client.graph_query(
        subject=entity_iri(NodeType.Threat, threat_id),
        predicate=predicate(EdgeType.mitigated_by.value),
        limit=200,
    )
    return len(rows)


def _score(threat: dict, service: dict, controls: int,
           commits: int, alerts: int) -> PlannerSignals:
    risk = threat.get("risk", "medium")
    crit = service.get("criticality", "medium")
    exposure = service.get("exposure", "internal")
    return PlannerSignals(
        exposure=25 if exposure == "internet" else (10 if exposure == "partner" else 0),
        risk=RISK_WEIGHT.get(risk, 12),
        control_gap=20 if controls == 0 else max(0, 15 - (controls * 5)),
        recent_change=min(15, commits * 3),
        runtime_signal=min(10, alerts * 5),
        criticality=CRITICALITY_WEIGHT.get(crit, 4),
        bonus=5 if threat.get("status") == "in_progress" else 0,
    )


def _objective(threat: dict, service: dict) -> str:
    return (
        f"Validate the threat '{threat.get('label','')}' against service "
        f"'{service.get('label','')}'. STRIDE: {threat.get('stride')}, "
        f"risk: {threat.get('risk')}, exposure: {service.get('exposure')}. "
        f"Demonstrate exploitability without causing impact; capture PoC, "
        f"affected endpoint, and minimal reproduction steps."
    )


async def run_planner(client: TrustGraphClient,
                      top_n: int = 20) -> list[PentestTask]:
    threats = await _query_threats(client)
    tasks: list[PentestTask] = []

    for t in threats:
        props = await _fetch_props(client, t["iri"])
        if props.get("status") == "mitigated":
            continue

        # find target service via `targets` edge
        tgt_rows = await client.graph_query(
            subject=t["iri"], predicate=predicate(EdgeType.targets.value), limit=5
        )
        if not tgt_rows:
            continue
        service_iri = tgt_rows[0]["o"]["v"]
        service_id = service_iri.rsplit("/", 1)[-1]
        svc_props = await _fetch_props(client, service_iri)

        controls = await _count_controls(client, t["id"])
        commits = await _count_recent_commits(client, service_id)
        alerts = await _count_runtime_alerts(client, service_id)

        sigs = _score(props, svc_props, controls, commits, alerts)
        priority = min(99, sum([sigs.exposure, sigs.risk, sigs.control_gap,
                                sigs.recent_change, sigs.runtime_signal,
                                sigs.criticality, sigs.bonus]))

        task = PentestTask(
            id=f"pt:thr:{t['id']}",
            threat_id=t["id"],
            title=f"Validate {props.get('label','threat')} on {svc_props.get('label', service_id)}",
            target_service=service_id,
            stride=props.get("stride", "Tampering"),  # type: ignore[arg-type]
            priority=priority,
            signals=sigs,
            attack_path=[svc_props.get("label", service_id)],
            objective=_objective(props, svc_props),
        )
        tasks.append(task)

    tasks.sort(key=lambda x: x.priority, reverse=True)
    return tasks[:top_n]


async def persist_tasks(client: TrustGraphClient,
                        tasks: list[PentestTask]) -> int:
    """Store tasks as ExploitAttempt nodes pre-execution."""
    triples = []
    for t in tasks:
        triples += _typed(
            NodeType.ExploitAttempt, t.id, label=t.title,
            props={
                "threat_id": t.threat_id,
                "target_service": t.target_service,
                "priority": t.priority,
                "status": t.status,
                "stride": t.stride,
                "objective": t.objective,
            },
        )
        # link back to threat via validates
        triples.append({
            "s": iri(entity_iri(NodeType.ExploitAttempt, t.id)),
            "p": iri(predicate(EdgeType.validates.value)),
            "o": iri(entity_iri(NodeType.Threat, t.threat_id)),
        })
    if triples:
        await client.put_triples(triples)
    return len(tasks)
