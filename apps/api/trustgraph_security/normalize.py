"""
Turn an IngestThreatModel (and enrichment payloads) into RDF triples
matching the security ontology, then push to the trustgraph core.
"""
from __future__ import annotations
from .schema import (
    TGS, TGSE, RDF_TYPE, RDFS_LABEL,
    NodeType, EdgeType, ThreatModel,
    GitHubEnrichment, ScannerFinding, RuntimeAlert,
    PentestEvidence,
)
from .tg_client import iri, lit, TrustGraphClient


def entity_iri(node_type: NodeType, ident: str) -> str:
    return f"{TGSE}{node_type.value.lower()}/{ident}"


def predicate(name: str) -> str:
    return f"{TGS}{name}"


def klass(node_type: NodeType) -> str:
    return f"{TGS}{node_type.value}"


def _typed(node_type: NodeType, ident: str, label: str | None = None,
           props: dict | None = None) -> list[dict]:
    s = entity_iri(node_type, ident)
    triples = [
        {"s": iri(s), "p": iri(RDF_TYPE), "o": iri(klass(node_type))},
    ]
    if label:
        triples.append({"s": iri(s), "p": iri(RDFS_LABEL), "o": lit(label)})
    if props:
        for k, v in props.items():
            if v is None:
                continue
            triples.append({"s": iri(s), "p": iri(predicate(k)), "o": lit(v)})
    return triples


def _edge(src_type: NodeType, src_id: str,
          edge: EdgeType,
          dst_type: NodeType, dst_id: str) -> dict:
    return {
        "s": iri(entity_iri(src_type, src_id)),
        "p": iri(predicate(edge.value)),
        "o": iri(entity_iri(dst_type, dst_id)),
    }


def threat_model_to_triples(tm: ThreatModel) -> list[dict]:
    triples: list[dict] = []

    triples += _typed(NodeType.System, tm.system, label=tm.system,
                      props={"environment": tm.environment})

    triples += _typed(NodeType.Environment, tm.environment, label=tm.environment)
    triples.append(_edge(NodeType.System, tm.system, EdgeType.defined_in,
                         NodeType.Environment, tm.environment))

    for tb in tm.trust_boundaries:
        triples += _typed(NodeType.TrustBoundary, tb.id, label=tb.name,
                          props={"kind": tb.kind})

    for actor in tm.actors:
        triples += _typed(NodeType.Actor, actor.id, label=actor.name,
                          props={"kind": actor.kind})

    for ds in tm.data_stores:
        triples += _typed(NodeType.DataStore, ds.id, label=ds.name,
                          props={"kind": ds.kind, "classification": ds.classification})

    for ctl in tm.controls:
        triples += _typed(NodeType.Control, ctl.id, label=ctl.name,
                          props={"kind": ctl.kind})

    for svc in tm.services:
        triples += _typed(NodeType.Service, svc.id, label=svc.name,
                          props={"criticality": svc.criticality,
                                 "exposure": svc.exposure,
                                 "repo": svc.repo})
        triples.append(_edge(NodeType.System, tm.system, EdgeType.contains,
                             NodeType.Service, svc.id))

        if svc.trust_boundary:
            triples.append(_edge(NodeType.Service, svc.id,
                                 EdgeType.crosses_boundary,
                                 NodeType.TrustBoundary, svc.trust_boundary))

        if svc.owner:
            triples += _typed(NodeType.Owner, svc.owner, label=svc.owner)
            triples.append(_edge(NodeType.Service, svc.id, EdgeType.owned_by,
                                 NodeType.Owner, svc.owner))

        for ep in svc.endpoints:
            triples += _typed(NodeType.Endpoint, ep.id, label=ep.path,
                              props={"method": ep.method, "exposure": ep.exposure})
            triples.append(_edge(NodeType.Service, svc.id, EdgeType.exposes,
                                 NodeType.Endpoint, ep.id))

        for cmp in svc.components:
            triples += _typed(NodeType.Component, cmp.id, label=cmp.name,
                              props={"kind": cmp.kind})
            triples.append(_edge(NodeType.Service, svc.id, EdgeType.contains,
                                 NodeType.Component, cmp.id))

        for ds_id in svc.data_stores:
            triples.append(_edge(NodeType.Service, svc.id, EdgeType.stores,
                                 NodeType.DataStore, ds_id))

    for flow in tm.data_flows:
        triples.append(_edge(NodeType.Service, flow.source,
                             EdgeType.communicates_with,
                             NodeType.Service, flow.target))

    for thr in tm.threats:
        triples += _typed(NodeType.Threat, thr.id, label=thr.title,
                          props={"stride": thr.stride, "risk": thr.risk,
                                 "status": thr.status,
                                 "description": thr.description})
        triples.append(_edge(NodeType.Threat, thr.id, EdgeType.targets,
                             NodeType.Service, thr.target_service))
        triples.append(_edge(NodeType.Threat, thr.id, EdgeType.threatens,
                             NodeType.Service, thr.target_service))
        for ctl_id in thr.controls:
            triples.append(_edge(NodeType.Threat, thr.id, EdgeType.mitigated_by,
                                 NodeType.Control, ctl_id))

    return triples


def github_enrichment_to_triples(payload: GitHubEnrichment) -> list[dict]:
    triples: list[dict] = []
    for commit in payload.commits:
        cid = commit["sha"]
        triples += _typed(NodeType.Commit, cid,
                          label=commit.get("message", "")[:80],
                          props={"author": commit.get("author"),
                                 "timestamp": commit.get("timestamp"),
                                 "repo": payload.repo})
        triples.append(_edge(NodeType.Service, payload.service_id,
                             EdgeType.changed_by, NodeType.Commit, cid))

    for pr in payload.pull_requests:
        pid = f"{payload.repo}#{pr['number']}"
        triples += _typed(NodeType.PullRequest, pid, label=pr.get("title", ""),
                          props={"author": pr.get("author"),
                                 "state": pr.get("state"),
                                 "merged_at": pr.get("merged_at"),
                                 "url": pr.get("url")})
        triples.append(_edge(NodeType.Service, payload.service_id,
                             EdgeType.changed_by, NodeType.PullRequest, pid))

    for owner_login in payload.code_owners:
        triples += _typed(NodeType.Owner, owner_login, label=owner_login)
        triples.append(_edge(NodeType.Service, payload.service_id,
                             EdgeType.owned_by, NodeType.Owner, owner_login))
    return triples


def scanner_findings_to_triples(findings: list[ScannerFinding]) -> list[dict]:
    triples: list[dict] = []
    for f in findings:
        triples += _typed(NodeType.Finding, f.id, label=f.title,
                          props={"scanner": f.scanner, "rule_id": f.rule_id,
                                 "severity": f.severity, "file": f.file,
                                 "line": f.line, "cve": f.cve,
                                 "evidence": f.evidence})
        triples.append(_edge(NodeType.Finding, f.id, EdgeType.targets,
                             NodeType.Service, f.target_service))
    return triples


def runtime_alerts_to_triples(alerts: list[RuntimeAlert]) -> list[dict]:
    triples: list[dict] = []
    for a in alerts:
        triples += _typed(NodeType.Alert, a.id, label=a.title,
                          props={"source": a.source, "severity": a.severity,
                                 "details": a.details})
        triples.append(_edge(NodeType.Alert, a.id, EdgeType.observed_as,
                             NodeType.Service, a.target_service))
    return triples


def evidence_to_triples(ev: PentestEvidence) -> list[dict]:
    triples = _typed(NodeType.Evidence, ev.id, label=ev.summary[:80],
                     props={"outcome": ev.outcome, "summary": ev.summary,
                            "task_id": ev.task_id,
                            "artifacts": str(ev.artifacts)})
    triples.append(_edge(NodeType.Threat, ev.threat_id, EdgeType.evidenced_by,
                         NodeType.Evidence, ev.id))
    return triples


async def push(client: TrustGraphClient, triples: list[dict],
               chunk: int = 500) -> int:
    """Write triples to trustgraph in chunks."""
    total = 0
    for i in range(0, len(triples), chunk):
        await client.put_triples(triples[i:i + chunk])
        total += min(chunk, len(triples) - i)
    return total
