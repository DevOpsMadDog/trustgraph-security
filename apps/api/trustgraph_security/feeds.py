"""
Customized feed ingestors — pull artifacts from prior pipeline stages
(GitHub Actions runs, S3, local volume, prior Perplexity Computer sessions)
and normalize them into ThreatModel + enrichment payloads.

Each feed source returns either a `ThreatModel`, a list of `ScannerFinding`,
a list of `GitHubEnrichment`, or a list of `RuntimeAlert` — whichever shape
the source carries.
"""
from __future__ import annotations
import json
import os
import pathlib
from typing import Any, Literal
import structlog
import boto3

from .schema import (
    ThreatModel, GitHubEnrichment, ScannerFinding, RuntimeAlert,
)
from .settings import get_settings

log = structlog.get_logger()


FeedSource = Literal["local", "s3", "prior-session", "github-actions"]


class FeedResult:
    def __init__(self,
                 threat_model: ThreatModel | None = None,
                 github: list[GitHubEnrichment] | None = None,
                 findings: list[ScannerFinding] | None = None,
                 alerts: list[RuntimeAlert] | None = None) -> None:
        self.threat_model = threat_model
        self.github = github or []
        self.findings = findings or []
        self.alerts = alerts or []

    def as_dict(self) -> dict:
        return {
            "threat_model": self.threat_model.model_dump() if self.threat_model else None,
            "github": [g.model_dump() for g in self.github],
            "findings": [f.model_dump() for f in self.findings],
            "alerts": [a.model_dump() for a in self.alerts],
        }


def _classify(payload: dict[str, Any]) -> str:
    """Heuristic — what shape is this artifact?"""
    if "system" in payload and "services" in payload:
        return "threat_model"
    if "scanner" in payload or (isinstance(payload, dict) and payload.get("results")):
        return "findings"
    if "commits" in payload or "pull_requests" in payload:
        return "github"
    if "alerts" in payload or "siem" in payload:
        return "alerts"
    return "unknown"


def _from_payload(payload: dict[str, Any]) -> FeedResult:
    result = FeedResult()
    kind = _classify(payload)
    if kind == "threat_model":
        result.threat_model = ThreatModel(**payload)
    elif kind == "findings":
        items = payload.get("findings") or payload.get("results") or payload
        if isinstance(items, dict):
            items = [items]
        result.findings = [ScannerFinding(**it) for it in items]
    elif kind == "github":
        result.github = [GitHubEnrichment(**payload)]
    elif kind == "alerts":
        items = payload.get("alerts", payload)
        if isinstance(items, dict):
            items = [items]
        result.alerts = [RuntimeAlert(**it) for it in items]
    return result


def from_local() -> FeedResult:
    s = get_settings()
    base = pathlib.Path(s.feed_local_path)
    out = FeedResult()
    if not base.exists():
        log.warning("feed_local_missing", path=str(base))
        return out
    for fp in base.glob("**/*.json"):
        try:
            data = json.loads(fp.read_text())
            chunk = _from_payload(data)
            if chunk.threat_model:
                out.threat_model = chunk.threat_model
            out.github.extend(chunk.github)
            out.findings.extend(chunk.findings)
            out.alerts.extend(chunk.alerts)
        except Exception as e:
            log.warning("feed_local_parse_error", path=str(fp), error=str(e))
    return out


def from_s3() -> FeedResult:
    s = get_settings()
    if not s.feed_s3_bucket:
        return FeedResult()
    cli = boto3.client("s3")
    out = FeedResult()
    paginator = cli.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=s.feed_s3_bucket):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json"):
                continue
            body = cli.get_object(Bucket=s.feed_s3_bucket, Key=key)["Body"].read()
            try:
                data = json.loads(body)
                chunk = _from_payload(data)
                if chunk.threat_model:
                    out.threat_model = chunk.threat_model
                out.github.extend(chunk.github)
                out.findings.extend(chunk.findings)
                out.alerts.extend(chunk.alerts)
            except Exception as e:
                log.warning("feed_s3_parse_error", key=key, error=str(e))
    return out


def from_prior_session(session_path: str) -> FeedResult:
    """
    Read artifacts emitted by a previous Perplexity Computer session.
    Convention: session_path/{threat_model,github,findings,alerts}/*.json
    """
    base = pathlib.Path(session_path)
    out = FeedResult()
    for sub, kind in [("threat_model", "threat_model"),
                      ("github", "github"),
                      ("findings", "findings"),
                      ("alerts", "alerts")]:
        d = base / sub
        if not d.exists():
            continue
        for fp in d.glob("*.json"):
            try:
                data = json.loads(fp.read_text())
                chunk = _from_payload(data)
                if chunk.threat_model:
                    out.threat_model = chunk.threat_model
                out.github.extend(chunk.github)
                out.findings.extend(chunk.findings)
                out.alerts.extend(chunk.alerts)
            except Exception as e:
                log.warning("feed_prior_parse_error", path=str(fp), error=str(e))
    return out


def pull(source: FeedSource, **kwargs) -> FeedResult:
    if source == "local":
        return from_local()
    if source == "s3":
        return from_s3()
    if source == "prior-session":
        return from_prior_session(kwargs["session_path"])
    raise ValueError(f"unknown source: {source}")
