"""
Real scanner runners. Each task:
  1. Shells out to the actual scanner binary inside the worker container
  2. Parses JSON output into the ScannerFinding shape
  3. POSTs findings back to tg-api which writes them as triples to trustgraph
"""
from __future__ import annotations
import json
import os
import subprocess
import tempfile
import uuid
import pathlib

import git
import structlog

from .celery_app import celery_app
from .api_client import post_findings

log = structlog.get_logger()


SEVERITY_MAP = {
    "INFO": "low", "LOW": "low",
    "WARNING": "medium", "MEDIUM": "medium",
    "ERROR": "high", "HIGH": "high",
    "CRITICAL": "critical",
}


def _clone(target: str, dst: str) -> str:
    log.info("clone", target=target, dst=dst)
    git.Repo.clone_from(target, dst, depth=1)
    return dst


def _post(target_service: str, findings: list[dict]) -> dict:
    if not findings:
        return {"count": 0}
    return post_findings(findings)


# ───────────────────────── Semgrep ─────────────────────────

@celery_app.task(name="scanners.semgrep", bind=True, max_retries=1)
def run_semgrep(self, target_service: str, target: str) -> dict:
    rules = os.environ.get("SEMGREP_RULES", "p/default")
    with tempfile.TemporaryDirectory() as tmp:
        path = _clone(target, tmp) if target.startswith(("http", "git@")) else target
        out = subprocess.run(
            ["semgrep", "--config", rules, "--json", "--quiet", path],
            capture_output=True, text=True, timeout=900,
        )
        try:
            data = json.loads(out.stdout or "{}")
        except json.JSONDecodeError:
            data = {"results": []}

        findings = []
        for r in data.get("results", []):
            sev = SEVERITY_MAP.get(
                r.get("extra", {}).get("severity", "MEDIUM").upper(), "medium",
            )
            findings.append({
                "id": f"f-sg-{uuid.uuid4().hex[:8]}",
                "scanner": "semgrep",
                "target_service": target_service,
                "rule_id": r.get("check_id", "unknown"),
                "severity": sev,
                "title": r.get("extra", {}).get("message", "")[:120],
                "file": r.get("path"),
                "line": r.get("start", {}).get("line"),
            })
        return _post(target_service, findings)


# ───────────────────────── Trivy ─────────────────────────

@celery_app.task(name="scanners.trivy", bind=True, max_retries=1)
def run_trivy(self, target_service: str, target: str) -> dict:
    """target may be an image ref (`org/img:tag`) or a path to a repo."""
    sev = os.environ.get("TRIVY_SEVERITY", "HIGH,CRITICAL")
    mode = "image" if ":" in target and "/" in target.split(":")[0] else "fs"
    out = subprocess.run(
        ["trivy", mode, "--format", "json", "--severity", sev,
         "--quiet", "--no-progress", target],
        capture_output=True, text=True, timeout=1200,
    )
    try:
        data = json.loads(out.stdout or "{}")
    except json.JSONDecodeError:
        data = {"Results": []}

    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            findings.append({
                "id": f"f-tr-{uuid.uuid4().hex[:8]}",
                "scanner": "trivy",
                "target_service": target_service,
                "rule_id": v.get("VulnerabilityID", "unknown"),
                "severity": SEVERITY_MAP.get(v.get("Severity", "MEDIUM"), "medium"),
                "title": v.get("Title", v.get("PkgName", "")),
                "cve": v.get("VulnerabilityID"),
                "evidence": v.get("PrimaryURL"),
            })
    return _post(target_service, findings)


# ───────────────────────── Gitleaks ─────────────────────────

@celery_app.task(name="scanners.gitleaks", bind=True, max_retries=1)
def run_gitleaks(self, target_service: str, target: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "gitleaks.json"
        path = _clone(target, str(pathlib.Path(tmp) / "repo")) \
            if target.startswith(("http", "git@")) else target
        subprocess.run(
            ["gitleaks", "detect", "--source", path,
             "--report-format", "json", "--report-path", str(report),
             "--no-banner", "--exit-code", "0"],
            capture_output=True, text=True, timeout=600,
        )
        try:
            data = json.loads(report.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            data = []

        findings = [{
            "id": f"f-gl-{uuid.uuid4().hex[:8]}",
            "scanner": "gitleaks",
            "target_service": target_service,
            "rule_id": item.get("RuleID", "unknown"),
            "severity": "high",
            "title": item.get("Description", "Secret leaked")[:120],
            "file": item.get("File"),
            "line": item.get("StartLine"),
            "evidence": item.get("Commit"),
        } for item in data]
        return _post(target_service, findings)


# ───────────────────────── Nuclei ─────────────────────────

@celery_app.task(name="scanners.nuclei", bind=True, max_retries=1)
def run_nuclei(self, target_service: str, target: str) -> dict:
    templates = os.environ.get("NUCLEI_TEMPLATES", "cves,exposures,misconfiguration")
    out = subprocess.run(
        ["nuclei", "-u", target, "-t", templates, "-jsonl",
         "-silent", "-disable-update-check"],
        capture_output=True, text=True, timeout=900,
    )
    findings = []
    for line in (out.stdout or "").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        findings.append({
            "id": f"f-nu-{uuid.uuid4().hex[:8]}",
            "scanner": "nuclei",
            "target_service": target_service,
            "rule_id": item.get("template-id", "unknown"),
            "severity": SEVERITY_MAP.get(info.get("severity", "medium").upper(), "medium"),
            "title": info.get("name", "")[:120],
            "evidence": item.get("matched-at"),
        })
    return _post(target_service, findings)
