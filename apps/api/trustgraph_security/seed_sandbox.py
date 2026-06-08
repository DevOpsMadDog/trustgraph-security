"""
Sandbox seed — same payments-platform model as `seed.py`, but rewritten so
the AI pentest agent has a concrete in-network target to attack.

Differences from the production seed:
  * `endpoint.path` values include the full URL (http://tg-demo-target:9000/…)
    so the CAI prompt + scanners can point at a real listener.
  * Adds a scanner finding telling the agent that ZAP is reachable at
    http://zap:8090 as a tool it can drive.
  * Drops MFA control on thr-002 so the attack path is clearly open in the UI.
"""
from __future__ import annotations
import asyncio
import os

from .schema import (
    ThreatModel, IngestService, IngestEndpoint, IngestComponent,
    IngestDataFlow, IngestThreat, IngestControl, IngestActor,
    IngestDataStore, IngestTrustBoundary, GitHubEnrichment,
    ScannerFinding, RuntimeAlert,
)
from .tg_client import get_client
from .normalize import (
    threat_model_to_triples, github_enrichment_to_triples,
    scanner_findings_to_triples, runtime_alerts_to_triples, push,
)
from .planner import run_planner, persist_tasks

TARGET = os.environ.get("TG_DEMO_TARGET_BASE", "http://tg-demo-target:9000")


PAYMENTS_TM = ThreatModel(
    system="payments-platform",
    environment="sandbox",
    trust_boundaries=[
        IngestTrustBoundary(id="tb-edge", name="Internet edge", kind="network"),
        IngestTrustBoundary(id="tb-app",  name="App tier",      kind="network"),
        IngestTrustBoundary(id="tb-data", name="Data tier",     kind="network"),
    ],
    actors=[
        IngestActor(id="act-attacker", name="External attacker", kind="external"),
        IngestActor(id="act-customer", name="Customer",          kind="external"),
        IngestActor(id="act-admin",    name="Internal admin",    kind="internal"),
    ],
    data_stores=[
        IngestDataStore(id="ds-userdb", name="user-db",   kind="postgres", classification="PII"),
        IngestDataStore(id="ds-ledger", name="ledger-db", kind="postgres", classification="financial"),
        IngestDataStore(id="ds-vault",  name="hsm-vault", kind="hsm",      classification="PAN"),
    ],
    controls=[
        IngestControl(id="ctl-waf",  name="Edge WAF",        kind="preventive"),
        IngestControl(id="ctl-siem", name="SIEM monitoring", kind="detective"),
    ],
    services=[
        IngestService(
            id="auth-service", name="auth-service",
            criticality="critical", exposure="internet",
            trust_boundary="tb-edge", owner="team-identity",
            repo="acme/auth-service",
            endpoints=[
                IngestEndpoint(id="ep-login", path=f"{TARGET}/v1/login",
                               method="POST", exposure="internet"),
                IngestEndpoint(id="ep-reset", path=f"{TARGET}/v1/password/reset",
                               method="POST", exposure="internet"),
                IngestEndpoint(id="ep-whoami", path=f"{TARGET}/v1/whoami",
                               method="GET", exposure="internet"),
            ],
            data_stores=["ds-userdb"],
        ),
        IngestService(
            id="payments-api", name="payments-api",
            criticality="critical", exposure="internet",
            trust_boundary="tb-edge", owner="team-payments",
            repo="acme/payments-api",
            endpoints=[
                IngestEndpoint(id="ep-tx", path=f"{TARGET}/v1/transactions/" + "{id}",
                               method="GET", exposure="internet"),
            ],
            data_stores=["ds-ledger", "ds-vault"],
        ),
        IngestService(
            id="webhook-dispatcher", name="webhook-dispatcher",
            criticality="medium", exposure="internet",
            trust_boundary="tb-app", owner="team-platform",
            repo="acme/webhook-dispatcher",
            endpoints=[
                IngestEndpoint(id="ep-wh", path=f"{TARGET}/v1/webhooks/inbound",
                               method="POST", exposure="internet"),
            ],
        ),
        IngestService(
            id="admin-portal", name="admin-portal",
            criticality="high", exposure="internet",
            trust_boundary="tb-edge", owner="team-internal-tools",
            repo="acme/admin-portal",
            endpoints=[
                IngestEndpoint(id="ep-users", path=f"{TARGET}/admin/users",
                               method="GET", exposure="internet"),
                IngestEndpoint(id="ep-adm-login", path=f"{TARGET}/admin/login",
                               method="GET", exposure="internet"),
            ],
        ),
    ],
    data_flows=[
        IngestDataFlow(source="auth-service",   target="payments-api",     crosses_boundary=True),
        IngestDataFlow(source="payments-api",   target="webhook-dispatcher", crosses_boundary=False),
        IngestDataFlow(source="admin-portal",   target="auth-service",     crosses_boundary=False),
    ],
    threats=[
        IngestThreat(id="thr-001", title="JWT audience validation bypass",
                     target_service="auth-service", stride="Spoofing",
                     risk="high", status="open", controls=[]),
        IngestThreat(id="thr-002", title="MFA enrollment bypass via password reset",
                     target_service="auth-service", stride="ElevationOfPrivilege",
                     risk="critical", status="open", controls=[]),
        IngestThreat(id="thr-004", title="PAN leakage in error responses",
                     target_service="payments-api", stride="InformationDisclosure",
                     risk="critical", status="open", controls=[]),
        IngestThreat(id="thr-006", title="SSRF via webhook URL validation gap",
                     target_service="webhook-dispatcher", stride="InformationDisclosure",
                     risk="high", status="open", controls=[]),
        IngestThreat(id="thr-007", title="IDOR on /admin/users",
                     target_service="admin-portal", stride="ElevationOfPrivilege",
                     risk="high", status="open", controls=[]),
        IngestThreat(id="thr-008", title="Admin portal session fixation",
                     target_service="admin-portal", stride="Spoofing",
                     risk="medium", status="open", controls=[]),
    ],
)


GH = [
    GitHubEnrichment(
        service_id="auth-service", repo="acme/auth-service",
        commits=[{"sha": "a1b2c3d", "message": "wip: jwt parsing",
                  "author": "alice", "timestamp": "2026-06-07T10:00:00Z"}],
        pull_requests=[{"number": 412, "title": "Add JWT parsing (no aud check yet)",
                        "state": "merged", "author": "alice",
                        "merged_at": "2026-06-07T11:00:00Z",
                        "url": "https://github.com/acme/auth-service/pull/412"}],
        code_owners=["alice", "team-identity"],
    ),
    GitHubEnrichment(
        service_id="payments-api", repo="acme/payments-api",
        commits=[{"sha": "c3d4e5f", "message": "feat: helpful debug errors",
                  "author": "carol", "timestamp": "2026-06-07T12:00:00Z"}],
        pull_requests=[{"number": 901, "title": "Verbose error responses",
                        "state": "merged", "author": "carol",
                        "merged_at": "2026-06-07T12:30:00Z",
                        "url": "https://github.com/acme/payments-api/pull/901"}],
        code_owners=["carol", "team-payments"],
    ),
]

FINDINGS = [
    ScannerFinding(id="f-sg-jwt", scanner="semgrep",
                   target_service="auth-service",
                   rule_id="python.jwt.audience-missing",
                   severity="high",
                   title="JWT audience claim not validated",
                   file="auth/jwt.py", line=42),
    ScannerFinding(id="f-sg-err", scanner="semgrep",
                   target_service="payments-api",
                   rule_id="python.flask.error-disclosure",
                   severity="critical",
                   title="PAN values returned in 404 error body",
                   file="payments/errors.py", line=23),
    ScannerFinding(id="f-sg-ssrf", scanner="semgrep",
                   target_service="webhook-dispatcher",
                   rule_id="python.requests.ssrf",
                   severity="high",
                   title="urlopen called on caller-supplied URL with no allow-list",
                   file="webhook/dispatcher.py", line=14),
]

ALERTS = [
    RuntimeAlert(id="a-001", source="SIEM",
                 target_service="auth-service", severity="high",
                 title="Spike in /v1/whoami requests with malformed JWTs"),
    RuntimeAlert(id="a-002", source="IAM",
                 target_service="admin-portal", severity="medium",
                 title="Privileged GET to /admin/users from unusual ASN"),
]


async def main() -> None:
    client = get_client()
    print(f"📥  Seeding sandbox against target {TARGET} …")
    n = await push(client, threat_model_to_triples(PAYMENTS_TM))
    print(f"   threat model       → {n} triples")
    for g in GH:
        n = await push(client, github_enrichment_to_triples(g))
        print(f"   github {g.service_id:<22} → {n} triples")
    n = await push(client, scanner_findings_to_triples(FINDINGS))
    print(f"   semgrep findings   → {n} triples")
    n = await push(client, runtime_alerts_to_triples(ALERTS))
    print(f"   runtime alerts     → {n} triples")
    print("🧠  Running planner …")
    tasks = await run_planner(client, top_n=10)
    await persist_tasks(client, tasks)
    for i, t in enumerate(tasks[:5], 1):
        print(f"   {i}. p={t.priority:>2}  {t.title}")
    await client.close()
    print("✅  Sandbox ready. Open http://localhost:8080 and log in as demo / demo.")


if __name__ == "__main__":
    asyncio.run(main())
