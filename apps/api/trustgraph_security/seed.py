"""Seed the payments-platform threat model into trustgraph."""
from __future__ import annotations
import asyncio

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


PAYMENTS_TM = ThreatModel(
    system="payments-platform",
    environment="production",
    trust_boundaries=[
        IngestTrustBoundary(id="tb-edge", name="Internet edge", kind="network"),
        IngestTrustBoundary(id="tb-app", name="App tier", kind="network"),
        IngestTrustBoundary(id="tb-data", name="Data tier", kind="network"),
    ],
    actors=[
        IngestActor(id="act-customer", name="Customer", kind="external"),
        IngestActor(id="act-merchant", name="Merchant", kind="partner"),
        IngestActor(id="act-admin", name="Internal admin", kind="internal"),
        IngestActor(id="act-attacker", name="External attacker", kind="external"),
        IngestActor(id="act-service", name="System service", kind="system"),
    ],
    data_stores=[
        IngestDataStore(id="ds-userdb", name="user-db", kind="postgres", classification="PII"),
        IngestDataStore(id="ds-ledger", name="ledger-db", kind="postgres", classification="financial"),
        IngestDataStore(id="ds-cache", name="redis-cache", kind="redis"),
        IngestDataStore(id="ds-vault", name="hsm-vault", kind="hsm", classification="PAN"),
        IngestDataStore(id="ds-eventbus", name="kafka-bus", kind="kafka"),
        IngestDataStore(id="ds-audit", name="audit-log", kind="s3", classification="audit"),
    ],
    controls=[
        IngestControl(id="ctl-mfa", name="MFA enrollment", kind="preventive"),
        IngestControl(id="ctl-waf", name="Edge WAF", kind="preventive"),
        IngestControl(id="ctl-rate", name="Rate limiting", kind="preventive"),
        IngestControl(id="ctl-rbac", name="Service RBAC", kind="preventive"),
        IngestControl(id="ctl-tls", name="mTLS service mesh", kind="preventive"),
        IngestControl(id="ctl-siem", name="SIEM monitoring", kind="detective"),
        IngestControl(id="ctl-tokenize", name="PAN tokenization", kind="preventive"),
        IngestControl(id="ctl-audit", name="Immutable audit log", kind="detective"),
        IngestControl(id="ctl-ipallow", name="IP allowlist (admin)", kind="preventive"),
    ],
    services=[
        IngestService(
            id="auth-service", name="auth-service",
            criticality="critical", exposure="internet",
            trust_boundary="tb-edge", owner="team-identity",
            repo="acme/auth-service",
            endpoints=[
                IngestEndpoint(id="ep-login", path="/v1/login", method="POST", exposure="internet"),
                IngestEndpoint(id="ep-reset", path="/v1/password/reset", method="POST", exposure="internet"),
                IngestEndpoint(id="ep-mfa", path="/v1/mfa/enroll", method="POST", exposure="internet"),
            ],
            components=[
                IngestComponent(id="cmp-jwt", name="jose-jwt", kind="library"),
                IngestComponent(id="cmp-bcrypt", name="bcrypt", kind="library"),
            ],
            data_stores=["ds-userdb", "ds-cache"],
        ),
        IngestService(
            id="payments-api", name="payments-api",
            criticality="critical", exposure="internet",
            trust_boundary="tb-edge", owner="team-payments",
            repo="acme/payments-api",
            endpoints=[
                IngestEndpoint(id="ep-charge", path="/v1/charge", method="POST", exposure="internet"),
                IngestEndpoint(id="ep-refund", path="/v1/refund", method="POST", exposure="internet"),
                IngestEndpoint(id="ep-tx", path="/v1/transactions/{id}", method="GET", exposure="internet"),
            ],
            components=[
                IngestComponent(id="cmp-stripe", name="stripe-sdk", kind="library"),
                IngestComponent(id="cmp-otel", name="opentelemetry", kind="library"),
            ],
            data_stores=["ds-ledger", "ds-vault", "ds-eventbus"],
        ),
        IngestService(
            id="ledger-service", name="ledger-service",
            criticality="high", exposure="internal",
            trust_boundary="tb-data", owner="team-payments",
            repo="acme/ledger-service",
            endpoints=[
                IngestEndpoint(id="ep-post", path="/internal/post", method="POST", exposure="internal"),
            ],
            data_stores=["ds-ledger", "ds-audit"],
        ),
        IngestService(
            id="webhook-dispatcher", name="webhook-dispatcher",
            criticality="medium", exposure="internet",
            trust_boundary="tb-app", owner="team-platform",
            repo="acme/webhook-dispatcher",
            endpoints=[
                IngestEndpoint(id="ep-wh-in", path="/v1/webhooks/inbound", method="POST", exposure="internet"),
            ],
            data_stores=["ds-eventbus", "ds-audit"],
        ),
        IngestService(
            id="admin-portal", name="admin-portal",
            criticality="high", exposure="internet",
            trust_boundary="tb-edge", owner="team-internal-tools",
            repo="acme/admin-portal",
            endpoints=[
                IngestEndpoint(id="ep-users", path="/admin/users", method="GET", exposure="internet"),
                IngestEndpoint(id="ep-tx-admin", path="/admin/transactions", method="GET", exposure="internet"),
            ],
            data_stores=["ds-userdb", "ds-ledger"],
        ),
    ],
    data_flows=[
        IngestDataFlow(source="auth-service", target="payments-api", crosses_boundary=True),
        IngestDataFlow(source="payments-api", target="ledger-service", crosses_boundary=True),
        IngestDataFlow(source="payments-api", target="webhook-dispatcher", crosses_boundary=False),
        IngestDataFlow(source="admin-portal", target="ledger-service", crosses_boundary=True),
        IngestDataFlow(source="admin-portal", target="auth-service", crosses_boundary=False),
    ],
    threats=[
        IngestThreat(id="thr-001", title="JWT audience validation bypass",
                     target_service="auth-service", stride="Spoofing",
                     risk="high", status="open", controls=["ctl-mfa", "ctl-waf"]),
        IngestThreat(id="thr-002", title="MFA enrollment bypass via password reset",
                     target_service="auth-service", stride="ElevationOfPrivilege",
                     risk="critical", status="open", controls=["ctl-mfa"]),
        IngestThreat(id="thr-003", title="Refund amount manipulation via parameter pollution",
                     target_service="payments-api", stride="Tampering",
                     risk="high", status="in_progress", controls=["ctl-waf"]),
        IngestThreat(id="thr-004", title="PAN leakage in error responses",
                     target_service="payments-api", stride="InformationDisclosure",
                     risk="critical", status="open", controls=["ctl-tokenize", "ctl-waf"]),
        IngestThreat(id="thr-005", title="Ledger double-post via race",
                     target_service="ledger-service", stride="Tampering",
                     risk="high", status="mitigated", controls=["ctl-rbac", "ctl-audit"]),
        IngestThreat(id="thr-006", title="SSRF via webhook URL validation gap",
                     target_service="webhook-dispatcher", stride="InformationDisclosure",
                     risk="medium", status="open", controls=["ctl-rate"]),
        IngestThreat(id="thr-007", title="Horizontal privilege escalation via IDOR on /admin/users",
                     target_service="admin-portal", stride="ElevationOfPrivilege",
                     risk="high", status="open", controls=[]),
        IngestThreat(id="thr-008", title="Admin portal session fixation",
                     target_service="admin-portal", stride="Spoofing",
                     risk="medium", status="open", controls=["ctl-ipallow"]),
    ],
)


GITHUB_ENRICHMENT = [
    GitHubEnrichment(
        service_id="auth-service", repo="acme/auth-service",
        commits=[
            {"sha": "a1b2c3d", "message": "feat: tighten JWT audience check",
             "author": "alice", "timestamp": "2026-06-04T12:00:00Z"},
            {"sha": "b2c3d4e", "message": "refactor: password reset flow",
             "author": "bob", "timestamp": "2026-06-05T10:00:00Z"},
        ],
        pull_requests=[
            {"number": 412, "title": "Tighten JWT audience validation",
             "state": "merged", "author": "alice",
             "merged_at": "2026-06-05T15:00:00Z",
             "url": "https://github.com/acme/auth-service/pull/412"},
        ],
        code_owners=["alice", "team-identity"],
    ),
    GitHubEnrichment(
        service_id="payments-api", repo="acme/payments-api",
        commits=[
            {"sha": "c3d4e5f", "message": "fix: scrub PAN from error responses",
             "author": "carol", "timestamp": "2026-06-06T09:00:00Z"},
            {"sha": "d4e5f6g", "message": "feat: refund idempotency",
             "author": "dave", "timestamp": "2026-06-06T14:00:00Z"},
            {"sha": "e5f6g7h", "message": "chore: bump stripe-sdk",
             "author": "carol", "timestamp": "2026-06-07T08:00:00Z"},
        ],
        pull_requests=[
            {"number": 901, "title": "PAN scrub middleware",
             "state": "merged", "author": "carol",
             "merged_at": "2026-06-06T11:00:00Z",
             "url": "https://github.com/acme/payments-api/pull/901"},
            {"number": 902, "title": "Refund idempotency keys",
             "state": "open", "author": "dave", "merged_at": None,
             "url": "https://github.com/acme/payments-api/pull/902"},
        ],
        code_owners=["carol", "team-payments"],
    ),
    GitHubEnrichment(
        service_id="admin-portal", repo="acme/admin-portal",
        commits=[
            {"sha": "f6g7h8i", "message": "feat: add user search endpoint",
             "author": "erin", "timestamp": "2026-06-07T11:00:00Z"},
        ],
        pull_requests=[
            {"number": 203, "title": "User search endpoint",
             "state": "merged", "author": "erin",
             "merged_at": "2026-06-07T13:00:00Z",
             "url": "https://github.com/acme/admin-portal/pull/203"},
        ],
        code_owners=["erin", "team-internal-tools"],
    ),
]


FINDINGS = [
    ScannerFinding(id="f-sg-001", scanner="semgrep",
                   target_service="auth-service",
                   rule_id="python.jwt.audience-missing",
                   severity="high",
                   title="JWT audience claim not validated",
                   file="auth/jwt.py", line=42),
    ScannerFinding(id="f-sg-002", scanner="semgrep",
                   target_service="payments-api",
                   rule_id="python.flask.error-disclosure",
                   severity="medium",
                   title="Stack trace returned to client in error path",
                   file="payments/errors.py", line=87),
    ScannerFinding(id="f-tr-001", scanner="trivy",
                   target_service="payments-api",
                   rule_id="CVE-2024-12345",
                   severity="critical",
                   title="stripe-sdk vulnerable to request smuggling",
                   cve="CVE-2024-12345"),
    ScannerFinding(id="f-gl-001", scanner="gitleaks",
                   target_service="admin-portal",
                   rule_id="aws-access-key-id",
                   severity="high",
                   title="AWS access key committed in legacy script",
                   file="scripts/deploy.sh", line=12),
    ScannerFinding(id="f-nu-001", scanner="nuclei",
                   target_service="admin-portal",
                   rule_id="default-login-admin",
                   severity="high",
                   title="Admin portal exposes default-login template match"),
]


ALERTS = [
    RuntimeAlert(id="a-001", source="SIEM",
                 target_service="auth-service", severity="high",
                 title="Spike in failed logins from single ASN"),
    RuntimeAlert(id="a-002", source="IAM",
                 target_service="admin-portal", severity="medium",
                 title="Privileged role assumed outside business hours"),
    RuntimeAlert(id="a-003", source="network",
                 target_service="webhook-dispatcher", severity="medium",
                 title="Outbound to RFC1918 from webhook worker"),
]


async def main() -> None:
    client = get_client()
    print("Pushing threat model…")
    n = await push(client, threat_model_to_triples(PAYMENTS_TM))
    print(f"  {n} triples")

    print("Pushing GitHub enrichment…")
    for g in GITHUB_ENRICHMENT:
        n = await push(client, github_enrichment_to_triples(g))
        print(f"  {g.service_id}: {n} triples")

    print("Pushing scanner findings…")
    n = await push(client, scanner_findings_to_triples(FINDINGS))
    print(f"  {n} triples")

    print("Pushing runtime alerts…")
    n = await push(client, runtime_alerts_to_triples(ALERTS))
    print(f"  {n} triples")

    print("Running planner…")
    tasks = await run_planner(client, top_n=20)
    await persist_tasks(client, tasks)
    print(f"  {len(tasks)} pentest tasks; top: "
          f"{tasks[0].title if tasks else 'n/a'} (p={tasks[0].priority if tasks else '-'})")
    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
