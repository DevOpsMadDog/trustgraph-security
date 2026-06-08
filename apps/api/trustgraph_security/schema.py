"""
Security ontology — 18 node types, 15 edge types — modeled as RDF triples
inside a trustgraph-ai knowledge core.

Namespaces:
  tgs:  https://trustgraph.security/ontology#        (classes + predicates)
  tgse: https://trustgraph.security/entity/<type>/<id>  (instances)
"""
from __future__ import annotations
from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field

TGS = "https://trustgraph.security/ontology#"
TGSE = "https://trustgraph.security/entity/"
RDF_TYPE = "https://www.w3.org/1999/02/22-rdf-syntax-ns#type"
RDFS_LABEL = "https://www.w3.org/2000/01/rdf-schema#label"


class NodeType(str, Enum):
    System = "System"
    Service = "Service"
    Component = "Component"
    Endpoint = "Endpoint"
    DataStore = "DataStore"
    TrustBoundary = "TrustBoundary"
    Actor = "Actor"
    Threat = "Threat"
    Control = "Control"
    Finding = "Finding"
    Alert = "Alert"
    Incident = "Incident"
    ExploitAttempt = "ExploitAttempt"
    Evidence = "Evidence"
    Owner = "Owner"
    Commit = "Commit"
    PullRequest = "PullRequest"
    Environment = "Environment"


class EdgeType(str, Enum):
    contains = "contains"
    communicates_with = "communicates_with"
    exposes = "exposes"
    stores = "stores"
    crosses_boundary = "crosses_boundary"
    owned_by = "owned_by"
    defined_in = "defined_in"
    changed_by = "changed_by"
    threatens = "threatens"
    mitigated_by = "mitigated_by"
    evidenced_by = "evidenced_by"
    observed_as = "observed_as"
    escalates_to = "escalates_to"
    targets = "targets"
    validates = "validates"


Stride = Literal["Spoofing", "Tampering", "Repudiation",
                 "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege"]
Severity = Literal["low", "medium", "high", "critical"]
ThreatStatus = Literal["open", "in_progress", "mitigated", "accepted"]
Exposure = Literal["internet", "partner", "internal"]


# ---- ingest contract (what callers POST to /api/v1/ingest/threat-model) ----

class IngestEndpoint(BaseModel):
    id: str
    path: str
    method: str = "GET"
    exposure: Exposure = "internal"


class IngestComponent(BaseModel):
    id: str
    name: str
    kind: str = "library"  # library, runtime, sidecar, framework


class IngestService(BaseModel):
    id: str
    name: str
    criticality: Severity = "medium"
    exposure: Exposure = "internal"
    trust_boundary: str | None = None
    owner: str | None = None
    repo: str | None = None
    endpoints: list[IngestEndpoint] = []
    components: list[IngestComponent] = []
    data_stores: list[str] = []


class IngestDataFlow(BaseModel):
    source: str
    target: str
    protocol: str = "https"
    crosses_boundary: bool = False
    data_classification: str | None = None


class IngestThreat(BaseModel):
    id: str
    title: str
    target_service: str
    stride: Stride
    risk: Severity
    status: ThreatStatus = "open"
    description: str | None = None
    controls: list[str] = []


class IngestControl(BaseModel):
    id: str
    name: str
    kind: str = "preventive"  # preventive, detective, corrective


class IngestActor(BaseModel):
    id: str
    name: str
    kind: str = "external"  # external, internal, partner, system


class IngestDataStore(BaseModel):
    id: str
    name: str
    kind: str = "rdbms"
    classification: str | None = None


class IngestTrustBoundary(BaseModel):
    id: str
    name: str
    kind: str = "network"


class ThreatModel(BaseModel):
    """Top-level ingest contract."""
    system: str
    environment: str = "production"
    services: list[IngestService] = []
    data_stores: list[IngestDataStore] = []
    actors: list[IngestActor] = []
    trust_boundaries: list[IngestTrustBoundary] = []
    controls: list[IngestControl] = []
    threats: list[IngestThreat] = []
    data_flows: list[IngestDataFlow] = []


# ---- enrichment contracts ----

class GitHubEnrichment(BaseModel):
    service_id: str
    repo: str                       # owner/name
    commits: list[dict] = Field(default_factory=list)
    pull_requests: list[dict] = Field(default_factory=list)
    code_owners: list[str] = []


class ScannerFinding(BaseModel):
    id: str
    scanner: Literal["semgrep", "trivy", "gitleaks", "nuclei"]
    target_service: str
    rule_id: str
    severity: Severity
    title: str
    file: str | None = None
    line: int | None = None
    cve: str | None = None
    evidence: str | None = None


class RuntimeAlert(BaseModel):
    id: str
    source: str  # SIEM/IAM/network
    target_service: str
    severity: Severity
    title: str
    details: str | None = None


# ---- planner output ----

class PlannerSignals(BaseModel):
    exposure: int = 0          # 0 or 25
    risk: int = 0              # 4..28
    control_gap: int = 0       # 0..20
    recent_change: int = 0     # 0..15
    runtime_signal: int = 0    # 0..10
    criticality: int = 0       # 2..10
    bonus: int = 0             # 0 or 5


class PentestTask(BaseModel):
    id: str
    threat_id: str
    title: str
    target_service: str
    stride: Stride
    priority: int              # 0..99
    signals: PlannerSignals
    attack_path: list[str] = []
    objective: str             # natural language brief handed to CAI
    status: Literal["pending", "running", "succeeded", "failed", "inconclusive"] = "pending"


class PentestEvidence(BaseModel):
    id: str
    task_id: str
    threat_id: str
    outcome: Literal["exploited", "mitigated", "inconclusive"]
    summary: str
    artifacts: dict = Field(default_factory=dict)  # PoC, logs, screenshots refs
