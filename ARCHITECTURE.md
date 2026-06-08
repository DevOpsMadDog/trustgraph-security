# TrustGraph Security — Architecture

## High-level data flow

```mermaid
flowchart LR
    %% ---------- Inputs ----------
    subgraph IN["Inputs"]
        GH["GitHub repos<br/>(code, PRs, commits)"]
        FEEDS["Threat feeds<br/>(CVE, KEV, EPSS)"]
        RT["Runtime telemetry<br/>(alerts, WAF, IDS)"]
        ARCH["Architecture<br/>(services, endpoints, data stores)"]
    end

    %% ---------- Ingest ----------
    subgraph INGEST["Ingest & Normalize (FastAPI)"]
        API["tg-api<br/>POST /v1/ingest/*"]
        NORM["normalize.py<br/>(entities → RDF triples)"]
    end

    %% ---------- Scanners ----------
    subgraph SCAN["Static + Supply-chain (Celery workers)"]
        SEMGREP["Semgrep<br/>(SAST)"]
        TRIVY["Trivy<br/>(images, SBOM, IaC)"]
        GITLEAKS["Gitleaks<br/>(secrets)"]
        NUCLEI["Nuclei<br/>(known-CVE probes)"]
    end

    %% ---------- Graph store ----------
    subgraph TG["trustgraph-ai (graph + retrieval)"]
        CORE["Knowledge core<br/>(RDF triples)"]
        CASS[("Cassandra<br/>triple store")]
        QDR[("Qdrant<br/>vector index")]
        FLOW["graph-rag flow<br/>+ agent interface"]
    end

    %% ---------- Brains ----------
    subgraph BRAIN["Decision layer"]
        PLAN["Planner<br/>(6-signal scoring)"]
        QUEUE[["Pentest task queue<br/>(Redis / Celery)"]]
    end

    %% ---------- AI Pentester ----------
    subgraph AI["AI Pentester (CAI)"]
        CAI["CAI agent<br/>(Claude / GPT / local LLM)"]
        TOOLS["Tools:<br/>nuclei • sqlmap • ffuf<br/>httpx • curl • nmap"]
    end

    %% ---------- Target ----------
    TARGET["tg-demo-target<br/>(intentionally vulnerable<br/>payments API)"]

    %% ---------- UI ----------
    UI["tg-ui (React)<br/>Graph • AppSec • SOC<br/>• Pentest • Explainers"]

    %% Flows
    GH --> API
    FEEDS --> API
    RT --> API
    ARCH --> API
    GH --> SEMGREP & TRIVY & GITLEAKS
    SEMGREP & TRIVY & GITLEAKS & NUCLEI --> API
    API --> NORM --> CORE
    CORE --> CASS
    CORE --> QDR
    FLOW -.reads.-> CASS & QDR
    PLAN -- "graph-rag query" --> FLOW
    PLAN --> QUEUE
    QUEUE --> CAI
    CAI <-->|HTTP probes| TARGET
    CAI --> TOOLS
    CAI -- "evidence (JSON)" --> API
    API -- "Findings, Evidence,<br/>ExploitAttempts" --> NORM
    UI <--> API

    classDef ai fill:#7c3aed,stroke:#5b21b6,color:#fff
    classDef store fill:#0ea5e9,stroke:#0369a1,color:#fff
    classDef danger fill:#dc2626,stroke:#7f1d1d,color:#fff
    class CAI,FLOW,PLAN ai
    class CASS,QDR,CORE,QUEUE store
    class TARGET danger
```

## The AI loop (zoom-in)

```mermaid
sequenceDiagram
    autonumber
    participant U as User / Cron
    participant API as tg-api
    participant P as Planner
    participant TG as trustgraph-ai
    participant Q as Celery queue
    participant CAI as CAI agent (LLM)
    participant T as Demo target

    U->>API: POST /v1/plan
    API->>P: run_planner()
    P->>TG: graph-rag query (threats, services, controls)
    TG-->>P: ranked context
    P->>P: score(severity, exposure, exploitability,<br/>controls gap, churn, alerts)
    P-->>API: pentest tasks (top-N)
    API->>Q: enqueue task
    Q->>CAI: run_cai_task(task)
    loop autonomous attack (≤ max_turns)
        CAI->>T: HTTP probe / tool call
        T-->>CAI: response
        CAI->>CAI: decide next step
    end
    CAI-->>API: evidence JSON (outcome, steps, artifacts)
    API->>TG: write Finding / Evidence / ExploitAttempt triples
    API-->>U: task complete + evidence link
```

## GitHub-repo → graph → pentest-tasks prototype

The standalone prototype in `prototype/` shows the **core idea in 200 lines** without needing Docker, Cassandra, or an LLM key.

```mermaid
flowchart LR
    R["GitHub repo URL"] --> M["fetch_repo_metadata()<br/>(GitHub REST API)"]
    M --> X["extract_signals()<br/>• languages<br/>• dependencies<br/>• endpoints (regex)<br/>• secrets patterns<br/>• Dockerfile flags<br/>• recent commits"]
    X --> G["build_graph()<br/>RDF-shaped JSON<br/>(nodes + edges)"]
    G --> S["score_threats()<br/>STRIDE mapping<br/>+ 6-signal score"]
    S --> T["pentest_tasks.json<br/>(ranked, objective +<br/>suggested tools)"]

    classDef out fill:#7c3aed,stroke:#5b21b6,color:#fff
    class T out
```

Run it:

```bash
cd prototype
pip install httpx
python repo_to_tasks.py https://github.com/OWASP/NodeGoat
# → writes graph.json + tasks.json next to the script
```
