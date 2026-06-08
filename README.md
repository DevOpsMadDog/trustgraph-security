# TrustGraph Security

Production AI-native security platform: **threat model → context graph → enrichment → AI pentest → evidence**.

> 🎓 **New to security?** Start with the **[15-minute Hackathon Primer](./PRIMER.md)** — 18 diagrams explaining threat modeling, STRIDE, MITRE, and how this fits next to PentestGPT / PentAGI / TaaC-AI. Zero security background needed.

The graph store is **[trustgraph-ai](https://github.com/trustgraph-ai/trustgraph)** — every security entity (services, threats, controls, findings, evidence, pentest tasks) is stored as RDF triples in a TrustGraph knowledge core and queried through TrustGraph's REST/WS gateway. This buys us Cassandra+Qdrant+Pulsar+Garage out of the box and lets RAG/agent flows reason directly over the security graph.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  UI (React)  →  FastAPI Control Plane  ←→  TrustGraph API   │
│                          │                       │           │
│                          ▼                       ▼           │
│                   Redis ──── Celery       Cassandra/Qdrant   │
│                          │     │                 │           │
│              ┌───────────┼─────┼────────┐  ┌────▼───────┐    │
│              ▼           ▼     ▼        ▼  │  Pulsar    │    │
│           Semgrep     Trivy  Gitleaks  CAI │  fabric    │    │
│           (SAST)      (SCA)  (secrets)(AI  └────────────┘    │
│                                       pentest)               │
└──────────────────────────────────────────────────────────────┘
```

### Components

| Service | Image | Purpose |
|---|---|---|
| `tg-api` | local build (Python 3.13 + FastAPI) | Control plane: ingest, enrich, plan, evidence, JWT auth, RBAC |
| `tg-worker` | local build | Celery workers running Semgrep, Trivy, Gitleaks, Nuclei |
| `tg-pentest-agent` | local build | [CAI](https://github.com/aliasrobotics/cai) AI pentest agent runner |
| `tg-ui` | local build (Vite/React) | Architect / AppSec / SOC / Pentest / Executive views |
| `trustgraph` | `trustgraph/trustgraph-flow` | Graph store + RAG + agent flows |
| `cassandra` | `cassandra:5` | Triple store (managed by trustgraph) |
| `qdrant` | `qdrant/qdrant` | Vector store (managed by trustgraph) |
| `pulsar` | `apachepulsar/pulsar:3.2` | Message bus (managed by trustgraph) |
| `redis` | `redis:7-alpine` | Celery broker + result backend |
| `nginx` | `nginx:alpine` | Gateway: routes `/api` → tg-api, `/` → tg-ui |

### Real scanners (no mocks)

* **[Semgrep](https://github.com/semgrep/semgrep)** — SAST over source trees
* **[Trivy](https://github.com/aquasecurity/trivy)** — container/SCA/IaC/secrets
* **[Gitleaks](https://github.com/gitleaks/gitleaks)** — git history secrets
* **[Nuclei](https://github.com/projectdiscovery/nuclei)** — DAST against live endpoints

### Real AI pentest

* **[CAI](https://github.com/aliasrobotics/cai)** — Cybersecurity AI agent framework. Each ranked pentest task is dispatched to a CAI agent with a structured objective derived from the planner; results are written back as `Evidence` triples linked via `evidenced_by`.

### Customized feeds

The `customized-feed` ingestor pulls artifacts from prior pipeline steps (other Perplexity Computer sessions, GitHub Actions runs, S3, or local volumes mounted at `/data/feeds`) and normalizes them into the ingest schema. See `apps/api/trustgraph_security/feeds.py`.

## Quickstart

```bash
cp .env.example .env
# Edit .env: set TG_API_KEY, JWT_SECRET, OPENAI_API_KEY (or ANTHROPIC_API_KEY) for CAI
docker compose -f infra/compose/docker-compose.yml up -d --build

# Wait ~60s for trustgraph + cassandra to be ready
docker compose -f infra/compose/docker-compose.yml logs -f tg-api | grep "ready"

# Seed the payments-platform threat model + run first pentest
docker compose -f infra/compose/docker-compose.yml exec tg-api python -m trustgraph_security.seed
```

Open http://localhost:8080 — JWT login (default admin from `.env`).

## Endpoints (v1)

All under `/api/v1`, JWT bearer auth, `X-Workspace` header for multi-tenancy.

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login` | issue JWT |
| POST | `/ingest/threat-model` | accept blueprint JSON, normalize → triples → POST to trustgraph |
| POST | `/ingest/feed/{source}` | pull from configured feed (`github`, `s3`, `local`, `prior-session`) |
| POST | `/enrich/github` | run GitHub App enrichment job |
| POST | `/enrich/scan` | dispatch scanner job (semgrep/trivy/gitleaks/nuclei) |
| POST | `/plan` | run planner over current graph |
| GET | `/plan/tasks` | list ranked pentest tasks |
| POST | `/plan/tasks/{id}/execute` | dispatch CAI agent |
| GET | `/graph/query` | SPARQL-lite over the security core |
| GET | `/evidence/{id}` | fetch evidence node + linked threat |
| GET | `/healthz` `/readyz` `/metrics` | ops |

## License

Apache-2.0
