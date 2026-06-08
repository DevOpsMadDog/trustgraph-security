# Deploying TrustGraph Security

## 1 · Local Docker Compose (dev / self-hosted)

```bash
cp .env.example .env
# Edit JWT_SECRET, TG_API_KEY, ADMIN_PASSWORD, and at least one of
# OPENAI_API_KEY / ANTHROPIC_API_KEY for the CAI pentest agent.

make up         # builds and starts every service
make seed       # loads the payments-platform threat model + enrichments
make logs       # tails all services
make plan       # forces a re-plan and lists top tasks
make down       # stops everything (data preserved in volumes)
make wipe       # stops + removes volumes (full reset)
```

Open http://localhost:8080 — log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

### What's running

| Container | Port | Purpose |
|---|---|---|
| tg-ui | 8080 | React frontend |
| tg-api | 8000 | FastAPI control plane |
| trustgraph | 8088 | trustgraph-ai gateway |
| pulsar | 6650 / 8081 | pub/sub fabric |
| cassandra | – | triple store |
| qdrant | 6333 | vector store |
| redis | – | celery broker |
| tg-worker | – | scanner + pentest workers (2 replicas) |

### Running the real scanners

```bash
# Semgrep over a repo
curl -X POST http://localhost:8000/api/v1/enrich/scan \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"scanner":"semgrep","target_service":"auth-service",
       "target":"https://github.com/acme/auth-service"}'

# Trivy over a container image
curl -X POST http://localhost:8000/api/v1/enrich/scan \
  -d '{"scanner":"trivy","target_service":"payments-api",
       "target":"acme/payments-api:1.2.3"}' …

# Gitleaks over a repo
# Nuclei over a live URL
```

Findings stream back into trustgraph as `Finding` triples and immediately
affect the planner's `control_gap` and `runtime_signal` scores.

### Running the AI pentest

```bash
# 1. Plan
curl -X POST http://localhost:8000/api/v1/plan -H "Authorization: Bearer $JWT"

# 2. Pick a task
curl http://localhost:8000/api/v1/plan/tasks -H "Authorization: Bearer $JWT" | jq

# 3. Execute — dispatches CAI agent in worker
curl -X POST http://localhost:8000/api/v1/plan/tasks/pt:thr:thr-002/execute \
  -H "Authorization: Bearer $JWT"

# 4. Poll job
curl http://localhost:8000/api/v1/jobs/$JOB_ID -H "Authorization: Bearer $JWT"

# 5. Inspect Evidence triples
curl "http://localhost:8000/api/v1/graph/query?subject=https://trustgraph.security/entity/threat/thr-002" \
  -H "Authorization: Bearer $JWT" | jq
```

## 2 · Customized feed from a prior session

```bash
# Drop artifacts from a previous Perplexity Computer session into ./feeds:
./feeds/
  threat_model/payments.json
  github/auth-service.json
  findings/semgrep-results.json
  alerts/siem-day1.json

curl -X POST http://localhost:8000/api/v1/ingest/feed/local \
  -H "Authorization: Bearer $JWT"
```

Or pull from S3:

```bash
# Set FEED_S3_BUCKET and AWS creds in .env, then:
curl -X POST http://localhost:8000/api/v1/ingest/feed/s3 \
  -H "Authorization: Bearer $JWT"
```

## 3 · Hardening for production

* Replace `JWT_SECRET` and `TG_API_KEY` with random 64-byte values
* Run behind nginx/Caddy/ALB with TLS termination
* Move `cassandra` and `qdrant` to managed services for any non-toy deployment
* Set `deploy.replicas` higher on `tg-worker` for parallel scans
* Mount a real GitHub App private key at `/run/secrets/github_app.pem`
* Enable Prometheus scraping on `:8000/api/v1/metrics`
* Enforce egress allowlists on `tg-worker` if running scanners against the internet

## 4 · Kubernetes

A starter Helm chart can be derived from this compose file — every service
maps 1:1 to a Deployment, with Cassandra/Qdrant/Pulsar/Redis lifted into their
official charts. See `infra/k8s/` (TBD).
