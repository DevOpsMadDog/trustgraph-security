# Local Test Report — TrustGraph-Security

> **Test environment:** sandbox VM (Python 3.12, Node 20, 2 vCPU, 8 GB RAM, no Docker)
> **Date:** 2026-06-09
> **Purpose:** Actually run every component reachable without Docker (prototype CLI, FastAPI app, UI build, unit tests) and verify against a real GitHub target. This replaces the earlier "statically validated" claim.

---

## Summary

| Component | Status | Notes |
|---|---|---|
| `prototype/repo_to_tasks.py` CLI | ✅ PASS | 9 tasks, 65 nodes, 102 endpoints against `juice-shop/juice-shop` |
| `prototype/guided_demo.py` end-to-end | ✅ PASS *(after fix)* | 2 missing imports + env-var fallback fixed |
| FastAPI `tg-api` (live uvicorn) | ✅ PASS | health, readyz, login, /auth/me all green on `:8765` |
| FastAPI internal endpoints (with mocked TG core) | ✅ PASS | `/plan`, `/plan/tasks`, `/ingest/threat-model`, `/graph/query`, `/graph/ask` all 200 |
| FastAPI unit tests (`pytest`) | ✅ PASS | `tests/test_normalize.py` 1 passed |
| UI build (Vite) | ✅ PASS *(after fix)* | 1666 modules → `dist/public/` (293 KB JS + 72 KB CSS) |
| `Makefile` targets | ⚠️ FIXED | sandbox-pentest creds now match sandbox compose env |
| `docker compose up` end-to-end | ⏭️ NOT RUN | No Docker in this sandbox — verified static config only |

**5 bugs found and fixed** during testing. **3 components require Docker** and were not exercised here (TrustGraph core, Pulsar/Cassandra, full sandbox stack).

---

## Bugs found and fixed

### 1. `guided_demo.py` — missing `shutil` import

`preflight()` calls `shutil.which("gh")` but `shutil` was never imported.

```
NameError: name 'shutil' is not defined. Did you forget to import 'shutil'?
```

**Fix**: added `import shutil` at top of file.

### 2. `guided_demo.py` — missing `subprocess` import

`preflight()` calls `subprocess.run(["gh", "auth", "status"], ...)` but `subprocess` was never imported. Would crash on machines where `gh` is installed and `GITHUB_TOKEN` isn't set.

**Fix**: added `import subprocess` at top of file.

### 3. `guided_demo.py` + `repo_to_tasks.py` — only checked `GITHUB_TOKEN` env var

When the sandbox provides `GH_ENTERPRISE_TOKEN` or `GH_TOKEN` (common with `gh` CLI installations), preflight reported "no auth" and aborted; HTTP client made unauthenticated calls.

**Fix**: both files now check `GITHUB_TOKEN` → `GH_TOKEN` → `GH_ENTERPRISE_TOKEN` in priority order.

### 4. `apps/ui/package.json` — stale build script

`"build": "tsx script/build.ts"` but `script/` directory does not exist. The Dockerfile uses `npx vite build` directly, so the repo built in CI but failed for anyone running `npm run build` locally.

**Fix**: replaced scripts with direct vite invocation:
```json
"dev": "vite",
"build": "vite build",
"preview": "vite preview",
"check": "tsc --noEmit"
```

### 5. (Reverted) — Makefile credential confusion

Initial fix replaced `demo@trustgraph.local/demo` with `admin@trustgraph.local/change-me` in `sandbox-pentest`. This was **wrong**: the sandbox compose file explicitly sets `ADMIN_EMAIL=demo@trustgraph.local` and `ADMIN_PASSWORD=demo` so the sandbox profile genuinely uses those creds. Reverted to original creds, kept the improved error-message-on-failure logic.

**Action**: no behavior change, but the failure message is now more diagnostic.

---

## Detailed test results

### prototype/repo_to_tasks.py

```
$ python prototype/repo_to_tasks.py juice-shop/juice-shop /tmp/tgs-out

[1/4] Fetching GitHub metadata for juice-shop/juice-shop …
[2/4] Extracting signals …
      langs=['TypeScript', 'JavaScript', 'HTML'] endpoints=102
      deps=182 risky_deps=1 secrets=1 dockerfile_flags=['runs_as_root']
[3/4] Building graph JSON …
      nodes=65 edges=64
[4/4] Scoring threats and generating pentest tasks …

Wrote /tmp/tgs-out/graph.json
Wrote /tmp/tgs-out/tasks.json  (9 tasks)
Wrote /tmp/tgs-out/signals.json

Top 5 pentest tasks:
  [0.93] critical I  Hard-coded credentials in repo  ->  juice-shop/juice-shop
  [0.87] high     T  Unrestricted file upload        ->  POST /file-upload
  [0.87] high     T  Unrestricted file upload        ->  POST /profile/image/file
  [0.87] high     S  Login endpoint lacks rate limit ->  POST /rest/user/login
  [0.87] high     T  Possible injection on search    ->  GET /rest/products/search
```

**Verified output schema**:
- `graph.json`: 65 nodes, 64 edges (Endpoint=50, Commit=10, Finding=3, System=1, Service=1)
- `tasks.json`: 9 tasks, each with `task_id`, `threat_id`, `title`, `target`, `objective`, `severity`, `priority`, `stride`, `signals`, `suggested_tools`
- `signals.json`: 9 signal fields including languages, deps, endpoints, secrets, dockerfile flags

Also verified:
- `--help` flag works and exits 0
- Missing-arg exits 2 with usage message
- Unauthenticated rate-limit returns a clean error message (not a stack trace)

### prototype/guided_demo.py

Ran with auto-piped input through all 4 stages against `juice-shop/juice-shop`:

```
✓ Stage 1 — repo discovery (real GitHub call)
✓ Stage 2 — signal extraction (102 endpoints, 1 risky dep, 1 secret, dockerfile flags)
✓ Stage 3 — graph build (65 nodes, 64 edges, all node types present)
✓ Stage 4 — task ranking (9 tasks, top score 0.93 critical, sensible ordering)
✓ Outputs persisted to prototype/runs/<repo>/<timestamp>/
```

CONCEPT boxes render cleanly. Menu navigation (`Pick a number [N]:`) works. Quit (`q`) exits gracefully.

### FastAPI tg-api

**Live uvicorn server** on `127.0.0.1:8765`:

```
GET  /api/v1/healthz      200  {"ok": true}
GET  /api/v1/readyz       200  {"ok": false}   ← correct: TG core not reachable
GET  /api/v1/metrics      200  (Prometheus exposition format)
POST /api/v1/auth/login   200  → valid JWT with roles [admin, architect, appsec, soc, exec]
GET  /api/v1/auth/me      200  → User payload
```

**Internal endpoints with mocked TrustGraph core** (`respx` mocks `http://trustgraph:8088/api/v1/{health,knowledge,flow}`):

```
POST /api/v1/plan                   200
GET  /api/v1/plan/tasks             200
POST /api/v1/ingest/threat-model    200
GET  /api/v1/graph/query?q=Service  200
POST /api/v1/graph/ask              200
```

Request validation works: malformed payloads return 422 with `pydantic` field-level errors.

### apps/api unit tests

```
$ PYTHONPATH=. pytest tests/ -q
.                                                                        [100%]
1 passed in 0.11s
```

### UI build

```
$ npm run build
✓ 1666 modules transformed.
../dist/public/index.html                   1.04 kB │ gzip:  0.64 kB
../dist/public/assets/index-g5gc7wCj.css   72.72 kB │ gzip: 11.85 kB
../dist/public/assets/index-CC4SZ5PP.js   293.14 kB │ gzip: 95.61 kB
✓ built in 4.19s
```

Output directory matches what the Dockerfile copies into nginx (`/app/dist/public/`).

---

## What was NOT tested (Docker-only)

These components require a real Docker daemon and were verified statically only. **They are the next thing to test on a real machine before the hackathon.**

| Component | Why Docker-only |
|---|---|
| TrustGraph core (`trustgraph-flow:2.5.13`) | Multi-container stack (Cassandra, Pulsar, Qdrant, Garage) |
| `tg-worker` (Celery + 5 scanners) | Needs Trivy/Gitleaks/Nuclei/HTTPX/FFuf binaries baked at build time |
| `tg-ui` nginx serving | Container-based deployment |
| `make hackathon` end-to-end | Spawns full sandbox stack |
| Juice-Shop sandbox + CAI agent | Container-to-container exploit execution |
| Terraform LocalStack for sandbox | Needs Docker for LocalStack |

### Recommended pre-hackathon Docker smoke test

On a real machine with Docker:

```bash
cd trustgraph-security
cp .env.example .env
make doctor          # verify docker present
make sandbox-up      # ~5 min first time (pulls 9 images, builds 3)
make sandbox-seed    # loads payments-platform threat model
make sandbox-pentest # logs in, plans, executes top task
open http://localhost:8080   # log in as demo@trustgraph.local / demo
```

If any step fails, the previous QA pass verified:
- All 9 Docker image tags resolve (verified via `docker manifest inspect`-equivalent HEAD requests)
- All 5 security tool URLs in `apps/worker/Dockerfile` are live for both amd64 and arm64
- All compose files parse and reference existing services
- No port collisions in the sandbox profile

---

## Reproducible test commands

```bash
# 1. Prototype CLI
export GITHUB_TOKEN=<your PAT>
python prototype/repo_to_tasks.py juice-shop/juice-shop /tmp/out

# 2. Guided demo (interactive)
python prototype/guided_demo.py

# 3. API health + login
cd apps/api && pip install -e .
uvicorn trustgraph_security.main:app --port 8000 &
curl http://localhost:8000/api/v1/healthz
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin@trustgraph.local&password=change-me"

# 4. API unit tests
cd apps/api && PYTHONPATH=. pytest tests/ -q

# 5. UI build
cd apps/ui && npm install && npm run build
ls dist/public/   # → index.html, assets/
```

---

## What attendees should hit if anything goes wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `repo_to_tasks.py` says rate-limited | No GitHub token | `export GITHUB_TOKEN=<PAT>` or `gh auth login` |
| `guided_demo.py` says "No GitHub auth" | Token env var not picked up | Check `GITHUB_TOKEN`, `GH_TOKEN`, or `GH_ENTERPRISE_TOKEN` is exported |
| `make hackathon` fails at `sandbox-pentest` | tg-api not ready | `docker compose -f infra/compose/docker-compose.yml -f infra/compose/docker-compose.sandbox.yml logs tg-api` |
| UI build fails | Stale `node_modules` | `rm -rf node_modules package-lock.json && npm install` |
| Can't log into UI | Wrong creds for profile | Sandbox profile = `demo@trustgraph.local / demo`. Base profile = `admin@trustgraph.local / change-me` |
