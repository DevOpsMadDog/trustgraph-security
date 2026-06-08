# Prototype: interactive `GitHub repo → graph → pentest tasks`

For hackathon devs with zero security background. **Start here:**

```bash
pip install httpx
python guided_demo.py
```

`guided_demo.py` walks you through every stage — pauses to explain the
concept in plain English, runs against any repo you pick, lets you inspect
intermediate JSON, and writes timestamped outputs to `runs/<repo>/<ts>/`.

For non-interactive use (CI, scripts):

```bash
python repo_to_tasks.py https://github.com/<owner>/<repo>
# optional out_dir:
python repo_to_tasks.py owner/repo /tmp/myrun
```

## What goes in / what comes out

```
GitHub URL → metadata → signals → graph.json → ranked tasks.json
```

| File           | What's in it                                                  |
|----------------|---------------------------------------------------------------|
| `signals.json` | Raw extracted signals (langs, deps, endpoints, secrets, …)    |
| `graph.json`   | Nodes + edges in the **same RDF ontology** used by production |
| `tasks.json`   | Ranked pentest tasks, each with objective + suggested tools   |

## How it maps to the full system

| Prototype function          | Production module                                                   |
|-----------------------------|---------------------------------------------------------------------|
| `fetch_repo_metadata()`     | `apps/api/.../feeds.py` (+ Celery ingest workers)                   |
| `extract_signals()`         | `apps/worker/.../scanners.py` (Semgrep, Trivy, Gitleaks, Nuclei)    |
| `build_graph()`             | `apps/api/.../normalize.py` → `tg_client.py` writes to trustgraph-ai|
| `score_threats()` / `_score`| `apps/api/.../planner.py` (same 6-signal formula)                   |
| `tasks.json`                | Tasks the CAI agent (`apps/worker/.../pentest.py`) executes         |

## No mocks, no hardcoding

Every number on screen comes from a live call to the GitHub API and a
deterministic local computation. The `samples/` folder contains frozen
reference artifacts for documentation, not used by the demo.

See `../HACKATHON.md` for the full guided experience.
