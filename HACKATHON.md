# Hackathon guide — TrustGraph Security

Built for devs with **zero security background**. Every step teaches the
concept first, runs live, lets you inspect what just happened, and lets you
try other inputs to see how the result changes.

There is **no hardcoded data** in the demo path. Every number you see comes
from analyzing a real GitHub repo you picked.

---

## The 5-minute path

```bash
cd prototype
python guided_demo.py
```

You'll see:

1. **A menu of repos to analyze** — pick a known-vulnerable one (Juice Shop,
   WebGoat, DVWA, DVNA, NodeGoat), a real-world template (full-stack-fastapi),
   or **paste any GitHub URL**.
2. **4 staged screens**, each starting with a yellow `CONCEPT` box that
   explains in plain English what the stage does and why it matters.
3. **An inspect prompt after every stage** — pick a file to peek at its JSON,
   or continue.
4. **A ranked pentest task table** at the end, written to
   `prototype/runs/<repo>/<timestamp>/`.

You can quit at any prompt by typing `q`.

## The 15-minute path

Run `python guided_demo.py` twice with two different repos (e.g. Juice Shop
and the FastAPI template). Then choose **"Compare two runs"** on the main menu.
You'll see:

- Tasks **only in A** (threats specific to repo A)
- Tasks **only in B** (threats specific to repo B)
- Tasks **in both**, with priority deltas

This is the most instructive part for non-security folks: it shows that the
score isn't magic — it's a deterministic function of signals, so swapping the
repo changes the score in a predictable way.

## The 60-minute path (full stack)

```bash
cd sandbox/juice-shop
make demo
```

This boots LocalStack, applies the Terraform stack (19 AWS resources: VPC,
subnets, IGW, SGs, ALB, ECS cluster, task def, service, IAM roles, log
group), starts a real Juice Shop container on `:3000`, then runs the
analyzer against the Juice Shop repo. The ALB DNS name and the resulting
`tasks.json` are then pluggable into the production CAI worker.

---

## What each stage teaches

| Stage | Concept introduced | What devs see |
|---|---|---|
| 0. Pick repo | "Any repo works — vulnerable apps make patterns obvious" | Numbered menu + custom URL |
| 1. Fetch metadata | "Ground truth comes before reasoning" | Stars, languages, files pulled |
| 2. Extract signals | "Signals are small machine-checkable facts" + STRIDE in one sentence | Endpoints, secrets, risky deps, Docker flags, churn |
| 3. Build graph | "Why a graph beats a flat findings list" | RDF nodes + edges (System → Service → Endpoint, evidenced_by → Finding) |
| 4. Rank tasks | "The 6-signal score and weights" | Ranked task table, severity-colored |
| 5. Hand-off | "How CAI takes over from here" | Pointer to live target + production stack |
| (compare) | "Same threat, different score — and why" | Set diff + priority deltas |

## Try these experiments

The whole point is *let devs poke at it*. Concrete things to try:

1. **Run twice with the same repo** — outputs should be identical (the pipeline is deterministic). Reassures them there's no LLM hallucination.
2. **Run on a known-vulnerable app**, then on a hardened template — see how the threat surface changes (more secrets/upload endpoints in the vulnerable one).
3. **Run on a private/empty repo** — pipeline degrades gracefully, no crash.
4. **Paste a repo with no HTTP routes** (e.g. a Python library) — you'll get only repo-level threats (deps, container). Good demonstration of "signals → threats" coverage.
5. **Use `compare`** after two runs and explain to the next person why each task is or isn't in both lists.

## Cheat-sheet for the presenter

If a dev asks…

| Question | Short answer |
|---|---|
| "Is this an LLM picking tasks?" | No — the planner is deterministic 6-signal math. The LLM (CAI) only *executes* tasks; it doesn't pick what to attack. |
| "Why STRIDE letters?" | Spoofing / Tampering / Repudiation / Information disclosure / DoS / Elevation. Six buckets every threat fits into. |
| "Why a graph and not a database table?" | Threats depend on relationships ("this endpoint is exposed AND owned by Team X AND has no rate-limit control"). Relationships are first-class in a graph. |
| "What if my repo has nothing to find?" | You'll still get repo-level checks (deps, Docker). Great control case. |
| "Is this production-ready?" | The prototype is *deliberately tiny* — under 500 lines. The full stack in `apps/` does the same job at scale with Semgrep / Trivy / Gitleaks / Nuclei + CAI. |

## File map

```
prototype/
  guided_demo.py             ← run this
  repo_to_tasks.py           ← the pipeline (called by guided_demo)
  runs/<repo>/<timestamp>/   ← live outputs (graph.json, tasks.json, signals.json)
  samples/                   ← reference artifacts, NOT used by the demo

sandbox/juice-shop/
  README.md                  ← LocalStack ECS Fargate stack
  Makefile                   ← `make learn`, `make compare`, `make demo`, …
  docker-compose.localstack.yml
  terraform/*.tf             ← 19 AWS resources, validated
```
