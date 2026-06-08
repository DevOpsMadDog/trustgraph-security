# Juice Shop on ECS Fargate (LocalStack) — TrustGraph Security demo

Following the pattern of [Bharath's Medium article](https://medium.com/@bharath181994/create-and-run-web-app-on-ecs-using-aws-fargate-3199551c6c1b)
*(console-based)* but realized as **Terraform on LocalStack** — no AWS account, no cost, runs on a laptop. After the stack is up, we point the
TrustGraph prototype at the Juice Shop repo to auto-generate a ranked pentest task list — the same loop the full product runs against your own services.

```
LocalStack (emulated AWS)           Real running container
┌──────────────────────────┐        ┌──────────────────────────┐
│  Terraform applies:      │        │  bkimminich/juice-shop   │
│  VPC, 2 subnets, IGW,    │        │  on host:3000            │
│  2 SGs, ALB + TG + LSNR, │        │                          │
│  ECS cluster + task def  │  ◀────▶│  (so HTTP pentest tools  │
│  + service, 2 IAM roles, │        │   have something real    │
│  CloudWatch log group    │        │   to hit)                │
│  ── 19 AWS resources ──  │        │                          │
└──────────────────────────┘        └──────────────────────────┘
                  ▲                                 ▲
                  │                                 │
                  └────────  prototype/repo_to_tasks.py  ────────┐
                            (graph + 9 ranked pentest tasks)    │
                                                                 ▼
                                                         tasks.json
```

## Prereqs (local laptop)

- Docker + Docker Compose
- Terraform ≥ 1.5 (`brew install terraform`)
- `awslocal` and `tflocal` (optional, nice to have):
  `pip install awscli-local terraform-local`

## One-command demo

```bash
cd sandbox/juice-shop
make demo
```

That target runs: `up` → `tf-apply` → `verify` → `pentest`. About 60–90 s on a warm cache.

## What it does, step by step

| Step | Command | What happens |
|---|---|---|
| 1 | `make up` | Starts LocalStack (port 4566) + Juice Shop (port 3000). Health-checks both. |
| 2 | `make tf-apply` | `terraform apply` against LocalStack. Creates **19 AWS resources**: VPC, 2 subnets, IGW, route table, 2 SGs, ALB+TG+listener, ECS cluster, task def, service, 2 IAM roles, log group. |
| 3 | `make verify` | Curls LocalStack health, lists ECS clusters and ALB DNS, fetches Juice Shop banner. |
| 4 | `make pentest` | Runs `prototype/repo_to_tasks.py` against `github.com/juice-shop/juice-shop`. Writes `tasks.json`. |

## What you get out

Running the prototype against the real Juice Shop repo produces:

- **102 HTTP endpoints** extracted from `server.ts` + route files
- **65 graph nodes** (1 System, 1 Service, 50 Endpoints, 10 Commits, 3 Findings) in the same RDF ontology the production stack uses
- **9 ranked pentest tasks**, top picks:

| Score | Sev | STRIDE | Threat | Target | Tools |
|---|---|---|---|---|---|
| 0.93 | crit | I | Hard-coded credentials in repo | repo-wide | gitleaks, trufflehog |
| 0.87 | high | T | Unrestricted file upload | `POST /file-upload` | curl, ffuf |
| 0.87 | high | T | Unrestricted file upload | `POST /profile/image/file` | curl, ffuf |
| 0.87 | high | S | No visible rate limiting | `POST /rest/user/login` | ffuf, hydra |
| 0.87 | high | T | Possible injection | `GET /rest/products/search` | sqlmap |
| 0.87 | high | E | Admin authz bypass / IDOR | `GET /rest/admin/application-version` | curl, burp, ffuf |
| 0.87 | high | E | Admin authz bypass / IDOR | `GET /rest/admin/application-configuration` | curl, burp, ffuf |
| 0.78 | med  | T | Risky deps | repo-wide | trivy, osv-scanner |
| 0.78 | med  | E | Container runs as root | Dockerfile | trivy, dockle |

Every one of these maps to a real, documented Juice Shop challenge — so the demo doubles as a sanity check that the planner picks the *right* things to attack.

## Hand-off into the full TrustGraph stack

`tasks.json` is in the exact shape `apps/worker/.../pentest.py` consumes. Feed it in like this:

```bash
# Inside the main stack
curl -sX POST http://localhost:8000/api/v1/pentest/enqueue \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @../../prototype/tasks.json
```

CAI then autonomously attacks each target on Juice Shop (`http://localhost:3000`) and writes evidence back into trustgraph-ai.

## Why LocalStack and not real AWS

- Zero cloud cost, repeatable in CI
- All AWS APIs we use (`ec2`, `ecs`, `ecr`, `elbv2`, `iam`, `logs`, `cloudwatch`, `sts`, `secretsmanager`, `ssm`) are in LocalStack Free
- Same Terraform applies to real AWS by removing the `endpoints { … }` block and dropping `skip_credentials_validation`

## Tear down

```bash
make down     # stop containers, keep state
make wipe     # nuke everything (containers, volumes, .terraform, tfstate)
```
