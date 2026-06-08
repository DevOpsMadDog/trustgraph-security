# Hackathon walkthrough — 10 minutes, zero security knowledge required

This is the script. Read it once before you demo; you can deliver it
verbatim or paraphrase. Times in parentheses are cumulative.

---

## Setup (do this once, before the demo)

```bash
git clone <your-fork-of>/trustgraph-security && cd trustgraph-security
make hackathon
```

That single command:
1. Checks Docker is installed
2. Builds 4 local images (api, worker, ui, demo-target)
3. Starts 11 containers (10 for the platform + 1 vulnerable demo app)
4. Waits for the graph DB to be ready
5. Loads the demo threat model
6. Runs the first AI pentest
7. Opens your browser at http://localhost:8080

First run takes ~5 minutes (image pulls + build). Subsequent runs ~30 sec.

If anything fails, run `make doctor` to see why.

---

## The pitch (60 sec)

> "Most companies have four security tools: a threat model in a Confluence
> page nobody updates, a vulnerability scanner that finds 10,000 problems,
> a SIEM that pages the on-call at 3 AM, and a pentest report from last
> year. None of those four things talks to each other.
>
> TrustGraph Security joins them into one graph and adds an AI agent that
> actually tries the attacks. Let me show you."

---

## Step 1 · Overview (1:30)

**Click**: Overview (default landing)

**Say**:
> "This is the executive view. One number per category. Right now we have
> N critical threats, M proven exploitable. The bar chart shows our
> coverage by service — green is *we have evidence this is safe*, red is
> *we have evidence this is broken*, grey is *we haven't tested yet*."

**Point to**: the top-3 priorities card.

> "These three didn't get here by alphabet. The planner ranked everything
> based on six signals — exposure, risk, control gap, recent change,
> runtime activity, criticality. We'll see the math in a minute."

---

## Step 2 · Trust Graph (2:30)

**Click**: Trust Graph

**Say**:
> "Every box is a thing in our system — a service, a database, a code
> change, a threat, a finding. Every line is a relationship. Drag a node
> to move it. Click one to see its neighbors."

**Do**: Click on `auth-service`.

> "This is the auth service. Notice it has two pull requests linked to
> it (those came from GitHub), a critical Semgrep finding (came from
> static analysis), a SIEM alert (came from runtime monitoring), and two
> threats targeting it. Architects and AppSec engineers see the same
> graph and the same truth."

---

## Step 3 · Architect view (3:15)

**Click**: Architect

**Say**:
> "If you're the person who designed this, this is your view. You see
> services grouped by trust boundary, the data stores they touch, and
> which services cross boundaries. Anything that crosses a boundary is
> automatically suspicious — that's where most breaches happen."

---

## Step 4 · AppSec view (4:00)

**Click**: AppSec

**Say**:
> "If you're the AppSec engineer, this is your view. Every threat,
> tagged with STRIDE — the standard security categorization — colored by
> risk, with the controls that *should* be mitigating it listed
> underneath. See `thr-007`? Zero controls. That's a gap."

---

## Step 5 · SOC view (4:45)

**Click**: SOC

**Say**:
> "If you're a SOC analyst — the people who watch for live attacks — this
> is your view. Runtime alerts at the top, attached to the services and
> threats they touch. Notice this alert about a spike in failed logins?
> It's wired to the same auth-service we were just looking at."

---

## Step 6 · Pentest view (the money shot, 5:30)

**Click**: Pentest

**Say**:
> "Now the interesting part. This is the planner output. Top of the list,
> priority 99: JWT audience validation bypass on auth-service."

**Click**: expand the top task.

> "Here's why it's ranked 99: exposure 25 because it's internet-facing,
> risk 28 because it's critical, control gap 20 because we have nothing
> mitigating it, plus recent code activity, plus a runtime alert. The
> planner is showing its work."

> "Click Execute and an AI pentest agent — built on the open-source CAI
> framework — will actually try to exploit this. It has curl, sqlmap,
> ffuf, ZAP, nuclei, and a few other tools available. Let's run it."

**Click**: Execute on the top task.

> "While that runs (60 to 180 seconds), let me show you how it scales…"

---

## Step 7 · Ingest view (6:30)

**Click**: Ingest

**Say**:
> "Everything we just looked at came from one JSON blob — the threat
> model. You can POST one from CI, from a Confluence export, from a
> drawing tool, or paste it here. The platform also takes feeds from
> previous pipeline runs — point it at an S3 bucket or a folder and it
> pulls in last night's scanner output."

---

## Step 8 · Back to Pentest — Evidence (8:00)

**Click**: Pentest

The task you executed should now show "succeeded" or "exploited".

**Click**: the expanded task.

**Say**:
> "The agent finished. Outcome: exploited. It says it sent this exact
> curl command to /v1/whoami with a forged JWT and got back the admin
> user's identity. That curl command is now permanent evidence attached
> to the threat. If we look at the Overview again…"

**Click**: Overview

> "…that threat is now in the *Proven exploitable* count and our coverage
> bar for auth-service moved from grey to red. A real bug, with a
> reproducible PoC, in under two minutes, with no human touching a
> terminal."

---

## Step 9 · Why this matters (9:00)

> "Pick your favorite stakeholder:
>
> - **The CEO** wants one number that means *are we OK?* They get that
>   on the Overview.
> - **The Architect** wants to know if changes to the diagram introduce
>   new risk. They get that on the graph.
> - **The Engineer** wants a fixable ticket, not a CVSS score. The
>   Evidence is a Jira-ready ticket.
> - **The Auditor** wants proof. The evidence node is signed and
>   permanent.
>
> One graph. One platform. The AI does the grunt work. Engineers fix
> things. Auditors see proof. Executives see one number.
>
> Questions?"

---

## Q&A cheat sheet

**Q: Is the AI safe to point at production?**
> Not yet. In the sandbox it attacks a contained vulnerable app on an
> isolated Docker network. For production you'd run it against staging
> first, then a designated bug-bounty-style scope. The agent has rate
> limits and an explicit allow-list of targets.

**Q: What if we already have Wiz / Snyk / Splunk?**
> Great — those become enrichment sources. We ingest their findings
> into the graph; they don't disappear. TrustGraph is the layer
> *above* the scanners, not a replacement for them.

**Q: Where does the graph live?**
> An open-source graph DB called trustgraph-ai. Self-hosted; no data
> leaves your VPC. Backed by Cassandra and Qdrant.

**Q: What does the AI cost?**
> Each pentest task is one LLM agent loop, typically 5-15 turns.
> Roughly $0.10-$0.50 per task with Claude Sonnet or GPT-4o. You set
> the model in `.env`.

**Q: Open source?**
> The platform is Apache-2.0. The scanners are all open-source. The CAI
> framework is open-source. The graph DB is open-source.

**Q: How long to deploy at our company?**
> Day one: `docker compose up` and a 30-line YAML for your threat
> model. Week one: hook up Semgrep / Trivy / your SIEM. Month one:
> first AI pentest in staging.

---

## After the demo

```bash
make sandbox-down    # stop containers, keep data
make sandbox-wipe    # full reset
```

Tarball + source: see attached `trustgraph-security-v0.1.0.tar.gz`.
