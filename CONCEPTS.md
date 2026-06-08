# Security concepts in 5 minutes

Written for hackathon attendees who have never touched security tooling.
Every term TrustGraph Security uses, explained in plain English with the
example from our payments-platform demo.

---

## The big idea

Every company that builds software runs the same loop, badly:

1. Architects draw diagrams of what they're building.
2. Engineers write code.
3. Security people scan for problems and file thousands of tickets.
4. Pentesters get hired once a year to try to break in.
5. Nobody connects steps 1-4, so the same problems keep showing up.

**TrustGraph Security joins those four steps into a single living picture
and uses an AI agent to actually try the attacks.**

---

## Concepts you'll see in the UI

### Threat model
> *A list of "here's what could go wrong and where."*

Example: *"Someone could log into our admin portal as another user by
guessing IDs in the URL."* That sentence is one **threat** in a threat model.
Threats are written once by the architect (often during design), then
updated as the system evolves.

### Trust graph
> *A map of your system where every box and arrow has a meaning.*

Boxes are **nodes** — a service, a database, a user, an open port, a
threat, a code change. Arrows are **edges** — *contains*, *talks to*,
*owned by*, *threatens*, *changed by*. The graph stores them all together
so you can ask questions like *"which internet-facing services have a
critical unmitigated threat and a code change in the last week?"*

### Enrichment
> *Pulling real-world signals into the graph automatically.*

Four kinds of signal feed the graph continuously:

| Signal | Source | Example in the demo |
|---|---|---|
| **Code changes** | GitHub | "Alice merged PR #412 yesterday that touches the JWT logic" |
| **Code vulnerabilities** | Semgrep, Trivy, Gitleaks | "Line 42 of auth/jwt.py doesn't validate the audience claim" |
| **Live attack-surface issues** | Nuclei, ZAP | "/admin/login responds with the default-credentials template match" |
| **Runtime alerts** | SIEM, IAM, network | "Privileged role assumed from a weird IP at 3 AM" |

### Planner
> *The robot that decides what's actually worth attention today.*

There are always too many findings. The planner scores every open threat
on six signals and ranks them 0-99:

- **Exposure** — is it reachable from the internet?
- **Risk** — how bad would it be if exploited?
- **Control gap** — are there any mitigations in place?
- **Recent change** — has someone touched this code lately?
- **Runtime signal** — are we seeing suspicious activity right now?
- **Criticality** — is the affected service important?

You see the breakdown on every task, so you can argue with the score.

### AI pentest
> *Instead of describing the threat, an AI agent tries to do it.*

When you click **Execute** on a ranked task, an AI agent (built on the
open-source [CAI framework](https://github.com/aliasrobotics/cai)) gets a
written objective — *"validate the JWT audience bypass on
http://auth-service/v1/whoami without disrupting service"* — and a
toolbox: curl, httpx, sqlmap, ffuf, nuclei, ZAP. It works the problem
for a few minutes and returns a verdict:

- **Exploited** — yes, here's the curl command that worked
- **Mitigated** — tried, couldn't reproduce
- **Inconclusive** — needs a human

The verdict becomes a permanent **Evidence** node in the graph attached
to the threat.

### Evidence
> *Proof, not opinion.*

A finding is "scanner thinks this might be bad." Evidence is "we actually
ran the attack and here's what happened." TrustGraph stores both, but
the planner promotes threats with real evidence to the top of executive
reports.

---

## The five personas (and what they care about)

| Persona | Spends their day worried about… | What TrustGraph gives them |
|---|---|---|
| **Architect** | Whether the design is sound | A live diagram that updates as code ships |
| **AppSec engineer** | The 10,000-row vulnerability list | A ranked 20-item list with reasons |
| **SOC analyst** | Is something happening right now? | Runtime alerts attached to the threats they validate |
| **Pentest team** | Where to spend manual effort | The AI handles the easy half so they focus on hard ones |
| **Executive** | "Are we OK?" | One number per service; drill in to evidence |

---

## STRIDE — the security alphabet

When you see `Spoofing`, `Tampering`, `Repudiation`,
`InformationDisclosure`, `DenialOfService`, `ElevationOfPrivilege` on a
threat, that's **STRIDE** — the standard taxonomy for categorizing
threats. You don't need to memorize it; the UI shows the human label
next to the code.

Quick translation:

| STRIDE | Plain English |
|---|---|
| Spoofing | Pretending to be someone you're not |
| Tampering | Changing data you shouldn't |
| Repudiation | Doing something then denying it |
| Information Disclosure | Leaking data |
| Denial of Service | Knocking something offline |
| Elevation of Privilege | Becoming more powerful than you should be |

---

## What's in the box (sandbox)

The hackathon sandbox is a complete, self-contained world running on
your laptop:

- A **deliberately vulnerable demo app** (`tg-demo-target`) that pretends
  to be a payments platform and has six real flaws baked in.
- **All the scanners** pre-installed (Semgrep, Trivy, Gitleaks, Nuclei,
  ZAP, sqlmap, ffuf, httpx).
- **The AI agent** ready to attack the demo app.
- A **threat model** of the demo app already loaded so you have something
  to look at immediately.
- A **web UI** with the five persona views.

Nothing leaves your laptop. The vulnerable app is on its own isolated
Docker network — even if someone exploited it, the only thing they could
reach is the demo app itself.

---

## How to actually do something in 60 seconds

1. Open http://localhost:8080
2. Log in: **demo / demo**
3. Click **Pentest** in the sidebar
4. Look at the top task. Read the **Why this is ranked here** breakdown.
5. Click **Execute** — watch the AI agent work.
6. When it finishes, click the resulting **Evidence** node to see the
   exact curl command it used to prove the bug.

That's the loop. Everything else in the app is variations on it.
