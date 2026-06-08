# Hackathon Primer — 15 Minutes Before the Demo

> **Audience:** Developers who have never written a threat model or run a pentest.
> **Goal:** By the end of this doc you'll know *what* threat modeling is, *how* pentesters think, *what* AI is already doing in this space, and *why* TrustGraph-Security exists.
>
> **Time:** ~15 min skim. Then we run the demo.

---

## Part 1 — Threat Modeling in One Picture

**Threat modeling** = sitting down *before* you ship and asking "if I were a bad guy, how would I break this?"

```mermaid
flowchart LR
    A[Feature idea] --> B{Threat model<br/>30 min}
    B --> C[List of<br/>'what could go wrong']
    C --> D[Decide: fix now /<br/>fix later / accept]
    D --> E[Ship safer code]

    style B fill:#fff3cd,stroke:#856404
    style C fill:#f8d7da,stroke:#721c24
    style E fill:#d4edda,stroke:#155724
```

It's a **code review for abuse**, not for cleanliness.

### A real threat model is just a small table

```mermaid
flowchart TB
    subgraph TM["Threat model for /api/upload"]
        T1["#1 · Critical<br/>Uploaded file runs as code"]
        T2["#2 · High<br/>User A reads User B's files"]
        T3["#3 · Medium<br/>Giant file → DoS"]
    end
    style T1 fill:#f8d7da,stroke:#721c24
    style T2 fill:#ffe5b4,stroke:#cc6600
    style T3 fill:#fff3cd,stroke:#856404
```

You don't have to *fix* everything — you have to **know it exists** so you can decide.

### Why devs skip it

```mermaid
flowchart LR
    A[Dev] -->|"'security team will do it'"| B[❌ No security team]
    A -->|"'I don't know STRIDE'"| C[❌ Never learned it]
    A -->|"'boring documentation'"| D[❌ Fair point]
    B & C & D --> E[Result:<br/>never happens]
    E --> F[💡 So let AI do it]
    style F fill:#d4edda,stroke:#155724
```

---

## Part 2 — STRIDE in One Diagram

STRIDE = **6 categories of things that can go wrong.** Memorize the letters, cover 80% of real bugs.

```mermaid
mindmap
  root((STRIDE))
    S - Spoofing
      Pretend to be someone else
      Stolen cookie → log in as victim
    T - Tampering
      Change data you shouldn't
      Edit price=99 → price=0
    R - Repudiation
      Deny you did something
      No audit log = can't prove anything
    I - Info Disclosure
      Leak data
      API returns password_hash
    D - Denial of Service
      Knock system offline
      One slow query × 1000 requests
    E - Elevation of Privilege
      Become admin
      /admin/* missing role check
```

### How to use STRIDE in 30 seconds

```mermaid
flowchart LR
    A[Pick any endpoint] --> B[For each STRIDE letter:<br/>could this happen?]
    B --> C{Yes?}
    C -->|Yes| D[Write it down]
    C -->|No| E[Move on]
    D & E --> F[That's a threat model. Done.]
    style F fill:#d4edda,stroke:#155724
```

---

## Part 3 — MITRE ATT&CK: The Attacker's Playbook

If STRIDE is "what *categories* of bug exist," MITRE ATT&CK is **"what real attackers actually do, in order."**

Attackers don't find one bug and win — they **chain bugs**. MITRE catalogues every step.

```mermaid
flowchart LR
    A[Recon] --> B[Initial<br/>Access]
    B --> C[Execution]
    C --> D[Persistence]
    D --> E[Privilege<br/>Escalation]
    E --> F[Defense<br/>Evasion]
    F --> G[Credential<br/>Access]
    G --> H[Discovery]
    H --> I[Lateral<br/>Movement]
    I --> J[Collection]
    J --> K[Exfiltration]
    K --> L[Impact]

    style A fill:#e3f2fd
    style B fill:#bbdefb
    style E fill:#ffcdd2
    style I fill:#ffcdd2
    style K fill:#f8d7da,stroke:#721c24
    style L fill:#f8d7da,stroke:#721c24
```

### A real attack chain

```mermaid
sequenceDiagram
    actor Attacker
    participant Web as /upload<br/>endpoint
    participant Shell as Web shell
    participant Env as .env file
    participant DB as Prod DB
    participant Out as Attacker laptop

    Attacker->>Web: Upload evil.php<br/>(T1190 Initial Access)
    Web-->>Attacker: 200 OK · saved to /uploads/
    Attacker->>Shell: GET /uploads/evil.php<br/>(T1059 Execution)
    Shell-->>Attacker: Shell prompt 🎯
    Attacker->>Env: cat .env<br/>(T1552 Cred Access)
    Env-->>Attacker: DB_PASSWORD=hunter2
    Attacker->>DB: psql with stolen creds<br/>(T1078 Lateral Movement)
    DB-->>Attacker: ✅ Connected
    Attacker->>Out: SELECT * FROM users<br/>(T1041 Exfiltration)
    Out-->>Attacker: 💀 50K user records
```

You don't memorize T-numbers. You internalize: **real attacks are graphs, not single bugs.**

### STRIDE vs MITRE — one picture

```mermaid
flowchart TB
    subgraph STRIDE["🛡️ STRIDE — Defender's view"]
        S1[Look at YOUR CODE]
        S2[For each piece:<br/>what category could break?]
    end

    subgraph MITRE["⚔️ MITRE — Attacker's view"]
        M1[Look at ATTACKER]
        M2[For each step:<br/>what technique do they use?]
    end

    STRIDE -.->|"Same bug,<br/>different lens"| MITRE
    style STRIDE fill:#d4edda,stroke:#155724
    style MITRE fill:#f8d7da,stroke:#721c24
```

---

## Part 4 — How a Pentest Actually Works

```mermaid
flowchart LR
    A[1·Recon] --> B[2·Scanning]
    B --> C[3·Exploit]
    C --> D[4·Post-Exploit]
    D --> E[5·Report]

    A -.- A1["'What does this<br/>look like outside?'"]
    B -.- B1["'What versions /<br/>endpoints exposed?'"]
    C -.- C1["'Can I get in?'"]
    D -.- D1["'What else can<br/>I reach now?'"]
    E -.- E1["'Here's what I<br/>found, ranked.'"]

    style A fill:#e3f2fd
    style B fill:#e3f2fd
    style C fill:#fff3cd
    style D fill:#ffe5b4
    style E fill:#d4edda
```

### Where the value actually is

```mermaid
pie title Where pentest value comes from
    "Recon + Scanning (info gathering)" : 60
    "Reporting (writeup)" : 25
    "Exploitation (the movie scene)" : 15
```

**90% of the work is information gathering + writeup.** That's exactly what LLMs are good at — which is why AI pentest tools exist.

---

## Part 5 — The AI Pentest Tool Landscape

Three tools devs will recognize the names of. Here's how they differ.

```mermaid
quadrantChart
    title AI Pentest Tools — Code Awareness vs Autonomy
    x-axis "Blind to code" --> "Reads your code"
    y-axis "Manual / Copilot" --> "Fully autonomous"
    quadrant-1 "Read code + autonomous"
    quadrant-2 "Autonomous black-box"
    quadrant-3 "Manual + blind"
    quadrant-4 "Read code, manual"
    "TaaC-AI": [0.25, 0.2]
    "PentestGPT": [0.15, 0.75]
    "PentAGI": [0.2, 0.9]
    "TrustGraph-Security": [0.85, 0.85]
```

### TaaC-AI — Threat modeling as code

```mermaid
flowchart LR
    A[You write<br/>service.yaml] --> B[GPT-4 / Claude]
    B --> C[STRIDE-mapped<br/>HTML report]
    style A fill:#fff3cd
    style C fill:#d4edda
```

- ✅ Cheap, fast, language-agnostic
- ❌ You hand-write the YAML — it never sees your real code
- 🎯 Best for: design reviews before code exists
- 🔗 [yevh/TaaC-AI](https://github.com/yevh/TaaC-AI)

### PentestGPT — GPT as your pentest copilot

```mermaid
flowchart LR
    A[You give URL] --> B[PentestGPT]
    B -->|"'run this'"| C[nmap, sqlmap,<br/>etc.]
    C -->|output| B
    B --> D[Next step]
    D --> B
    B --> E[Final report]
    style B fill:#e3f2fd
    style E fill:#d4edda
```

- ✅ ~90% solve rate on Hack The Box · mature (3 years) · now fully autonomous
- ❌ Black-box only — finds the bug, can't tell you the *line of code*
- ❌ Needs OpenAI API key with billing
- 🎯 Best for: you have a URL, you want to know if it's broken
- 🔗 [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT)

### PentAGI — Autonomous pentester in a Docker sandbox

```mermaid
flowchart TB
    A[You give goal in English] --> O[Orchestrator agent]
    O --> R[Researcher agent]
    O --> D[Developer agent]
    O --> E[Executor agent]
    E --> K[Kali Linux container<br/>nmap, metasploit, sqlmap, +20 tools]
    K --> Rep[Vulnerability report]
    style O fill:#e3f2fd
    style K fill:#f8d7da
    style Rep fill:#d4edda
```

- ✅ Most autonomous · multi-LLM (OpenAI, Anthropic, Gemini, Ollama) · production observability
- ❌ Heavy stack (multiple containers, Postgres, vector DB) · still black-box
- 🎯 Best for: replacing a junior pentester for routine scans
- 🔗 [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi)

### The comparison table

| Tool | Reads your code? | Black-box attacks? | Threat model? | Self-driving? | Devs can run it? |
|------|:---:|:---:|:---:|:---:|:---:|
| TaaC-AI | ❌ needs YAML | ❌ | ✅ STRIDE | ❌ | ✅ |
| PentestGPT | ❌ | ✅ | ❌ | ✅ | ⚠️ API key |
| PentAGI | ❌ | ✅ | ❌ | ✅ | ⚠️ heavy |
| **TrustGraph-Security** | ✅ **from repo** | ✅ via CAI | ✅ STRIDE+MITRE | ✅ | ✅ **one command** |

---

## Part 6 — So What Are We Building?

**TrustGraph-Security** is the missing column on that table.

> **"Point me at a GitHub repo. I'll read the code, build a security knowledge graph, rank the realistic attack paths, and run a live pentest against a deployed copy."**

### The pipeline

```mermaid
flowchart LR
    R[📦 Any<br/>GitHub repo] --> P[1·Parse code<br/>endpoints · auth ·<br/>DB queries · file ops]
    P --> G[2·Build<br/>knowledge graph<br/>nodes + data flows]
    G --> S[3·Score<br/>6 signals]
    S --> T[4·Ranked tasks<br/>STRIDE + MITRE tagged]
    T --> C[5·CAI executes<br/>attacks live]
    C --> Rep[6·Report<br/>with code references]

    style R fill:#e3f2fd
    style G fill:#fff3cd
    style T fill:#ffe5b4
    style Rep fill:#d4edda

    P -.- P1[whitebox]
    C -.- C1[blackbox sandbox]
    style P1 fill:#fff,stroke-dasharray:3
    style C1 fill:#fff,stroke-dasharray:3
```

### Why this is different — whitebox + blackbox

```mermaid
flowchart TB
    subgraph Others["🤖 PentestGPT / PentAGI"]
        O1[Probe from outside]
        O2[Guess what to attack]
        O3[Find bug · don't know<br/>where in code]
    end

    subgraph TaaC["📝 TaaC-AI"]
        T1[Read hand-written YAML]
        T2[Threat-model the<br/>description not reality]
    end

    subgraph Us["🎯 TrustGraph-Security"]
        U1[Read REAL code → graph]
        U2[Rank attacks by<br/>actual exposure]
        U3[Execute against<br/>deployed copy]
        U4[Map findings back<br/>to code line]
    end

    style Others fill:#f8d7da,stroke:#721c24
    style TaaC fill:#fff3cd,stroke:#856404
    style Us fill:#d4edda,stroke:#155724
```

### The 6-signal scorer

```mermaid
flowchart LR
    G[Graph node:<br/>one endpoint] --> S1[🌐 Exposure<br/>public? auth'd?]
    G --> S2[💎 Sensitivity<br/>touches PII / money?]
    G --> S3[🔗 Reachability<br/>how many hops in?]
    G --> S4[🔓 Auth gap<br/>missing checks?]
    G --> S5[📚 CVE prior<br/>known pattern?]
    G --> S6[👃 Code smell<br/>raw SQL · eval · etc.]

    S1 & S2 & S3 & S4 & S5 & S6 --> R[🎯 Risk score 0–100]
    R --> Rank[Ranked task list]

    style G fill:#e3f2fd
    style R fill:#fff3cd
    style Rank fill:#d4edda
```

---

## Part 7 — What Happens Next

```mermaid
flowchart TB
    Now[⏰ Now<br/>You're reading this] --> Read[📖 Next 15 min<br/>Read README + HACKATHON]
    Read --> Pick{Pick your path}
    Pick -->|5 min| P1[🚀 prototype/guided_demo.py<br/>any repo · in terminal]
    Pick -->|15 min| P2[☁️ Deploy Juice Shop to<br/>LocalStack · run pipeline]
    Pick -->|60 min| P3[🏗️ Full stack via<br/>Docker Compose]
    P1 & P2 & P3 --> H[🏆 Hackathon begins<br/>Pick any repo · find the<br/>gnarliest attack chain]

    style Now fill:#e3f2fd
    style Read fill:#fff3cd
    style H fill:#d4edda,stroke:#155724
```

The graph and the tasks belong to you. The leaderboard is whoever finds the nastiest attack chain.

Welcome. Now read the rest of the room.

---

### Quick reference

- 🗺️ [Architecture diagram](./ARCHITECTURE.md)
- 📖 [Security concepts glossary](./CONCEPTS.md)
- 🚀 [5 / 15 / 60-min paths](./HACKATHON.md)
- 🎬 [Presenter walkthrough](./WALKTHROUGH.md)
- 🚢 [Full deployment](./DEPLOY.md)
