# Hackathon Primer — AI Pentesting Across the SDLC

> **Audience:** Developers learning how AI is changing security testing.
> **Goal:** By the end of this doc you'll know how AI pentesting flows from **design → code → runtime → LLM apps**, what open-source tools exist at each stage, and what enterprises need before they trust any of it.
>
> **TrustGraph-Security is one tool in this story** — the whitebox/runtime example we'll run in the hackathon. The patterns transfer to every other tool in the field.
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

## Part 5 — AI Pentesting Across the SDLC

AI is showing up at every stage of the software lifecycle. Each stage has its own open-source tools, its own strengths, and its own enterprise-trust questions.

```mermaid
flowchart LR
    D[1·Design] --> C[2·Code]
    C --> R[3·Runtime]
    R --> L[4·LLM App]

    D -.- D1["Threat-model<br/>before code exists"]
    C -.- C1["Read repo →<br/>rank attack surface"]
    R -.- R1["Attack deployed<br/>system autonomously"]
    L -.- L1["Test the AI itself<br/>jailbreaks · prompt injection"]

    style D fill:#e3f2fd
    style C fill:#fff3cd
    style R fill:#ffe5b4
    style L fill:#f8d7da
```

> **For full per-tool detail, see [LANDSCAPE.md](./LANDSCAPE.md). For the enterprise trust matrix, see [ENTERPRISE.md](./ENTERPRISE.md).**

### Stage 1 — Design (shift-left threat modeling)

```mermaid
flowchart LR
    A[You write<br/>service.yaml] --> B[GPT-4 / Claude]
    B --> C[STRIDE-mapped<br/>HTML report]
    style A fill:#fff3cd
    style C fill:#d4edda
```

- **Tool**: [TaaC-AI](https://github.com/yevh/TaaC-AI) — Threat-modeling-as-code via LLMs
- **Strength**: Catches threats before a line is written. Cheap, fast, language-agnostic.
- **Trust gap**: Models the YAML, not reality. Stale description = stale threat model.

### Stage 2 — Code (whitebox autonomous)

```mermaid
flowchart LR
    R[📦 GitHub repo] --> P[Parse code]
    P --> G[Build graph<br/>endpoints · auth · data flows]
    G --> S[Score · rank]
    S --> T[Ranked attack tasks<br/>with code refs]
    style R fill:#e3f2fd
    style G fill:#fff3cd
    style T fill:#d4edda
```

- **Tools**: [Shannon by Keygraph](https://github.com/KeygraphHQ/shannon), **TrustGraph-Security** (this repo)
- **Strength**: Findings link back to file + line. Devs know what to fix.
- **Trust gap**: Source code leaves perimeter unless self-hosted LLM is used.

### Stage 3 — Runtime (black-box autonomous)

```mermaid
flowchart TB
    A[You give URL/goal] --> O[Orchestrator agent]
    O --> R[Recon agent]
    O --> E[Exploit agent]
    E --> K[Kali sandbox<br/>nmap · metasploit · sqlmap · 20+ tools]
    K --> Rep[Vulnerability report]
    style O fill:#e3f2fd
    style K fill:#f8d7da
    style Rep fill:#d4edda
```

- **Tools**: [PentAGI](https://github.com/vxcontrol/pentagi), [PentestGPT](https://github.com/GreyDGL/PentestGPT), XBOW (commercial)
- **Strength**: Real exploits, real PoCs, mature toolchains.
- **Trust gap**: No code awareness — finds bugs but not the root cause line.

### Stage 4 — LLM-app testing (the new attack surface)

```mermaid
flowchart LR
    A[Your LLM app] --> B[Adversarial prompts]
    B --> C[Jailbreak attempts]
    B --> D[Prompt injection]
    B --> E[Data extraction]
    C & D & E --> R[Behavioral report<br/>OWASP LLM Top 10]
    style A fill:#e3f2fd
    style R fill:#d4edda
```

- **Tools**: [Promptfoo](https://www.promptfoo.dev/), [PyRIT (Microsoft)](https://github.com/Azure/PyRIT), [Garak (NVIDIA)](https://github.com/NVIDIA/garak)
- **Strength**: Tests behavior an LLM-based app exhibits, not its hosting infra.
- **Trust gap**: Models change; tests need continuous re-runs to stay valid.

### The lifecycle in one diagram

```mermaid
flowchart TB
    subgraph SDLC["AI Pentesting Across the SDLC"]
        direction LR
        D[1·Design<br/><br/>TaaC-AI] --> C[2·Code<br/><br/>Shannon<br/>TrustGraph]
        C --> R[3·Runtime<br/><br/>PentAGI<br/>PentestGPT]
        R --> L[4·LLM-app<br/><br/>Promptfoo<br/>PyRIT · Garak]
    end
    SDLC --> ENT[🏢 Enterprise Trust Layer<br/>local LLMs · audit · scope · evidence · SLAs]
    style D fill:#e3f2fd
    style C fill:#fff3cd
    style R fill:#ffe5b4
    style L fill:#f8d7da
    style ENT fill:#d4edda,stroke:#155724
```

Most of these are open source. **No enterprise will plug them in raw** — that's the gap [ENTERPRISE.md](./ENTERPRISE.md) addresses.

---

## Part 6 — TrustGraph-Security as the Hands-On Example

We picked the **whitebox/code stage** for the hackathon because it's where most devs spend their time — and where a graph + ranked tasks teaches the most transferable patterns.

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

### Whitebox + blackbox in the same loop

```mermaid
flowchart TB
    subgraph WB["📖 Whitebox half"]
        U1[Read REAL code → graph]
        U2[Rank attacks by<br/>actual exposure]
    end

    subgraph BB["💥 Blackbox half"]
        U3[Execute against<br/>deployed copy]
        U4[Map findings back<br/>to code line]
    end

    WB --> BB
    style WB fill:#fff3cd,stroke:#856404
    style BB fill:#d4edda,stroke:#155724
```

Most tools do one half. The hackathon lets you watch both halves run end-to-end on a repo you choose.

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
- 🌍 [AI pentest landscape — tools per SDLC stage](./LANDSCAPE.md)
- 🏢 [Enterprise trust matrix](./ENTERPRISE.md)
- 🚀 [5 / 15 / 60-min paths](./HACKATHON.md)
- 🎬 [Presenter walkthrough](./WALKTHROUGH.md)
- 🚢 [Full deployment](./DEPLOY.md)
