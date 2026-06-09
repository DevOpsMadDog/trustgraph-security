"""
TrustGraph Security — Guided hackathon demo
===========================================

Audience: developers with zero security background.

This script is the only thing they should run. It walks them through every
stage of the pipeline, *teaching as it goes*, pausing for input, and letting
them inspect intermediate artifacts before continuing.

It is fully live — there is no hardcoded data, no mocks. Every number on
screen is produced by `repo_to_tasks.run(...)` against whatever GitHub repo
the user picks.

Run it with:
    python guided_demo.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Callable

# repo_to_tasks lives next to this file
sys.path.insert(0, str(Path(__file__).resolve().parent))
from repo_to_tasks import run as run_pipeline  # noqa: E402


# ---------- terminal helpers --------------------------------------------

ANSI = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "red":    "\033[31m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "blue":   "\033[34m",
    "cyan":   "\033[36m",
    "mag":    "\033[35m",
}


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, *styles: str) -> str:
    if not supports_color():
        return text
    return "".join(ANSI[s] for s in styles) + text + ANSI["reset"]


def hr(char: str = "─") -> str:
    try:
        width = min(80, os.get_terminal_size().columns)
    except OSError:
        width = 80
    return char * width


def banner(title: str, subtitle: str = "") -> None:
    print()
    print(c(hr("═"), "cyan"))
    print(c(f"  {title}", "bold", "cyan"))
    if subtitle:
        print(c(f"  {subtitle}", "dim"))
    print(c(hr("═"), "cyan"))


def teach(title: str, body: str) -> None:
    """Render a 'concept' callout — the teaching part of each stage."""
    print()
    print(c("┌─ CONCEPT ─ " + title + " " + "─" * max(0, 60 - len(title)), "yellow"))
    for line in textwrap.wrap(body.strip(), width=74):
        print(c("│ ", "yellow") + line)
    print(c("└" + "─" * 74, "yellow"))


def info(msg: str) -> None:
    print(c("ℹ ", "blue") + msg)


def ok(msg: str) -> None:
    print(c("✓ ", "green") + msg)


def warn(msg: str) -> None:
    print(c("! ", "yellow") + msg)


# ---------- interactive controls ----------------------------------------

def pause(prompt: str = "Press Enter to continue, [q] to quit, [s] to skip teaching") -> str:
    """Returns the user's keystroke (lower-cased), '' for Enter."""
    try:
        v = input(c(f"\n› {prompt} ", "dim")).strip().lower()
    except EOFError:
        # Non-interactive (CI, piped stdin exhausted) — just continue
        return ""
    if v == "q":
        print(c("\nBye.", "dim"))
        sys.exit(0)
    return v


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(c(f"❯ {prompt}{suffix}: ", "bold")).strip()
    except EOFError:
        return default or ""
    return v or (default or "")


def menu(prompt: str, options: list[tuple[str, str]], default_idx: int = 0) -> str:
    """Render a numbered menu. Returns the chosen option's key."""
    print()
    print(c(prompt, "bold"))
    for i, (_, label) in enumerate(options, 1):
        marker = c("→", "green") if i - 1 == default_idx else " "
        print(f"  {marker} {c(str(i), 'cyan')}. {label}")
    while True:
        v = ask("Pick a number", default=str(default_idx + 1))
        try:
            n = int(v)
            if 1 <= n <= len(options):
                return options[n - 1][0]
        except ValueError:
            pass
        warn(f"Enter 1..{len(options)}")


# ---------- repo picker -------------------------------------------------

SUGGESTED_REPOS = [
    ("juice-shop/juice-shop",
     "OWASP Juice Shop — the famous intentionally-vulnerable Node/TS shop"),
    ("OWASP/NodeGoat",
     "OWASP NodeGoat — Top-10 demo (older, simpler)"),
    ("appsecco/dvna",
     "Damn Vulnerable Node Application — small & fast"),
    ("digininja/DVWA",
     "Damn Vulnerable Web App — classic PHP target"),
    ("WebGoat/WebGoat",
     "OWASP WebGoat — Java/Spring training app"),
    ("fastapi/full-stack-fastapi-template",
     "A *real* template (not vulnerable on purpose) — good control case"),
    ("__custom__",
     "Bring your own — paste any public GitHub URL"),
]


def pick_repo() -> str:
    banner("Step 0 — Pick a repository",
           "Anything on GitHub works. Vulnerable apps make the demo prettier.")
    teach(
        "What we're about to do",
        "We'll point the analyzer at a real GitHub repository. From the "
        "repo alone — no running app, no credentials — we will (1) extract "
        "security-relevant signals, (2) build a knowledge graph, and "
        "(3) produce a ranked list of pentest tasks. You can try this with "
        "any repo: a known-vulnerable one to see the system 'light up', or "
        "your own to see what it picks out.",
    )
    key = menu("Pick a target repo to analyze:", SUGGESTED_REPOS, default_idx=0)
    if key == "__custom__":
        url = ask("Paste a GitHub URL or owner/repo", default="juice-shop/juice-shop")
        return url
    return key


# ---------- inspect helpers ---------------------------------------------

def show_json_preview(path: Path, max_chars: int = 1400) -> None:
    raw = path.read_text()
    print(c(f"\n── {path.name} ──", "dim"))
    if len(raw) <= max_chars:
        print(raw)
    else:
        print(raw[:max_chars])
        print(c(f"... ({len(raw) - max_chars} more chars; full file: {path})", "dim"))


def inspect_loop(artifacts: dict[str, Path]) -> None:
    """Let the user open intermediate JSON files in a tiny REPL."""
    while True:
        print()
        print(c("Inspect what just happened?", "bold"))
        names = list(artifacts.keys())
        for i, n in enumerate(names, 1):
            print(f"  {c(str(i), 'cyan')}. {n}  {c(str(artifacts[n]), 'dim')}")
        print(f"  {c(str(len(names) + 1), 'cyan')}. continue to next stage")
        v = ask("Pick a number", default=str(len(names) + 1))
        try:
            n = int(v)
        except ValueError:
            continue
        if n == len(names) + 1:
            return
        if 1 <= n <= len(names):
            show_json_preview(artifacts[names[n - 1]])


# ---------- stages ------------------------------------------------------

def stage_fetch(repo: str) -> dict[str, Any]:
    banner("Stage 1 / 4 — Fetch repository metadata",
           "What the GitHub API gives us about this codebase")
    teach(
        "Why we start here",
        "Before reasoning about security, the system needs ground truth: "
        "what languages are used, what dependencies are declared, what files "
        "exist, and how the codebase is changing. We pull this from the "
        "GitHub REST API. No code execution yet — just metadata.",
    )
    pause("Press Enter to fetch")
    from repo_to_tasks import _parse_repo, fetch_repo_metadata
    owner, name = _parse_repo(repo)
    info(f"Calling GitHub for {owner}/{name} …")
    meta = fetch_repo_metadata(owner, name)
    ok(f"Repo: {meta['repo'].get('full_name')} "
       f"({meta['repo'].get('stargazers_count', 0)} ★)")
    ok(f"Default branch: {meta['repo'].get('default_branch', '?')}")
    ok(f"Languages: {', '.join(list(meta['languages'])[:5]) or 'unknown'}")
    ok(f"Recent commits sampled: {len(meta.get('commits') or [])}")
    ok(f"High-signal files pulled: {len(meta.get('files') or {})}")
    if meta.get("files"):
        for fname in list(meta["files"])[:6]:
            print(c(f"    • {fname}", "dim"))
        if len(meta["files"]) > 6:
            print(c(f"    … and {len(meta['files']) - 6} more", "dim"))
    return meta


def stage_signals(meta: dict[str, Any]) -> Any:
    banner("Stage 2 / 4 — Extract security signals",
           "Pattern-match the source for things attackers care about")
    teach(
        "What's a 'signal'",
        "A signal is a small, machine-checkable fact: this file declares "
        "an HTTP endpoint, that file contains an AWS key, this Dockerfile "
        "runs as root, etc. Each signal is cheap and noisy on its own — "
        "the value comes from combining many of them in a graph.",
    )
    teach(
        "STRIDE in one sentence",
        "Threats fall into 6 categories: Spoofing, Tampering, Repudiation, "
        "Information disclosure, Denial of service, Elevation of privilege. "
        "Each signal type maps to one or more STRIDE letters — that's how a "
        "raw 'endpoint with /admin' becomes a threat hypothesis.",
    )
    pause("Press Enter to extract signals")
    from repo_to_tasks import extract_signals
    sig = extract_signals(meta)
    ok(f"Languages: {dict(list(sig.languages.items())[:4])}")
    ok(f"Dependencies declared: {len(sig.dependencies)}")
    ok(f"Risky deps flagged:   {len(sig.risky_deps)}")
    for d, why in sig.risky_deps[:5]:
        print(c(f"    • {d}  —  {why}", "dim"))
    ok(f"HTTP endpoints found: {len(sig.endpoints)}")
    for f, m, p in sig.endpoints[:6]:
        print(c(f"    • {m:<6} {p}   ({f})", "dim"))
    if len(sig.endpoints) > 6:
        print(c(f"    … and {len(sig.endpoints) - 6} more", "dim"))
    ok(f"Secrets found:        {len(sig.secrets)}")
    for f, kind in sig.secrets[:5]:
        print(c(f"    • {kind}  in  {f}", "dim"))
    ok(f"Dockerfile flags:     {sig.dockerfile_flags or '(none)'}")
    ok(f"Recent commit churn:  {sig.recent_commits}")
    ok(f"Looks internet-facing? {sig.exposed_to_internet}")
    return sig


def stage_graph(meta: dict[str, Any], sig: Any, out_dir: Path) -> Path:
    banner("Stage 3 / 4 — Build the knowledge graph",
           "Turn flat signals into a connected model of the system")
    teach(
        "Why a graph",
        "A flat list of findings can't tell you 'this SSRF matters because "
        "the vulnerable endpoint is internet-facing AND fetches a URL "
        "controlled by user input AND lives in a service that handles "
        "money'. A graph can — because the relationships are first-class. "
        "We use the same RDF-shaped ontology the production system uses: "
        "System → contains → Service → exposes → Endpoint, and "
        "Service → evidenced_by → Finding.",
    )
    pause("Press Enter to build the graph")
    from repo_to_tasks import build_graph
    graph = build_graph(meta, sig)
    out_dir.mkdir(parents=True, exist_ok=True)
    gpath = out_dir / "graph.json"
    gpath.write_text(json.dumps(graph, indent=2))
    from collections import Counter
    nt = Counter(n["type"].split("#")[1] for n in graph["nodes"])
    et = Counter(e["p"].split("#")[1] for e in graph["edges"])
    ok(f"Wrote {gpath}")
    ok(f"Nodes ({sum(nt.values())}): "
       + ", ".join(f"{k}={v}" for k, v in nt.most_common()))
    ok(f"Edges ({sum(et.values())}): "
       + ", ".join(f"{k}={v}" for k, v in et.most_common()))
    return gpath


def stage_tasks(meta: dict[str, Any], sig: Any, out_dir: Path) -> Path:
    banner("Stage 4 / 4 — Rank pentest tasks",
           "What should be attacked first, and why")
    teach(
        "How the score is built",
        "Every threat gets a priority from 6 signals: severity, exposure, "
        "exploitability, control gap, code churn, and runtime alerts. "
        "Weights: 30/20/20/15/10/5. The output is a ranked task list — "
        "each task names a target, a STRIDE category, an objective written "
        "for the AI pentester, and which tools it should reach for.",
    )
    pause("Press Enter to score & rank")
    from repo_to_tasks import score_threats
    tasks = score_threats(meta, sig)
    out_dir.mkdir(parents=True, exist_ok=True)
    tpath = out_dir / "tasks.json"
    tpath.write_text(json.dumps(tasks, indent=2))
    spath = out_dir / "signals.json"
    from dataclasses import asdict
    spath.write_text(json.dumps(asdict(sig), indent=2))
    ok(f"Wrote {tpath}  ({len(tasks)} tasks)")
    if not tasks:
        warn("Zero tasks ranked. Try a repo with route handlers in obvious "
             "paths (e.g. /routes, /controllers, /api, main.py).")
        return tpath
    print()
    print(c("Top tasks (highest priority first):", "bold"))
    print()
    print(c(f"  {'score':>5}  {'sev':<8} {'S':<2} {'title':<50} target", "dim"))
    for t in tasks[:10]:
        tgt = t["target"].get("endpoint") or t["target"].get("repo")
        sev_color = {"critical": "red", "high": "red",
                     "medium": "yellow", "low": "green"}.get(t["severity"], "reset")
        prio = f"{t['priority']:>5.2f}"
        sev = f"{t['severity']:<8}"
        title = t['title'][:50].ljust(50)
        print(f"  {c(prio, 'bold')}  {c(sev, sev_color)} {t['stride']:<2} {title} {c(tgt, 'cyan')}")
    return tpath


def stage_handoff(tpath: Path) -> None:
    banner("Where this goes next",
           "Hand-off into the full TrustGraph stack")
    teach(
        "The full loop",
        "In the production stack, this tasks.json is enqueued to the CAI "
        "agent (apps/worker/.../pentest.py). CAI then *autonomously* attacks "
        "each target: it picks tools, makes HTTP probes, reads responses, "
        "decides next moves, and writes evidence back into the graph. The "
        "next planning cycle is then smarter, because the graph now "
        "contains real exploit evidence.",
    )
    print()
    print(c("To execute this task list against the live Juice Shop:", "bold"))
    print(c("  1.  cd ../sandbox/juice-shop  &&  make demo", "dim"))
    print(c("  2.  CAI agent reads tasks.json and attacks http://localhost:3000", "dim"))
    print(c("  3.  Evidence is written back into trustgraph-ai", "dim"))
    print()
    info(f"Your task file: {tpath}")
    info(f"Inspect it with:  cat {tpath}  |  jq '.[0]'")


# ---------- compare runs ------------------------------------------------

def compare_runs() -> None:
    banner("Compare two runs",
           "Pick two folders under prototype/runs/ and see what changed")
    runs_root = Path(__file__).resolve().parent / "runs"
    if not runs_root.exists():
        warn("No runs yet. Do at least 2 guided demos first.")
        return
    all_runs = sorted([p for p in runs_root.rglob("tasks.json")])
    if len(all_runs) < 2:
        warn(f"Need ≥ 2 runs. Found {len(all_runs)}.")
        return
    opts = [(str(p.parent), str(p.parent.relative_to(runs_root))) for p in all_runs]
    a_key = menu("Pick first run (A):", opts, 0)
    b_key = menu("Pick second run (B):", opts, len(opts) - 1)
    a = json.loads((Path(a_key) / "tasks.json").read_text())
    b = json.loads((Path(b_key) / "tasks.json").read_text())
    print()
    print(c(f"A: {a_key}  →  {len(a)} tasks", "cyan"))
    print(c(f"B: {b_key}  →  {len(b)} tasks", "mag"))
    print()
    titles_a = {t["task_id"]: t for t in a}
    titles_b = {t["task_id"]: t for t in b}
    only_a = set(titles_a) - set(titles_b)
    only_b = set(titles_b) - set(titles_a)
    common = set(titles_a) & set(titles_b)
    print(c(f"Only in A: {len(only_a)}", "cyan"))
    for tid in list(only_a)[:8]:
        print(c(f"  - {tid}", "dim"))
    print(c(f"Only in B: {len(only_b)}", "mag"))
    for tid in list(only_b)[:8]:
        print(c(f"  + {tid}", "dim"))
    print(c(f"In both:   {len(common)}  (priority diffs follow)", "bold"))
    for tid in list(common)[:8]:
        pa = titles_a[tid]["priority"]
        pb = titles_b[tid]["priority"]
        if abs(pa - pb) < 0.01:
            continue
        arrow = "▲" if pb > pa else "▼"
        print(f"    {arrow}  {tid}   A={pa:.2f}  B={pb:.2f}")
    teach(
        "Why the same threat can score differently",
        "Even for an identical threat shape, the 6 signals differ per repo: "
        "more endpoints raises exploitability; more recent commits raises "
        "churn; a Dockerfile that runs as root raises control_gap; secrets "
        "in the repo push severity to critical. That's why two repos with "
        "the same surface still produce different priorities.",
    )


# ---------- main --------------------------------------------------------

def main_menu() -> str:
    return menu(
        "What do you want to do?",
        [
            ("learn",   "Run the guided demo (recommended for first-timers)"),
            ("compare", "Compare two previous runs side-by-side"),
            ("quit",    "Quit"),
        ],
        default_idx=0,
    )


def guided_run() -> None:
    repo = pick_repo()
    meta = stage_fetch(repo)
    inspect_loop({"raw repo info": _write_temp(meta["repo"], "repo")})

    sig = stage_signals(meta)
    from dataclasses import asdict
    inspect_loop({"signals.json (raw)": _write_temp(asdict(sig), "signals_preview")})

    # From here on, write into the per-run folder
    import datetime
    owner, name = repo.replace("https://github.com/", "").rstrip("/").split("/")[:2]
    slug = f"{owner}_{name}".replace("/", "_")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(__file__).resolve().parent / "runs" / slug / stamp

    gpath = stage_graph(meta, sig, out_dir)
    inspect_loop({"graph.json": gpath})

    tpath = stage_tasks(meta, sig, out_dir)
    inspect_loop({"tasks.json": tpath, "graph.json": gpath})

    stage_handoff(tpath)
    print()
    ok(f"Outputs saved to: {out_dir}")
    print(c("Tip: run again with a different repo, then choose 'compare' "
            "on the main menu to diff the two.", "dim"))


_TEMP_DIR = Path("/tmp/tgs_demo_temp")


def _write_temp(obj: Any, name: str) -> Path:
    _TEMP_DIR.mkdir(parents=True, exist_ok=True)
    p = _TEMP_DIR / f"{name}.json"
    p.write_text(json.dumps(obj, indent=2, default=str))
    return p


def preflight() -> None:
    """Warn about GitHub auth before the user wastes a demo run."""
    # Accept any of the common GitHub token env vars
    token_envs = ("GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN")
    detected = next((v for v in token_envs if os.environ.get(v)), None)
    has_gh = shutil.which("gh") is not None
    if detected:
        ok(f"{detected} detected — you have 5000 req/hr.")
        return
    if has_gh:
        # Check `gh auth status` succeeds
        try:
            r = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                ok("`gh` CLI is authenticated — you have 5000 req/hr.")
                return
        except Exception:
            pass
    warn("No GitHub auth detected. Unauthenticated requests are capped at "
         "60/hr and this demo will fail on busy networks.")
    print(c("   Fix in one of two ways before continuing:", "dim"))
    print(c("     1)  export GITHUB_TOKEN=<a public_repo PAT>", "dim"))
    print(c("     2)  gh auth login   (one-time, then re-run)", "dim"))
    cont = ask("Continue anyway? (y/N)", default="n")
    if cont.lower() not in {"y", "yes"}:
        print(c("Exiting. Set up auth and come back.", "yellow"))
        sys.exit(0)


def main() -> None:
    banner("TrustGraph Security — Guided demo",
           "GitHub repo  →  signals  →  graph  →  ranked pentest tasks")
    print(c(
        "This walks you through every stage. At any prompt:\n"
        "  • Enter           continue\n"
        "  • q + Enter       quit\n"
        "  • a number        pick from the menu\n"
        "No security background needed — each stage starts with a short "
        "explanation of the concept.", "dim"))
    preflight()
    while True:
        choice = main_menu()
        if choice == "quit":
            return
        if choice == "learn":
            try:
                guided_run()
            except KeyboardInterrupt:
                print()
                warn("Interrupted. Back to main menu.")
            except Exception as e:
                warn(f"Something failed: {e}")
                import traceback; traceback.print_exc()
        elif choice == "compare":
            compare_runs()
        print()
        again = ask("Run again? (y/N)", default="y")
        if again.lower() not in {"y", "yes"}:
            print(c("\nThanks for trying TrustGraph Security. Have a great hackathon.", "green"))
            return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
