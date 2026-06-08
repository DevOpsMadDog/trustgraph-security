"""
TrustGraph Security — Standalone prototype
==========================================

Pipeline:  GitHub repo URL  ->  metadata  ->  graph JSON  ->  ranked pentest tasks

This is a self-contained mini-version of what the full stack does in
production. It runs with just `httpx` (and optionally a `GITHUB_TOKEN` env
var to avoid rate limits) — no Docker, no Cassandra, no LLM key required.

It demonstrates the core loop:

    1. Pull repo metadata + a handful of files from the GitHub REST API.
    2. Extract security-relevant signals (langs, deps, endpoints, secrets,
       Docker flags, recent churn).
    3. Build an RDF-shaped graph JSON (nodes + edges) using the same
       ontology the production system uses (System, Service, Endpoint,
       Threat, Control, Finding, Commit, ...).
    4. Map signals to STRIDE threats, score them with the same 6 signals
       the production planner uses, and emit ranked pentest tasks the
       CAI agent could pick up next.

Usage:
    python repo_to_tasks.py https://github.com/OWASP/NodeGoat
    GITHUB_TOKEN=ghp_xxx python repo_to_tasks.py owner/repo
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import httpx


# ---------- ontology (subset of production schema.py) -------------------

TGS = "https://trustgraph.security/ontology#"
TGSE = "https://trustgraph.security/entity/"


def iri(local: str) -> str:
    return f"{TGSE}{local}"


def prop(name: str) -> str:
    return f"{TGS}{name}"


# ---------- GitHub fetch ------------------------------------------------

GH_API = "https://api.github.com"


def _headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json",
         "User-Agent": "trustgraph-security-prototype"}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _gh_available() -> bool:
    return shutil.which("gh") is not None


def _gh_api(path: str) -> Any:
    """Call GitHub via the `gh` CLI when available (uses ambient auth)."""
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"gh api {path} failed")
    return json.loads(r.stdout) if r.stdout.strip() else {}


def _parse_repo(url_or_slug: str) -> tuple[str, str]:
    s = url_or_slug.strip().rstrip("/")
    s = re.sub(r"^https?://github\.com/", "", s)
    s = re.sub(r"\.git$", "", s)
    parts = s.split("/")
    if len(parts) < 2:
        raise ValueError(f"Not a repo: {url_or_slug}")
    return parts[0], parts[1]


# High-signal manifest filenames
MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml",
    "Dockerfile", "docker-compose.yml", ".env.example",
    "go.mod", "Cargo.toml", "pom.xml",
}

# Source files likely to contain route handlers — pulled by extension
SOURCE_EXTS = (".py", ".js", ".ts", ".tsx", ".java", ".go", ".rb")
# Path hints that strongly suggest route/controller files
ROUTE_HINTS = ("route", "router", "controller", "handler", "api", "endpoint",
               "views", "main.py", "app.py", "server")
MAX_SOURCE_FILES = 25
MAX_FILE_BYTES = 80_000


class GitHubRateLimitError(RuntimeError):
    """Raised when the GitHub API rate-limits us and no token is configured."""


_RL_SIGNALS = ("rate limit", "api rate limit exceeded", "abuse detection",
               "secondary rate limit", "please wait a few minutes")


def _check_gh_payload(payload: Any, path: str) -> Any:
    """Detect rate-limit / error envelopes and fail loudly with a helpful hint."""
    if isinstance(payload, dict):
        msg = str(payload.get("message", "")).lower()
        if any(s in msg for s in _RL_SIGNALS):
            raise GitHubRateLimitError(
                f"GitHub API rate-limited on /{path}: {payload.get('message')}\n"
                "  Fix: export GITHUB_TOKEN=<a personal-access-token with public_repo scope>\n"
                "        (or install `gh` and run `gh auth login` once).\n"
                "  Token boosts the limit from 60/hr to 5000/hr."
            )
        if msg in {"not found", "bad credentials"}:
            raise RuntimeError(f"GitHub API error on /{path}: {payload.get('message')}")
    return payload


def _get(path: str, client: httpx.Client | None) -> Any:
    """Try `gh` first (auth, no rate-limit pain), then fall back to httpx."""
    if _gh_available():
        try:
            return _check_gh_payload(_gh_api(path.lstrip("/")), path)
        except GitHubRateLimitError:
            raise
        except Exception:
            pass
    assert client is not None
    r = client.get(f"{GH_API}/{path.lstrip('/')}")
    # Surface HTTP-level errors cleanly
    if r.status_code in (403, 429) and any(s in r.text.lower() for s in _RL_SIGNALS):
        raise GitHubRateLimitError(
            f"GitHub API rate-limited (HTTP {r.status_code}) on /{path}.\n"
            "  Fix: export GITHUB_TOKEN=<a personal-access-token with public_repo scope>\n"
            "        (or install `gh` and run `gh auth login` once).\n"
            "  Token boosts the limit from 60/hr to 5000/hr."
        )
    if r.status_code == 404:
        raise RuntimeError(f"Repo or path not found: /{path}")
    return _check_gh_payload(r.json(), path)


def fetch_repo_metadata(owner: str, repo: str) -> dict[str, Any]:
    """Pull repo info, languages, recent commits, manifests + a few route files."""
    client = httpx.Client(headers=_headers(), timeout=20)
    try:
        repo_info = _get(f"repos/{owner}/{repo}", client)
        if not isinstance(repo_info, dict) or repo_info.get("message") == "Not Found":
            raise RuntimeError(f"Repo not found or private: {owner}/{repo}")

        languages = _get(f"repos/{owner}/{repo}/languages", client) or {}
        commits = _get(f"repos/{owner}/{repo}/commits?per_page=30", client)
        if not isinstance(commits, list):
            commits = []
        try:
            default_branch = repo_info.get("default_branch", "main")
            tree = _get(
                f"repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1",
                client)
        except Exception:
            tree = {"tree": []}

        files: dict[str, str] = {}
        tree_nodes = (tree.get("tree") or []) if isinstance(tree, dict) else []

        # 1) Manifests first
        for node in tree_nodes[:4000]:
            name = node.get("path", "")
            base = name.rsplit("/", 1)[-1]
            if base in MANIFEST_NAMES:
                _maybe_load_file(client, owner, repo, name, files)

        # 2) Likely route/controller source files (extension + path hint)
        candidates = [
            n.get("path", "") for n in tree_nodes
            if n.get("type") == "blob"
            and n.get("path", "").lower().endswith(SOURCE_EXTS)
            and any(h in n.get("path", "").lower() for h in ROUTE_HINTS)
            and (n.get("size") or 0) <= MAX_FILE_BYTES
        ]
        # Prefer shallower paths (typically `app/main.py` over deep test files)
        candidates.sort(key=lambda p: (p.count("/"), len(p)))
        for name in candidates[:MAX_SOURCE_FILES]:
            _maybe_load_file(client, owner, repo, name, files)

        return {
            "repo": repo_info,
            "languages": languages,
            "commits": commits,
            "files": files,
        }
    finally:
        client.close()


def _maybe_load_file(client: httpx.Client, owner: str, repo: str,
                     path: str, files: dict[str, str]) -> None:
    if path in files:
        return
    try:
        blob = _get(f"repos/{owner}/{repo}/contents/{path}", client)
        if isinstance(blob, dict) and blob.get("content"):
            files[path] = base64.b64decode(
                blob["content"]).decode("utf-8", "ignore")
    except Exception:
        pass


# ---------- signal extraction ------------------------------------------

ENDPOINT_PATTERNS = [
    # FastAPI / Flask / Express style
    re.compile(r"""@(?:app|router)\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""(?:app|router)\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']""", re.I),
    # Spring
    re.compile(r"""@(?:Get|Post|Put|Delete|Patch)Mapping\(\s*["']([^"']+)["']""", re.I),
]

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token":   re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    "private_key":    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "slack_token":    re.compile(r"xox[abpr]-[A-Za-z0-9-]{10,}"),
    "generic_secret": re.compile(
        r"""(?i)(?:secret|password|api[_-]?key)\s*[:=]\s*["']([^"']{8,})["']"""),
}

DANGEROUS_DEPS = {
    "lodash": "Prototype pollution history; pin >=4.17.21",
    "request": "Deprecated, unpatched",
    "pyyaml": "Use safe_load only",
    "pickle": "Unsafe deserialization",
    "express": "Check version for CVE-2024-29041",
    "django": "Check version for active CVEs",
    "flask":  "Check version; default cookie config is weak",
    "axios":  "SSRF history pre-1.7",
}


@dataclass
class Signals:
    languages: dict[str, int] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    risky_deps: list[tuple[str, str]] = field(default_factory=list)
    endpoints: list[tuple[str, str, str]] = field(default_factory=list)  # (file, method, path)
    secrets: list[tuple[str, str]] = field(default_factory=list)         # (file, kind)
    dockerfile_flags: list[str] = field(default_factory=list)
    recent_commits: int = 0
    has_dockerfile: bool = False
    exposed_to_internet: bool = False  # heuristic


def _parse_deps(files: dict[str, str]) -> list[str]:
    deps: list[str] = []
    for name, content in files.items():
        base = Path(name).name
        if base == "package.json":
            try:
                j = json.loads(content)
                deps += list((j.get("dependencies") or {}).keys())
                deps += list((j.get("devDependencies") or {}).keys())
            except Exception:
                pass
        elif base == "requirements.txt":
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    deps.append(re.split(r"[<>=!~ ]", line, 1)[0].strip())
        elif base == "pyproject.toml":
            for line in content.splitlines():
                m = re.match(r"""\s*["']?([A-Za-z0-9_.-]+)["']?\s*=\s*["']""", line)
                if m and "tool" not in line.lower():
                    deps.append(m.group(1))
    return [d for d in deps if d]


def _check_dockerfile(content: str) -> list[str]:
    flags: list[str] = []
    if re.search(r"^\s*USER\s+root", content, re.M | re.I) or \
            not re.search(r"^\s*USER\s+", content, re.M | re.I):
        flags.append("runs_as_root")
    if re.search(r"ADD\s+http", content, re.I):
        flags.append("ADD_from_url")
    if re.search(r":latest\b", content):
        flags.append("uses_latest_tag")
    if re.search(r"--no-check-certificate|--insecure", content):
        flags.append("disables_tls_verify")
    if "curl " in content and "| sh" in content:
        flags.append("curl_pipe_sh")
    return flags


def extract_signals(meta: dict[str, Any]) -> Signals:
    s = Signals()
    s.languages = meta.get("languages") or {}
    s.recent_commits = len(meta.get("commits") or [])
    deps = _parse_deps(meta.get("files") or {})
    s.dependencies = sorted(set(deps))
    for d in s.dependencies:
        if d.lower() in DANGEROUS_DEPS:
            s.risky_deps.append((d, DANGEROUS_DEPS[d.lower()]))

    for fname, content in (meta.get("files") or {}).items():
        for pat in ENDPOINT_PATTERNS:
            for m in pat.finditer(content):
                groups = m.groups()
                if len(groups) >= 2:
                    method, path = groups[0].upper(), groups[1]
                else:
                    method, path = "GET", groups[0]
                # Dedup + ignore obvious non-paths
                if path.startswith("/") and (fname, method, path) not in s.endpoints:
                    s.endpoints.append((fname, method, path))
        for kind, pat in SECRET_PATTERNS.items():
            if pat.search(content):
                s.secrets.append((fname, kind))
        if Path(fname).name == "Dockerfile":
            s.has_dockerfile = True
            s.dockerfile_flags += _check_dockerfile(content)

    repo = meta.get("repo") or {}
    # Heuristic: public repo + has Dockerfile or compose -> likely internet-facing service
    s.exposed_to_internet = (
        not repo.get("private", True)
        and (s.has_dockerfile or any("docker-compose" in f for f in (meta.get("files") or {})))
    )
    return s


# ---------- graph build -------------------------------------------------

def build_graph(meta: dict[str, Any], sig: Signals) -> dict[str, Any]:
    repo = meta.get("repo") or {}
    repo_slug = repo.get("full_name", "unknown/unknown")
    safe = repo_slug.replace("/", "_")
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def add_node(type_: str, id_: str, **props: Any) -> str:
        n = {"id": iri(id_), "type": prop(type_), "props": props}
        nodes.append(n)
        return n["id"]

    def add_edge(s_id: str, predicate: str, o_id: str) -> None:
        edges.append({"s": s_id, "p": prop(predicate), "o": o_id})

    sys_id = add_node("System", f"system-{safe}",
                      name=repo_slug,
                      description=repo.get("description") or "",
                      url=repo.get("html_url"))
    svc_id = add_node("Service", f"service-{safe}",
                      name=repo.get("name", "service"),
                      language=max(sig.languages, key=sig.languages.get) if sig.languages else "unknown",
                      exposed_to_internet=sig.exposed_to_internet)
    add_edge(sys_id, "contains", svc_id)

    # Endpoints
    for i, (fname, method, path) in enumerate(sig.endpoints[:50]):
        eid = add_node("Endpoint", f"endpoint-{safe}-{i}",
                       method=method, path=path, defined_in=fname)
        add_edge(svc_id, "exposes", eid)

    # Commits (recent churn signal)
    for i, c in enumerate((meta.get("commits") or [])[:10]):
        cid = add_node("Commit", f"commit-{safe}-{i}",
                       sha=c.get("sha", "")[:12],
                       message=(c.get("commit") or {}).get("message", "")[:160],
                       author=((c.get("commit") or {}).get("author") or {}).get("name", ""))
        add_edge(svc_id, "changed_by", cid)

    # Findings from static signals
    finding_ids: list[str] = []
    for fname, kind in sig.secrets:
        fid = add_node("Finding", f"finding-secret-{safe}-{len(finding_ids)}",
                       title=f"Possible {kind} in {fname}",
                       severity="high", source="prototype-secret-scan",
                       file=fname)
        add_edge(svc_id, "evidenced_by", fid)
        finding_ids.append(fid)
    for dep, note in sig.risky_deps:
        fid = add_node("Finding", f"finding-dep-{safe}-{dep}",
                       title=f"Risky dependency: {dep}",
                       severity="medium", source="prototype-dep-scan",
                       note=note)
        add_edge(svc_id, "evidenced_by", fid)
        finding_ids.append(fid)
    for flag in sig.dockerfile_flags:
        fid = add_node("Finding", f"finding-docker-{safe}-{flag}",
                       title=f"Dockerfile issue: {flag}",
                       severity="medium", source="prototype-docker-scan")
        add_edge(svc_id, "evidenced_by", fid)
        finding_ids.append(fid)

    return {
        "ontology": {"namespace": TGS},
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "endpoints": len(sig.endpoints),
            "commits": sig.recent_commits,
            "findings": len(finding_ids),
            "risky_deps": len(sig.risky_deps),
            "secrets": len(sig.secrets),
        },
    }


# ---------- threats + scoring (same shape as production planner) -------

STRIDE_RULES = [
    # (predicate, threat-id, title, stride, severity, suggested_tools)
    (lambda sig, ep: ep[1] in {"POST", "PUT", "PATCH"} and "/login" in ep[2].lower(),
     "thr-bruteforce", "Login endpoint lacks visible rate limiting",
     "S", "high", ["ffuf", "hydra"]),
    (lambda sig, ep: "/admin" in ep[2].lower(),
     "thr-admin-authz", "Admin endpoint authorization bypass / IDOR",
     "E", "high", ["curl", "burp", "ffuf"]),
    (lambda sig, ep: "{id}" in ep[2] or "/users/" in ep[2].lower() or "user_id" in ep[2].lower(),
     "thr-idor", "Object-level authorization (IDOR) on parameterized route",
     "I", "high", ["curl", "ffuf"]),
    (lambda sig, ep: "/webhook" in ep[2].lower() or "/callback" in ep[2].lower()
                       or "/proxy" in ep[2].lower() or "/fetch" in ep[2].lower(),
     "thr-ssrf", "Potential SSRF via user-supplied URL",
     "I", "high", ["curl", "interactsh"]),
    (lambda sig, ep: any(k in ep[2].lower() for k in ("/search", "/query", "/filter")),
     "thr-sqli", "Possible injection on search/query endpoint",
     "T", "high", ["sqlmap"]),
    (lambda sig, ep: ep[1] == "POST" and any(k in ep[2].lower()
                       for k in ("/upload", "/file", "/import")),
     "thr-upload", "Unrestricted file upload",
     "T", "high", ["curl", "ffuf"]),
]

EXTRA_THREATS = [
    ("thr-secrets-in-repo", "Hard-coded credentials in repo",
     "I", "critical", ["gitleaks", "trufflehog"],
     lambda sig: bool(sig.secrets)),
    ("thr-supply-chain", "Risky / outdated dependencies",
     "T", "medium", ["trivy", "osv-scanner"],
     lambda sig: bool(sig.risky_deps)),
    ("thr-container-root", "Container runs as root",
     "E", "medium", ["trivy", "dockle"],
     lambda sig: "runs_as_root" in sig.dockerfile_flags),
    ("thr-tls-verify-off", "TLS verification disabled in build",
     "T", "high", ["curl"],
     lambda sig: "disables_tls_verify" in sig.dockerfile_flags),
    ("thr-curl-pipe-sh", "Untrusted curl-pipe-sh in build",
     "T", "high", ["trivy"],
     lambda sig: "curl_pipe_sh" in sig.dockerfile_flags),
]


SEVERITY_W = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}


def _score(severity: str, sig: Signals, controls: int = 0) -> dict[str, float]:
    """Same 6 signals as production planner.py."""
    sev = SEVERITY_W.get(severity, 0.4)
    exposure = 0.9 if sig.exposed_to_internet else 0.3
    # Exploitability: more endpoints + risky deps => easier surface
    exploitability = min(1.0, 0.2 + 0.05 * len(sig.endpoints) + 0.1 * len(sig.risky_deps))
    control_gap = max(0.0, 1.0 - 0.25 * controls)
    churn = min(1.0, sig.recent_commits / 30.0)
    runtime_alerts = 0.0  # not available from repo alone
    total = round(
        0.30 * sev +
        0.20 * exposure +
        0.20 * exploitability +
        0.15 * control_gap +
        0.10 * churn +
        0.05 * runtime_alerts, 3)
    return {
        "severity": sev, "exposure": exposure,
        "exploitability": round(exploitability, 3),
        "control_gap": round(control_gap, 3),
        "churn": round(churn, 3),
        "runtime_alerts": runtime_alerts,
        "total": total,
    }


def score_threats(meta: dict[str, Any], sig: Signals) -> list[dict[str, Any]]:
    repo = meta.get("repo") or {}
    repo_slug = repo.get("full_name", "unknown/unknown")
    tasks: list[dict[str, Any]] = []

    # Per-endpoint threats
    for fname, method, path in sig.endpoints:
        for predicate, tid, title, stride, sev, tools in STRIDE_RULES:
            if predicate(sig, (fname, method, path)):
                signals = _score(sev, sig)
                tasks.append({
                    "task_id": f"{tid}::{method}:{path}",
                    "threat_id": tid,
                    "title": title,
                    "stride": stride,
                    "severity": sev,
                    "target": {"repo": repo_slug,
                               "endpoint": f"{method} {path}",
                               "defined_in": fname},
                    "objective": (
                        f"Verify whether {title.lower()} is exploitable against "
                        f"{method} {path} in repo {repo_slug}. Produce a minimal "
                        f"reproducer and a one-line fix."),
                    "suggested_tools": tools,
                    "signals": signals,
                    "priority": signals["total"],
                })

    # Repo-level threats
    for tid, title, stride, sev, tools, predicate in EXTRA_THREATS:
        if predicate(sig):
            signals = _score(sev, sig)
            tasks.append({
                "task_id": f"{tid}::{repo_slug}",
                "threat_id": tid,
                "title": title,
                "stride": stride,
                "severity": sev,
                "target": {"repo": repo_slug},
                "objective": f"Confirm and remediate: {title} in {repo_slug}.",
                "suggested_tools": tools,
                "signals": signals,
                "priority": signals["total"],
            })

    tasks.sort(key=lambda t: t["priority"], reverse=True)
    return tasks


# ---------- main --------------------------------------------------------

def run(repo_url: str, out_dir: Path | None = None) -> Path:
    owner, repo = _parse_repo(repo_url)
    if out_dir is None:
        import datetime
        slug = f"{owner}_{repo}".replace("/", "_")
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = Path(__file__).resolve().parent / "runs" / slug / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[1/4] Fetching GitHub metadata for {owner}/{repo} …")
    meta = fetch_repo_metadata(owner, repo)

    print("[2/4] Extracting signals …")
    sig = extract_signals(meta)
    print(f"      langs={list(sig.languages)[:3]} "
          f"endpoints={len(sig.endpoints)} "
          f"deps={len(sig.dependencies)} "
          f"risky_deps={len(sig.risky_deps)} "
          f"secrets={len(sig.secrets)} "
          f"dockerfile_flags={sig.dockerfile_flags}")

    print("[3/4] Building graph JSON …")
    graph = build_graph(meta, sig)
    (out_dir / "graph.json").write_text(json.dumps(graph, indent=2))
    print(f"      nodes={len(graph['nodes'])} edges={len(graph['edges'])}")

    print("[4/4] Scoring threats and generating pentest tasks …")
    tasks = score_threats(meta, sig)
    (out_dir / "tasks.json").write_text(json.dumps(tasks, indent=2))
    (out_dir / "signals.json").write_text(json.dumps(asdict(sig), indent=2))

    print()
    print(f"Wrote {out_dir/'graph.json'}")
    print(f"Wrote {out_dir/'tasks.json'}  ({len(tasks)} tasks)")
    print(f"Wrote {out_dir/'signals.json'}")
    print()
    print("Top 5 pentest tasks:")
    for t in tasks[:5]:
        tgt = t["target"].get("endpoint") or t["target"].get("repo")
        print(f"  [{t['priority']:.2f}] {t['severity']:<8} {t['stride']}  "
              f"{t['title']}  ->  {tgt}")
    return out_dir


USAGE = """\
Usage: python repo_to_tasks.py <owner/repo or full GitHub URL> [out_dir]

Reads a public GitHub repo, builds a security knowledge graph, and emits a
ranked list of pentest tasks (graph.json, tasks.json, signals.json).

Examples:
    python repo_to_tasks.py juice-shop/juice-shop
    python repo_to_tasks.py https://github.com/fastapi/full-stack-fastapi-template /tmp/out

Environment:
    GITHUB_TOKEN   Personal access token (public_repo scope). Strongly recommended
                   — without it you get 60 req/hr and the script will fail loudly.
                   If `gh` CLI is installed and authenticated, that is used instead.

Flags:
    -h, --help     Show this message and exit.
"""

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        sys.exit(0 if args else 2)
    out = Path(args[1]).resolve() if len(args) > 1 else None
    try:
        final_dir = run(args[0], out)
    except GitHubRateLimitError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(3)
    except ValueError as e:
        print(f"\n❌ Invalid argument: {e}", file=sys.stderr)
        sys.exit(2)
    except RuntimeError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(4)
    print(f"\nOutputs in: {final_dir}")
