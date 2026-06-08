/**
 * TrustGraph Security — sandbox UI
 * Single-file React app sized for hackathon stakeholders. Five views,
 * an explainer panel on every screen, and a one-click AI pentest flow.
 */
import { useEffect, useMemo, useState } from "react";
import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Router, Route, Switch, useLocation, Link } from "wouter";
import { useHashLocation } from "wouter/use-hash-location";
import { api, setToken, sevClass, statusClass, type PentestTask, type Triple } from "@/lib/api";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Toaster } from "@/components/ui/toaster";
import { useToast } from "@/hooks/use-toast";
import {
  ShieldCheck, Network, FileSearch, Activity, Crosshair, Upload,
  HelpCircle, Play, LogOut, ChevronRight, Cpu, Database, AlertTriangle,
} from "lucide-react";

const qc = new QueryClient({
  defaultOptions: { queries: { staleTime: 10_000, refetchOnWindowFocus: false } },
});

// ─────────────────────────────────────────────────────────────
// Auth shell
// ─────────────────────────────────────────────────────────────
function useAuth() {
  const [user, setUser] = useState<{ email: string; roles: string[] } | null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => { setReady(true); }, []);
  const login = async (email: string, password: string) => {
    const r = await api.login(email, password);
    if (!r.access_token) throw new Error("invalid credentials");
    setToken(r.access_token);
    setUser(r.user);
  };
  const logout = () => { setToken(null); setUser(null); };
  return { user, ready, login, logout };
}

function LoginScreen({ onLogin }: { onLogin: (e: string, p: string) => Promise<void> }) {
  const [email, setEmail] = useState("demo@trustgraph.local");
  const [pw, setPw] = useState("demo");
  const [err, setErr] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try { await onLogin(email, pw); }
    catch (x: any) { setErr(x.message || "login failed"); }
  };
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100">
      <Card className="p-8 w-[400px] bg-slate-900 border-slate-800">
        <div className="flex items-center gap-3 mb-6">
          <ShieldCheck className="text-cyan-400" />
          <div>
            <div className="font-semibold text-lg">TrustGraph Security</div>
            <div className="text-xs text-slate-400">Hackathon sandbox</div>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-3">
          <Input value={email} onChange={e => setEmail(e.target.value)} placeholder="email"
                 className="bg-slate-800 border-slate-700" />
          <Input type="password" value={pw} onChange={e => setPw(e.target.value)} placeholder="password"
                 className="bg-slate-800 border-slate-700" />
          <Button type="submit" className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950">
            Sign in
          </Button>
          {err && <div className="text-rose-400 text-xs">{err}</div>}
          <div className="text-xs text-slate-500 pt-2 border-t border-slate-800">
            Demo creds prefilled. Press Sign in.
          </div>
        </form>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Explainer panel (the killer feature for non-security users)
// ─────────────────────────────────────────────────────────────
const EXPLAINERS: Record<string, { title: string; body: string[] }> = {
  overview: {
    title: "Overview — the executive view",
    body: [
      "One number per category. Critical threats, proven exploitable, services covered.",
      "The 'Top priorities' list comes from the planner, which scores every threat 0-99.",
      "Click any priority to jump to its full Pentest task.",
    ],
  },
  pentest: {
    title: "Pentest — the planner queue",
    body: [
      "Every open threat is scored on six signals: exposure, risk, control gap, recent change, runtime signal, criticality.",
      "Top of the list = most worth your attention right now.",
      "Click Execute and the CAI AI agent will actually try to exploit it inside the sandbox network.",
      "The agent has curl, sqlmap, ffuf, nuclei, ZAP, and httpx available.",
    ],
  },
  graph: {
    title: "Graph — your living system map",
    body: [
      "Every entity (services, databases, threats, code changes, findings) is a node.",
      "Every relationship is an edge. The graph is the source of truth shared by all five views.",
      "Filter by node type with the chips above the canvas.",
    ],
  },
  appsec: {
    title: "AppSec — what code and supply chain look like",
    body: [
      "Findings from Semgrep, Trivy and Gitleaks land here, grouped by service.",
      "Each finding links to the line of code or the CVE that flagged it.",
      "Recent PRs and commits per service tell you where activity is.",
    ],
  },
  soc: {
    title: "SOC — what's happening right now",
    body: [
      "Runtime alerts from your SIEM, IAM and network sensors arrive here.",
      "Each alert is attached to the service it touches and the threats targeting that service.",
      "An alert on a service with no controls is your highest-urgency item.",
    ],
  },
  architect: {
    title: "Architect — the design view",
    body: [
      "Services grouped by trust boundary, with the data stores they touch.",
      "Services crossing a boundary are highlighted — most breaches happen at boundaries.",
      "Use this view before approving a design change.",
    ],
  },
  ingest: {
    title: "Ingest — feed the graph",
    body: [
      "POST a threat-model JSON, or trigger a feed pull from local files / S3 / a prior session.",
      "Sample threat model below — copy, edit, repost to see the graph update.",
    ],
  },
};

function Explainer({ id }: { id: keyof typeof EXPLAINERS }) {
  const ex = EXPLAINERS[id];
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-4">
      <button
        onClick={() => setOpen(o => !o)}
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/15 text-xs"
      >
        <HelpCircle className="w-3.5 h-3.5" />
        {open ? "Hide explainer" : "What am I looking at?"}
      </button>
      {open && (
        <Card className="mt-2 p-4 bg-slate-900/60 border-cyan-500/20">
          <div className="font-semibold text-cyan-300 mb-2">{ex.title}</div>
          <ul className="space-y-1 text-sm text-slate-300 list-disc ml-5">
            {ex.body.map((line, i) => <li key={i}>{line}</li>)}
          </ul>
        </Card>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Chrome
// ─────────────────────────────────────────────────────────────
const NAV = [
  { path: "/", label: "Overview",   icon: ShieldCheck, key: "overview"  as const },
  { path: "/graph",     label: "Trust Graph", icon: Network,    key: "graph"     as const },
  { path: "/architect", label: "Architect",   icon: Cpu,        key: "architect" as const },
  { path: "/appsec",    label: "AppSec",      icon: FileSearch, key: "appsec"    as const },
  { path: "/soc",       label: "SOC",         icon: Activity,   key: "soc"       as const },
  { path: "/pentest",   label: "Pentest",     icon: Crosshair,  key: "pentest"   as const },
  { path: "/ingest",    label: "Ingest",      icon: Upload,     key: "ingest"    as const },
];

function Sidebar({ onLogout, email }: { onLogout: () => void; email: string }) {
  const [loc] = useLocation();
  return (
    <aside className="w-60 bg-slate-950 border-r border-slate-800 flex flex-col">
      <div className="p-5 border-b border-slate-800 flex items-center gap-2">
        <ShieldCheck className="text-cyan-400 w-5 h-5" />
        <div>
          <div className="font-semibold text-sm">TrustGraph</div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500">Security · sandbox</div>
        </div>
      </div>
      <nav className="flex-1 py-2">
        {NAV.map(n => (
          <Link key={n.path} href={n.path}>
            <a className={`flex items-center gap-3 px-5 py-2 text-sm hover:bg-slate-900 ${loc === n.path ? "text-cyan-300 border-r-2 border-cyan-400 bg-slate-900/50" : "text-slate-400"}`}>
              <n.icon className="w-4 h-4" /> {n.label}
            </a>
          </Link>
        ))}
      </nav>
      <div className="p-4 border-t border-slate-800 text-xs text-slate-400">
        <div className="truncate">{email}</div>
        <button onClick={onLogout} className="mt-2 inline-flex items-center gap-1 hover:text-rose-400">
          <LogOut className="w-3 h-3" /> Sign out
        </button>
      </div>
    </aside>
  );
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────
function localId(iri: string) { return iri.split("/").pop() || iri; }
function predName(iri: string) { return iri.split("#").pop() || iri; }

function useTriples(params: Parameters<typeof api.graphQuery>[0]) {
  return useQuery({
    queryKey: ["graph", params],
    queryFn: () => api.graphQuery(params),
  });
}

// Group triples by subject -> { rdf:type, label, props, edges }
function indexTriples(triples: Triple[]) {
  const idx: Record<string, { type?: string; label?: string; props: Record<string, string>; edges: { p: string; o: string }[] }> = {};
  for (const t of triples) {
    const s = t.s.v;
    if (!idx[s]) idx[s] = { props: {}, edges: [] };
    const p = predName(t.p.v);
    if (p === "type") idx[s].type = localId(t.o.v);
    else if (p === "label") idx[s].label = t.o.v;
    else if (t.o.e) idx[s].edges.push({ p, o: t.o.v });
    else idx[s].props[p] = t.o.v;
  }
  return idx;
}

// ─────────────────────────────────────────────────────────────
// Overview
// ─────────────────────────────────────────────────────────────
function OverviewView() {
  const { data: tasks } = useQuery({ queryKey: ["tasks"], queryFn: api.listTasks });
  const { data: threats } = useTriples({
    predicate: "https://www.w3.org/1999/02/22-rdf-syntax-ns#type",
    obj: "https://trustgraph.security/ontology#Threat",
  });
  const { data: services } = useTriples({
    predicate: "https://www.w3.org/1999/02/22-rdf-syntax-ns#type",
    obj: "https://trustgraph.security/ontology#Service",
  });
  const { data: evidence } = useTriples({
    predicate: "https://www.w3.org/1999/02/22-rdf-syntax-ns#type",
    obj: "https://trustgraph.security/ontology#Evidence",
  });

  const top3 = (tasks ?? []).slice(0, 3);

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold">Overview</h1>
      <Explainer id="overview" />

      <div className="grid grid-cols-4 gap-4">
        <StatCard icon={<AlertTriangle />} label="Open threats" value={threats?.count ?? 0} accent="amber" />
        <StatCard icon={<Crosshair />} label="Pentest tasks" value={tasks?.length ?? 0} accent="cyan" />
        <StatCard icon={<ShieldCheck />} label="Evidence collected" value={evidence?.count ?? 0} accent="emerald" />
        <StatCard icon={<Database />} label="Services" value={services?.count ?? 0} accent="violet" />
      </div>

      <Card className="bg-slate-900/40 border-slate-800 p-5">
        <div className="font-semibold mb-3">Top priorities</div>
        {top3.length === 0 ? (
          <div className="text-sm text-slate-500">No tasks yet — run the planner from the Pentest view.</div>
        ) : (
          <div className="space-y-2">
            {top3.map(t => (
              <Link key={t.id} href="/pentest">
                <a className="flex items-center gap-3 p-3 bg-slate-900 rounded-md hover:bg-slate-800">
                  <div className="text-xl font-bold w-12 text-center text-cyan-300">{t.priority}</div>
                  <div className="flex-1">
                    <div className="font-medium text-sm">{t.title}</div>
                    <div className="text-xs text-slate-500">{t.stride} · {t.target_service}</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-500" />
                </a>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function StatCard({ icon, label, value, accent }: { icon: React.ReactNode; label: string; value: number; accent: string }) {
  const accents: Record<string, string> = {
    amber:   "text-amber-400 border-amber-500/20 bg-amber-500/5",
    cyan:    "text-cyan-400 border-cyan-500/20 bg-cyan-500/5",
    emerald: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
    violet:  "text-violet-400 border-violet-500/20 bg-violet-500/5",
  };
  return (
    <Card className={`p-4 border ${accents[accent]} border-slate-800`}>
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-slate-400">
        <span className="opacity-70">{icon}</span> {label}
      </div>
      <div className={`text-3xl font-semibold mt-2 ${accents[accent].split(" ")[0]}`}>{value}</div>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────
// Graph view (table-style, since deploys vary on canvas perf)
// ─────────────────────────────────────────────────────────────
function GraphView() {
  const { data } = useTriples({ limit: 2000 });
  const triples = data?.triples ?? [];
  const idx = useMemo(() => indexTriples(triples), [triples]);
  const nodes = Object.entries(idx).filter(([, v]) => v.type);
  const [filter, setFilter] = useState<string>("");
  const types = Array.from(new Set(nodes.map(([, v]) => v.type!))).sort();

  const filtered = filter ? nodes.filter(([, v]) => v.type === filter) : nodes;

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold">Trust Graph</h1>
      <Explainer id="graph" />
      <div className="flex flex-wrap gap-2">
        <button onClick={() => setFilter("")}
                className={`px-3 py-1 text-xs rounded-full border ${!filter ? "border-cyan-500 text-cyan-300" : "border-slate-700 text-slate-400"}`}>
          all ({nodes.length})
        </button>
        {types.map(t => {
          const count = nodes.filter(([, v]) => v.type === t).length;
          return (
            <button key={t} onClick={() => setFilter(t)}
                    className={`px-3 py-1 text-xs rounded-full border ${filter === t ? "border-cyan-500 text-cyan-300" : "border-slate-700 text-slate-400"}`}>
              {t} ({count})
            </button>
          );
        })}
      </div>
      <Card className="bg-slate-900/40 border-slate-800 divide-y divide-slate-800">
        {filtered.slice(0, 200).map(([iri, n]) => (
          <div key={iri} className="px-4 py-3 hover:bg-slate-900/50">
            <div className="flex items-baseline gap-2">
              <Badge variant="outline" className="text-[10px] border-slate-700 text-slate-400">{n.type}</Badge>
              <div className="font-medium text-sm">{n.label || localId(iri)}</div>
              <div className="text-[10px] text-slate-600 ml-auto">{localId(iri)}</div>
            </div>
            {Object.keys(n.props).length > 0 && (
              <div className="text-xs text-slate-500 mt-1 flex flex-wrap gap-x-4">
                {Object.entries(n.props).slice(0, 5).map(([k, v]) =>
                  <span key={k}><span className="text-slate-600">{k}</span>: {v}</span>)}
              </div>
            )}
            {n.edges.length > 0 && (
              <div className="text-xs text-slate-500 mt-1">
                <span className="text-slate-600">edges:</span>{" "}
                {n.edges.slice(0, 4).map((e, i) =>
                  <span key={i} className="mr-3"><span className="text-cyan-400">{e.p}</span> → {localId(e.o)}</span>
                )}
              </div>
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Architect / AppSec / SOC — type-filtered views
// ─────────────────────────────────────────────────────────────
function TypedListView({
  id, title, includeTypes,
}: { id: keyof typeof EXPLAINERS; title: string; includeTypes: string[] }) {
  const { data } = useTriples({ limit: 2000 });
  const idx = useMemo(() => indexTriples(data?.triples ?? []), [data]);
  const nodes = Object.entries(idx).filter(([, v]) => v.type && includeTypes.includes(v.type));

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold">{title}</h1>
      <Explainer id={id} />
      <div className="grid gap-3">
        {nodes.map(([iri, n]) => (
          <Card key={iri} className="bg-slate-900/40 border-slate-800 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Badge variant="outline" className="text-[10px] border-slate-700 text-slate-400">{n.type}</Badge>
              <div className="font-medium">{n.label || localId(iri)}</div>
              {n.props.severity && (
                <Badge className={`ml-auto ${sevClass(n.props.severity)} bg-transparent border`}>
                  {n.props.severity}
                </Badge>
              )}
              {n.props.status && (
                <Badge variant="outline" className={`${statusClass(n.props.status)}`}>{n.props.status}</Badge>
              )}
            </div>
            <div className="text-xs text-slate-500 grid grid-cols-2 gap-x-6 gap-y-1">
              {Object.entries(n.props).slice(0, 6).map(([k, v]) =>
                <div key={k}><span className="text-slate-600">{k}:</span> {v}</div>)}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Pentest view
// ─────────────────────────────────────────────────────────────
function PentestView() {
  const { data, refetch, isLoading } = useQuery({ queryKey: ["tasks"], queryFn: api.listTasks });
  const [expanded, setExpanded] = useState<string | null>(null);
  const { toast } = useToast();
  const qcl = useQueryClient();

  const plan = useMutation({
    mutationFn: () => api.plan(20),
    onSuccess: () => { qcl.invalidateQueries({ queryKey: ["tasks"] }); toast({ title: "Planner ran" }); },
  });
  const execute = useMutation({
    mutationFn: (id: string) => api.execute(id),
    onSuccess: (r) => toast({ title: "AI pentest dispatched", description: `job ${r.job_id}` }),
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold flex-1">Pentest</h1>
        <Button variant="outline" onClick={() => refetch()}>Refresh</Button>
        <Button onClick={() => plan.mutate()} disabled={plan.isPending}
                className="bg-cyan-500 text-slate-950 hover:bg-cyan-400">
          {plan.isPending ? "Planning…" : "Re-plan"}
        </Button>
      </div>
      <Explainer id="pentest" />

      <Card className="bg-slate-900/40 border-slate-800 divide-y divide-slate-800">
        {isLoading && <div className="p-6 text-slate-500">Loading tasks…</div>}
        {!isLoading && (data ?? []).length === 0 && (
          <div className="p-6 text-slate-500">No tasks yet. Click <em>Re-plan</em>.</div>
        )}
        {(data ?? []).map(t => (
          <div key={t.id}>
            <div onClick={() => setExpanded(e => e === t.id ? null : t.id)}
                 className="px-4 py-3 flex items-center gap-3 hover:bg-slate-900 cursor-pointer">
              <div className={`text-2xl font-bold w-12 text-center
                              ${t.priority >= 80 ? "text-rose-400" : t.priority >= 60 ? "text-amber-400" : "text-slate-400"}`}>
                {t.priority}
              </div>
              <div className="flex-1">
                <div className="font-medium text-sm">{t.title}</div>
                <div className="text-xs text-slate-500">
                  {t.stride} · {t.target_service} · <span className={statusClass(t.status)}>{t.status}</span>
                </div>
              </div>
              <Button size="sm" onClick={(e) => { e.stopPropagation(); execute.mutate(t.id); }}
                      className="bg-cyan-500 text-slate-950 hover:bg-cyan-400">
                <Play className="w-3 h-3 mr-1" /> Execute
              </Button>
            </div>
            {expanded === t.id && (
              <div className="px-6 pb-4 bg-slate-950/50">
                <div className="text-xs text-slate-400 mb-2 uppercase tracking-wider">Why this is ranked here</div>
                <div className="grid grid-cols-4 gap-2 mb-3">
                  {Object.entries(t.signals).map(([k, v]) => (
                    <div key={k} className="bg-slate-900 rounded p-2">
                      <div className="text-[10px] uppercase text-slate-500">{k}</div>
                      <div className="text-lg font-mono text-cyan-300">{v}</div>
                    </div>
                  ))}
                </div>
                <div className="text-xs text-slate-400 mb-1 uppercase tracking-wider">Objective handed to the AI agent</div>
                <Card className="bg-slate-900 border-slate-800 p-3 text-xs font-mono text-slate-300 whitespace-pre-wrap">
                  {t.objective}
                </Card>
              </div>
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Ingest
// ─────────────────────────────────────────────────────────────
const SAMPLE_TM = JSON.stringify({
  system: "demo-system",
  services: [
    { id: "svc-web", name: "web", criticality: "high", exposure: "internet",
      endpoints: [{ id: "ep-1", path: "/login", method: "POST", exposure: "internet" }] }
  ],
  threats: [
    { id: "thr-x", title: "Login brute force", target_service: "svc-web",
      stride: "Spoofing", risk: "high" }
  ],
}, null, 2);

function IngestView() {
  const { toast } = useToast();
  const [body, setBody] = useState(SAMPLE_TM);
  const ingest = useMutation({
    mutationFn: () => api.ingestTm(JSON.parse(body)),
    onSuccess: (r) => toast({ title: "Ingested", description: `${r.triples} triples` }),
    onError: (e: any) => toast({ title: "Ingest failed", description: e.message, variant: "destructive" }),
  });
  const feed = useMutation({
    mutationFn: (src: string) => api.ingestFeed(src),
    onSuccess: (r) => toast({ title: `Feed ${r.source}`, description: JSON.stringify(r.counts) }),
  });
  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold">Ingest</h1>
      <Explainer id="ingest" />
      <div className="flex gap-2">
        <Button onClick={() => feed.mutate("local")} variant="outline">Pull local feed</Button>
        <Button onClick={() => feed.mutate("s3")} variant="outline">Pull S3 feed</Button>
        <Button onClick={() => ingest.mutate()} disabled={ingest.isPending}
                className="bg-cyan-500 text-slate-950 hover:bg-cyan-400 ml-auto">
          {ingest.isPending ? "Posting…" : "POST threat-model"}
        </Button>
      </div>
      <textarea
        value={body} onChange={e => setBody(e.target.value)}
        className="w-full h-[480px] bg-slate-900 border border-slate-800 rounded p-3 font-mono text-xs text-slate-200"
        spellCheck={false}
      />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// App root
// ─────────────────────────────────────────────────────────────
export default function App() {
  const auth = useAuth();
  if (!auth.ready) return null;
  if (!auth.user) return (
    <QueryClientProvider client={qc}>
      <Toaster />
      <LoginScreen onLogin={auth.login} />
    </QueryClientProvider>
  );
  return (
    <QueryClientProvider client={qc}>
      <TooltipProvider>
        <Toaster />
        <Router hook={useHashLocation}>
          <div className="flex min-h-screen bg-slate-950 text-slate-100">
            <Sidebar onLogout={auth.logout} email={auth.user.email} />
            <main className="flex-1 overflow-y-auto">
              <Switch>
                <Route path="/" component={OverviewView} />
                <Route path="/graph" component={GraphView} />
                <Route path="/architect"><TypedListView id="architect" title="Architect view"
                  includeTypes={["Service", "DataStore", "TrustBoundary", "Endpoint"]} /></Route>
                <Route path="/appsec"><TypedListView id="appsec" title="AppSec view"
                  includeTypes={["Threat", "Finding", "PullRequest", "Commit", "Control"]} /></Route>
                <Route path="/soc"><TypedListView id="soc" title="SOC view"
                  includeTypes={["Alert", "Incident", "ExploitAttempt"]} /></Route>
                <Route path="/pentest" component={PentestView} />
                <Route path="/ingest" component={IngestView} />
              </Switch>
            </main>
          </div>
        </Router>
      </TooltipProvider>
    </QueryClientProvider>
  );
}
