/**
 * tg-api client — calls FastAPI backend with JWT bearer auth.
 * Token persisted in React state (sandbox blocks localStorage; the AuthProvider
 * keeps the JWT alive via cookieless in-memory store).
 */
const BASE = import.meta.env.VITE_API_BASE || "/api/v1";

let TOKEN: string | null = null;
export const setToken = (t: string | null) => { TOKEN = t; };
export const getToken = () => TOKEN;

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> || {}),
  };
  if (TOKEN) headers["Authorization"] = `Bearer ${TOKEN}`;
  const r = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  const ct = r.headers.get("content-type") || "";
  return (ct.includes("json") ? r.json() : r.text()) as Promise<T>;
}

export type StridE = "Spoofing" | "Tampering" | "Repudiation"
  | "InformationDisclosure" | "DenialOfService" | "ElevationOfPrivilege";

export interface PentestTask {
  id: string; threat_id: string; title: string;
  target_service: string; stride: StridE; priority: number;
  signals: {
    exposure: number; risk: number; control_gap: number;
    recent_change: number; runtime_signal: number;
    criticality: number; bonus: number;
  };
  attack_path: string[]; objective: string;
  status: "pending" | "running" | "succeeded" | "failed" | "inconclusive";
}

export interface Triple {
  s: { v: string; e: boolean };
  p: { v: string; e: boolean };
  o: { v: string; e: boolean };
}

export const api = {
  login: (email: string, password: string) => {
    const body = new URLSearchParams({ username: email, password });
    return fetch(`${BASE}/auth/login`, {
      method: "POST", body,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }).then(r => r.json());
  },
  me: () => req<{ email: string; roles: string[] }>("/auth/me"),
  health: () => req<{ ok: boolean }>("/readyz"),

  graphQuery: (params: { subject?: string; predicate?: string; obj?: string; limit?: number }) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && qs.set(k, String(v)));
    return req<{ count: number; triples: Triple[] }>(`/graph/query?${qs}`);
  },
  ask: (question: string) =>
    req<any>("/graph/ask", { method: "POST", body: JSON.stringify({ question }) }),

  ingestTm: (tm: unknown) =>
    req<{ system: string; triples: number }>("/ingest/threat-model",
      { method: "POST", body: JSON.stringify(tm) }),
  ingestFeed: (source: string, sessionPath?: string) => {
    const qs = sessionPath ? `?session_path=${encodeURIComponent(sessionPath)}` : "";
    return req<{ source: string; counts: Record<string, number> }>(
      `/ingest/feed/${source}${qs}`, { method: "POST" });
  },

  dispatchScan: (scanner: string, target_service: string, target: string) =>
    req<{ job_id: string }>("/enrich/scan", {
      method: "POST",
      body: JSON.stringify({ scanner, target_service, target }),
    }),
  job: (id: string) => req<{ id: string; status: string; result: unknown }>(`/jobs/${id}`),

  plan: (top_n = 20) => req<{ count: number; tasks: PentestTask[] }>(
    `/plan?top_n=${top_n}`, { method: "POST" }),
  listTasks: () => req<PentestTask[]>("/plan/tasks"),
  execute: (id: string) => req<{ job_id: string }>(
    `/plan/tasks/${encodeURIComponent(id)}/execute`, { method: "POST" }),
};

export const sevClass = (s: string) => ({
  low: "text-emerald-400",
  medium: "text-amber-400",
  high: "text-orange-400",
  critical: "text-rose-400",
})[s] ?? "text-slate-400";

export const statusClass = (s: string) => ({
  open: "text-amber-400",
  in_progress: "text-cyan-400",
  mitigated: "text-emerald-400",
  succeeded: "text-emerald-400",
  failed: "text-rose-400",
  inconclusive: "text-amber-400",
  pending: "text-slate-400",
  running: "text-cyan-400",
})[s] ?? "text-slate-400";
