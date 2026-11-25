import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { LogRow } from "@/lib/format";

// Filters as they sit in the URL: from/to are <input type="datetime-local">
// values, read as UTC like the HTMX page did. Any filter, or a page past the
// first, shows history instead of the live feed.
export type LogSearch = { from?: string; to?: string; app?: string; status?: string; page?: number; mode?: "history" };

export const pageSize = 50;

export const isLive = (s: LogSearch) => !s.from && !s.to && !s.app && !s.status && (s.page ?? 1) === 1 && s.mode !== "history";

// The query /api/logs takes (RFC 3339 times), and the one /logs/export takes (the URL's own).
export function logsQuery(s: LogSearch) {
  const q = new URLSearchParams({ limit: String(pageSize), offset: String(((s.page ?? 1) - 1) * pageSize) });
  if (s.app) q.set("app", s.app);
  if (s.status) q.set("status", s.status);
  if (s.from) q.set("from", `${s.from}:00Z`);
  if (s.to) q.set("to", `${s.to}:00Z`);
  return q.toString();
}

export function exportQuery(s: LogSearch) {
  const q = new URLSearchParams();
  for (const k of ["app", "status", "from", "to"] as const) if (s[k]) q.set(k, s[k]);
  const out = q.toString();
  return out ? `?${out}` : "";
}

export const useLogs = (s: LogSearch, live: boolean) =>
  useQuery({
    queryKey: ["logs", s],
    queryFn: () => api<{ total: number; logs: LogRow[] }>(`/api/logs?${logsQuery(s)}`),
    placeholderData: keepPreviousData,
    // The live feed keeps itself current from the stream.
    refetchOnWindowFocus: !live,
  });

export const useLogApps = () => useQuery({ queryKey: ["logs", "apps"], queryFn: () => api<string[]>("/api/logs/apps"), staleTime: 60_000 });

// One event per request on {admin}/logs/stream and in the stats seed
// (statEvent in internal/ui/logstats.go).
export type StatEvent = {
  id: number;
  t: number; // unix ms
  app: string;
  ip: string;
  cc: string;
  m: string;
  p: string;
  s: number;
  blk: boolean;
  why?: string;
  rule?: number;
  ms: number;
  br: string;
  os: string;
};

export const eventRow = (e: StatEvent): LogRow => ({
  ID: e.id,
  Timestamp: new Date(e.t).toISOString(),
  AppName: e.app,
  RealIP: e.ip,
  Country: e.cc,
  Method: e.m,
  Host: "",
  Path: e.p,
  Status: e.s,
  Blocked: e.blk,
  RuleID: e.rule ?? 0,
  Action: "",
  UserAgent: "",
  Duration: e.ms,
});

export type LogDetail = {
  id: number;
  request_id: string;
  timestamp: string;
  app_name: string;
  real_ip: string;
  proxy_ip: string;
  country: string;
  method: string;
  host: string;
  path: string;
  query: string;
  status: number;
  blocked: boolean;
  rule_id: number;
  action: string;
  user_agent: string;
  duration_ms: number;
  proto: string;
  tls_version: string;
  tls_cipher: string;
  tls_sni: string;
  asn: number;
  org: string;
  ja4: string;
  visitor_id: string;
  bot_score: number;
  cache_status: string;
  headers: Record<string, string> | null;
  has_threat_score: boolean;
  threat_score: number;
  threat_autoban: number;
  threat_bot: number;
  threat_asn: number;
  threat_geo: number;
  threat_ja4: number;
};

export const useLogDetail = (id: number | null) =>
  useQuery({ queryKey: ["log", id], queryFn: () => api<LogDetail>(`/logs/${id}`), enabled: id !== null, staleTime: Infinity });

// Rule feedback (issue #76) and a per-service exception (issue #7). The
// server takes the rule and service from the stored row, never from here.
export const useRuleFeedback = (id: number) =>
  useMutation({
    mutationFn: (falsePositive: boolean) => {
      const body = new FormData();
      body.set("false_positive", falsePositive ? "1" : "0");
      return api(`/logs/feedback/${id}`, { method: "POST", body });
    },
  });

export const useLogException = (id: number) =>
  useMutation({ mutationFn: () => api<{ service: string }>(`/logs/exception/${id}`, { method: "POST" }) });
