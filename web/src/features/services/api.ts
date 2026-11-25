import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// The Services page (internal/ui/services.go, issue #356): one read with
// every service and all its settings, grouped as the edit dialog's tabs, and
// one write per tab.

export type Mode3 = "off" | "log" | "enforce";
export type Backend = { url: string; healthy: boolean; known: boolean };
export type Backends = { urls: string[]; health?: Backend[]; lb_policy: "round_robin" | "least_conn"; health_path: string; health_interval: number; ca: string };
export type Hosts = { aliases: string[]; canonical: string };
export type RateLimit = { rps: number; burst: number; path_rules: string };
export type Bot = { mode: "inherit" | "always" | "off"; ai: Partial<Record<"training" | "search" | "user", string>>; login_paths: string[]; breach_action: "" | "log" | "block"; breach_fields: string[] };
export type Gate = {
  maintenance: boolean;
  message: string;
  start: string;
  end: string;
  bypass?: string;
  waiting_room: boolean;
  max_active: number;
  idle_mins: number;
  wait_message: string;
  crawlers: "bypass" | "deny";
};
export type Uploads = { large_js: boolean; multipart_mb: number; malware_scan: "" | "log" | "block" };
export type MCP = { mode: Mode3; path: string; origins: string[]; methods: string[]; tools: string[] };
export type JWT = { mode: Mode3; jwks_url: string; public_key: string; issuer: string; audience: string; algorithms: string[]; prefixes: string[] };
export type CSPScript = { origin: string; page: string; first_seen: string };
export type CSP = { mode: "off" | "report" | "enforce"; policy: string; scripts?: CSPScript[]; approved: string[]; recent?: boolean; full?: boolean };
export type Policy = { mode: Mode3; methods: string[]; content_types: string[]; max_body_kib: number };
export type Cache = { enabled: boolean; by_session: boolean; session_cookie: string; ttl_floor: number; ttl_ceiling: number; grace: number; keep: number; rules: string };
export type TLS = { mode: "" | "custom" | "auto"; cert_id: number; cert_name: string; expires_at: string; http3: boolean; mtls: { mode: "off" | "optional" | "required"; ca_set: boolean; allow: string[] } };

export type Service = {
  id: number;
  name: string;
  host: string;
  prefix: string;
  docker: boolean;
  created_at: string;
  healthy: boolean;
  known: boolean;
  hosts: Hosts;
  backends: Backends;
  rate_limit: RateLimit;
  bot: Bot;
  gate: Gate;
  uploads: Uploads;
  schema: { mode: Mode3; schema: string };
  openapi_mode: Mode3;
  mcp: MCP;
  jwt: JWT;
  csp: CSP;
  cookies: { enabled: boolean; exempt: string[] };
  policy: Policy;
  responses: "" | "log" | "block";
  cache: Cache;
  compress: boolean;
  tls: TLS;
};

export type PoolCert = { id: number; name: string; domains: string };
export type ServicesPage = { services: Service[]; certificates: PoolCert[]; acme_email: boolean; http3_listener: boolean; varnish: boolean };

export type NewService = { name: string; match_type: "host" | "prefix"; match_value: string; backend: string; rate_limit_rps: number; rate_limit_burst: number };

export type CacheStats = {
  enabled: boolean;
  stats_error?: string;
  stats?: { ratio: string; objects: number; used: string; total: string; evicted: number };
  services?: { app: string; hits: number; misses: number; passes: number; errors: number; ratio: string }[];
};

const key = ["services"];
const json = (method: string, body: unknown) => ({ method, body: JSON.stringify(body) });

// Polled so the health dots follow real traffic.
export const useServices = () => useQuery({ queryKey: key, queryFn: () => api<ServicesPage>("/api/services"), refetchInterval: 15_000 });

// varnishstat is an exec on the server, so it has its own slower poll.
export const useCacheStats = () => useQuery({ queryKey: ["services", "cache-stats"], queryFn: () => api<CacheStats>("/api/services/cache-stats"), refetchInterval: 30_000 });

function useServiceWrite<V>(fn: (v: V) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSettled: () => qc.invalidateQueries({ queryKey: key }) });
}

export const useAddService = () => useServiceWrite((s: NewService) => api<unknown>("/api/services", json("POST", s)));
export const useDeleteService = () => useServiceWrite((id: number) => api<null>(`/api/services/${id}`, { method: "DELETE" }));

export const usePurge = (id: number) => useServiceWrite((path: string) => api<null>(`/api/services/${id}/purge`, json("POST", { path })));

// useSetService writes one tab: PUT /api/services/:id/<tab>.
export const useSetService = <V>(id: number, tab: string) => useServiceWrite((v: V) => api<null>(`/api/services/${id}/${tab}`, json("PUT", v)));

// lines turns a textarea into a list, dropping blank lines.
export const lines = (s: string) =>
  s
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

// The OpenAPI spec can be large, so the list carries only its mode and the
// Requests tab reads the spec itself.
export type OpenAPI = { mode: Mode3; spec: string };
export const useOpenAPI = (id: number) => useQuery({ queryKey: ["services", id, "openapi"], queryFn: () => api<OpenAPI>(`/api/services/${id}/openapi`) });

export type TLSWrite = { mode: "pool" | "custom" | "auto" | "none"; cert_id?: number; cert_pem?: string; key_pem?: string; acme_email?: string };
export type MTLSWrite = { mode: TLS["mtls"]["mode"]; ca: string; allow: string[] };
