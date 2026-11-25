import { screen, within } from "@testing-library/react";
import type { CacheStats, Service, ServicesPage } from "./api";

// Fixtures the services page tests share.

export const svc = (over: Partial<Service> = {}): Service => ({
  id: 1,
  name: "blog",
  host: "blog.example.com",
  prefix: "",
  docker: false,
  created_at: "2026-11-24T10:00:00Z",
  healthy: true,
  known: true,
  hosts: { aliases: [], canonical: "" },
  backends: { urls: ["http://10.0.0.5:3000"], health: [{ url: "http://10.0.0.5:3000", healthy: true, known: true }], lb_policy: "round_robin", health_path: "", health_interval: 0, ca: "" },
  rate_limit: { rps: 0, burst: 0, path_rules: "" },
  bot: { mode: "inherit", ai: {}, login_paths: [], breach_action: "", breach_fields: [] },
  gate: { maintenance: false, message: "", start: "", end: "", bypass: "abc", waiting_room: false, max_active: 0, idle_mins: 0, wait_message: "", crawlers: "bypass" },
  uploads: { large_js: false, multipart_mb: 0, malware_scan: "" },
  schema: { mode: "off", schema: "" },
  openapi_mode: "off",
  mcp: { mode: "off", path: "", origins: [], methods: [], tools: [] },
  jwt: { mode: "off", jwks_url: "", public_key: "", issuer: "", audience: "", algorithms: [], prefixes: [] },
  csp: { mode: "off", policy: "", approved: [] },
  cookies: { enabled: false, exempt: [] },
  policy: { mode: "off", methods: [], content_types: [], max_body_kib: 0 },
  responses: "",
  cache: { enabled: false, by_session: false, session_cookie: "", ttl_floor: 0, ttl_ceiling: 0, grace: 0, keep: 0, rules: "" },
  compress: false,
  tls: { mode: "", cert_id: 0, cert_name: "", expires_at: "", http3: false, mtls: { mode: "off", ca_set: false, allow: [] } },
  ...over,
});

export const page = (services: Service[]): ServicesPage => ({ services, certificates: [], acme_email: false, http3_listener: false, varnish: false });

export const base = (services: Service[]) => ({
  "GET /api/notifications": { unread: 0, blocks: [] },
  "GET /api/services": page(services),
  "GET /api/services/cache-stats": { enabled: false } satisfies CacheStats,
});

export async function openEdit(user: { click: (e: Element) => Promise<void> }, name = "blog") {
  await user.click(await screen.findByRole("button", { name: new RegExp(`^(Edit|View) ${name}$`) }));
  return within(await screen.findByRole("dialog"));
}
