// Session values Go renders onto <body> (web/index.html, internal/ui/app.go),
// so the app starts without a "who am I" request.
const d = document.body.dataset;

export type Role = "owner" | "admin" | "viewer";

export const boot = {
  admin: d.admin ?? "/admin",
  csrf: d.csrf ?? "",
  role: (d.role ?? "viewer") as Role,
  email: d.email ?? "",
  demo: d.demo === "true",
  version: d.version ?? "",
  waf: d.waf === "true",
  nonce: d.nonce ?? "",
};

const rank: Record<Role, number> = { viewer: 1, admin: 2, owner: 3 };

// can mirrors the Go templates' {{if can .Role "admin"}}. Display only: the
// server enforces every role on its routes.
export const can = (need: Role) => (rank[boot.role] ?? 0) >= rank[need];
