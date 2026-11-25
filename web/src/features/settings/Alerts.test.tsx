import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole, setBoot } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { Alerts, AuditEntry } from "./api";

const alerts: Alerts = {
  webhook: { enabled: true, url: "https://hooks.example.com/x", secret: "s", events: ["blocked"], destination_type: "slack" },
  email: { enabled: false, sender: "reports@palisade.example", to: "ops@example.com", token_set: true },
};
const entry = (n: number): AuditEntry => ({ ts: "2026-11-24T10:00:00Z", actor: "me@example.com", ip: "192.0.2.1", action: `PUT /api/settings/bot`, target: "", summary: `threshold=${n}` });

const base = {
  "GET /api/notifications": { unread: 0, blocks: [] },
  "GET /api/settings/account": pending,
  "GET /api/settings/team": pending,
  "GET /api/settings/protection": pending,
  "GET /api/settings/alerts": alerts,
  "GET /api/settings/audit": { entries: [entry(1)], page: 1, pages: 1, total: 1 },
};
const card = async (title: string) => within((await screen.findByRole("heading", { name: title })).closest("section")!);

describe("settings: alerts and activity", () => {
  it("saves the webhook with its events and shows field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "PUT /api/settings/webhook": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { url: "Use https." } }) : reply(204)),
    });
    const { user } = await renderRoute("/settings");
    const c = await card("Webhook / SIEM Export");
    await user.click(c.getByLabelText("New script sources (CSP)"));
    await user.click(c.getByRole("button", { name: /Save/ }));
    expect(await c.findByText("Use https.")).toBeInTheDocument();
    fail = false;
    await user.click(c.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/webhook")).toHaveLength(2));
    expect(api.calls("PUT /api/settings/webhook")[1]!.json).toEqual({ enabled: true, url: "https://hooks.example.com/x", secret: "s", events: ["blocked", "scripts"], destination_type: "slack" });
  });

  it("says why a test send failed", async () => {
    mockApi({ ...base, "POST /api/settings/webhook/test": reply(502, { error: "send_failed", message: "Send failed: connection refused" }) });
    const { user } = await renderRoute("/settings");
    const c = await card("Webhook / SIEM Export");
    await user.click(c.getByRole("button", { name: "Send test alert" }));
    expect(await c.findByRole("alert")).toHaveTextContent("connection refused");
  });

  it("saves email keeping a blank token", async () => {
    const api = mockApi({ ...base, "PUT /api/settings/email": reply(204), "POST /api/settings/email/test": reply(204) });
    const { user } = await renderRoute("/settings");
    const c = await card("Email Alerts");
    expect(c.getByText("reports@palisade.example")).toBeInTheDocument();
    expect(c.getByLabelText("Cloudflare API token (saved; blank keeps it)")).toHaveValue("");
    await user.click(c.getByLabelText("Enable daily report email"));
    await user.click(c.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/email")[0]?.json).toEqual({ enabled: true, to: "ops@example.com", token: "" }));
    await user.click(c.getByRole("button", { name: "Send test report" }));
    await vi.waitFor(() => expect(api.calls("POST /api/settings/email/test")).toHaveLength(1));
  });

  it("pages through the audit log", async () => {
    const api = mockApi({
      ...base,
      "GET /api/settings/audit?page=1": { entries: [entry(1)], page: 1, pages: 2, total: 11 },
      "GET /api/settings/audit?page=2": { entries: [entry(2)], page: 2, pages: 2, total: 11 },
    });
    const { user } = await renderRoute("/settings");
    const c = await card("Audit log");
    expect(await c.findByText("threshold=1")).toBeInTheDocument();
    expect(c.getByRole("button", { name: "← Prev" })).toBeDisabled();
    await user.click(c.getByRole("button", { name: "Next →" }));
    expect(await c.findByText("threshold=2")).toBeInTheDocument();
    expect(c.getByText(/Page 2 of 2/)).toBeInTheDocument();
    expect(api.calls("GET /api/settings/audit?page=2")).toHaveLength(1);
  });

  it("shows an empty and a failed audit log", async () => {
    mockApi({ ...base, "GET /api/settings/audit": { entries: [], page: 1, pages: 1, total: 0 } });
    const r = await renderRoute("/settings");
    expect(await screen.findByText("No changes recorded yet.")).toBeInTheDocument();
    r.unmount();
    mockApi({ ...base, "GET /api/settings/audit": reply(500, {}) });
    await renderRoute("/settings");
    expect(await within(screen.getByRole("region", { name: "Activity" })).findByRole("alert")).toHaveTextContent("Couldn't load the audit log");
  });

  it("hides alerts from admins and links to the Pro page when there is one", async () => {
    asRole("admin");
    setBoot({ pro: true });
    mockApi(base);
    await renderRoute("/settings");
    expect(await screen.findByRole("heading", { name: "Audit log" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Webhook / SIEM Export" })).toBeNull();
    expect(screen.getByRole("link", { name: "Palisade Pro settings" })).toHaveAttribute("href", "/admin/settings/pro");
  });
});
