import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { IPRule, IPRulesPage, IPSettings } from "./api";

const rule = (id: number, ip: string, extra: Partial<IPRule> = {}): IPRule => ({
  id,
  app_name: "",
  ip,
  rule_type: "block",
  note: "",
  auto: false,
  score: 0,
  proxy: "",
  created_at: "2026-11-24T10:00:00Z",
  ...extra,
});

const page: IPRulesPage = {
  rules: [rule(1, "203.0.113.9", { auto: true, note: "Auto-banned — sqli", score: 42, proxy: "DCH" }), rule(2, "10.0.0.0/8", { rule_type: "allow", app_name: "shop" })],
  page: 1,
  total_pages: 2,
  total: 18,
  block_count: 17,
  allow_count: 1,
};

const settings: IPSettings = {
  autoban: { enabled: true, threshold: 10, window: 10, ban_hours: 24, bad_status: false, bad_codes: "404", bad_points: 1 },
  adaptive: { enabled: false, high_threshold: 70, low_threshold: 10, high_scale: 0.3, low_scale: 1.5, force_challenge: 70 },
  honeypot_paths: ["/wp-login.php"],
};

const base = {
  "GET /api/notifications": { unread: 0, blocks: [] },
  "GET /api/ip-rules?page=1": page,
  "GET /api/ip-rules/settings": settings,
  "GET /api/logs/apps": ["shop"],
};

describe("ip rules page", () => {
  it("lists rules with auto bans, scores, counts and pages", async () => {
    mockApi({ ...base, "GET /api/ip-rules?page=1": { ...page, rules: [...page.rules, rule(3, "17.0.0.1", { proxy: "CPN" })] } });
    await renderRoute("/ip-rules");
    expect(await screen.findByText("203.0.113.9")).toBeInTheDocument();
    expect(screen.getByText("Auto")).toBeInTheDocument();
    expect(screen.getByText("Score 42")).toBeInTheDocument();
    expect(screen.getAllByText("Score —")).toHaveLength(2);
    // Proxy type from --proxy-db: only listed addresses get a tag.
    expect(screen.getByText("Data centre")).toHaveAttribute("title", expect.stringMatching(/counts toward/));
    expect(screen.getByText("Privacy relay")).toHaveAttribute("title", expect.stringMatching(/not scored/));
    expect(screen.getByText(/Auto-banned — sqli/)).toBeInTheDocument();
    expect(screen.getByText(/shop ·/)).toBeInTheDocument();
    expect(screen.getByText("18 rules")).toBeInTheDocument();
    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Next →" })).toHaveAttribute("href", "/admin/ip-rules?page=2");
    expect(await screen.findByDisplayValue("/wp-login.php")).toBeInTheDocument();
  });

  it("reads the page from the URL", async () => {
    mockApi({ ...base, "GET /api/ip-rules?page=2": { ...page, page: 2, rules: [rule(3, "192.0.2.1")] } });
    await renderRoute("/ip-rules?page=2");
    expect(await screen.findByText("192.0.2.1")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "← Prev" })).toHaveAttribute("href", "/admin/ip-rules");
  });

  it("shows loading, empty and error states", async () => {
    mockApi({ ...base, "GET /api/ip-rules?page=1": pending, "GET /api/ip-rules/settings": pending });
    const { unmount } = await renderRoute("/ip-rules");
    expect(screen.getAllByText("Loading…").length).toBeGreaterThan(0);
    unmount();

    mockApi({ ...base, "GET /api/ip-rules?page=1": { ...page, rules: [], total: 0, total_pages: 1 } });
    const r = await renderRoute("/ip-rules");
    expect(await screen.findByText("No IP rules yet")).toBeInTheDocument();
    r.unmount();

    mockApi({ ...base, "GET /api/ip-rules?page=1": reply(500, { error: "internal", message: "x" }), "GET /api/ip-rules/settings": reply(500, {}) });
    await renderRoute("/ip-rules");
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.map((a) => a.textContent).join(" ")).toMatch(/Couldn't load the IP rules.*|Couldn't load the banning settings/);
    expect(screen.queryByText("No IP rules yet")).not.toBeInTheDocument();
  });

  it("adds several rules at once and shows a server field error", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/ip-rules": () => (fail ? reply(400, { error: "invalid", message: "bad", fields: { ip: '"nope" is not an IP or CIDR range.' } }) : reply(201, { added: 2 })),
    });
    const { user } = await renderRoute("/ip-rules");
    const ips = await screen.findByLabelText("IP addresses");
    await user.type(ips, "1.2.3.4{enter}nope");
    await user.selectOptions(screen.getByLabelText("Scope"), "shop");
    await user.click(screen.getByLabelText("Allow"));
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText('"nope" is not an IP or CIDR range.')).toBeInTheDocument();
    expect(api.calls("POST /api/ip-rules")[0]!.json).toEqual({ ip: "1.2.3.4\nnope", app_name: "shop", rule_type: "allow" });
    expect(api.calls("POST /api/ip-rules")[0]!.headers.get("X-CSRF-Token")).toBeTruthy();

    fail = false;
    await user.click(screen.getByRole("button", { name: "Add" }));
    await vi.waitFor(() => expect(api.calls("GET /api/ip-rules?page=1").length).toBeGreaterThan(1));
    expect(screen.getByLabelText("IP addresses")).toHaveValue("");
  });

  it("removes the selected rules after confirming", async () => {
    const api = mockApi({ ...base, "POST /api/ip-rules/remove": reply(204) });
    const { user } = await renderRoute("/ip-rules");
    await user.click(await screen.findByLabelText("Select 203.0.113.9"));
    await user.click(screen.getByLabelText("Select 10.0.0.0/8"));
    await user.click(screen.getByRole("button", { name: "Remove selected (2)" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove 2 rules?" });
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    expect(api.calls("POST /api/ip-rules/remove")[0]!.json).toEqual({ ids: [1, 2] });

    await user.click(screen.getByRole("button", { name: "Remove 10.0.0.0/8" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Remove 10.0.0.0/8?" })).getByRole("button", { name: "Remove" }));
    expect(api.calls("POST /api/ip-rules/remove")[1]!.json).toEqual({ ids: [2] });
  });

  it("saves the banning settings and shows field errors", async () => {
    const api = mockApi({
      ...base,
      "PUT /api/ip-rules/autoban": reply(400, { error: "invalid", message: "Fix the highlighted fields.", fields: { threshold: "Between 1 and 1000." } }),
      "PUT /api/ip-rules/honeypots": reply(204),
    });
    const { user } = await renderRoute("/ip-rules");
    const score = await screen.findByLabelText("Ban score");
    await user.clear(score);
    // The browser's own min/max checks stop 0; the server's error is shown too.
    await user.type(score, "5");
    await user.click(screen.getAllByRole("button", { name: "Save & apply" })[0]!);
    await vi.waitFor(() => expect(api.calls("PUT /api/ip-rules/autoban")).toHaveLength(1));
    expect(await screen.findByText("Between 1 and 1000.")).toBeInTheDocument();
    expect(api.calls("PUT /api/ip-rules/autoban")[0]!.json).toEqual({ ...settings.autoban, threshold: 5 });

    const paths = screen.getByLabelText("Honeypot paths");
    await user.type(paths, "{enter}/xmlrpc.php");
    await user.click(screen.getAllByRole("button", { name: "Save & apply" })[2]!);
    await vi.waitFor(() => expect(api.calls("GET /api/ip-rules/settings").length).toBeGreaterThan(1));
    expect(api.calls("PUT /api/ip-rules/honeypots")[0]!.json).toEqual({ honeypot_paths: "/wp-login.php\n/xmlrpc.php" });
  });

  it("saves adaptive enforcement and shows errors no field carries", async () => {
    const api = mockApi({
      ...base,
      "PUT /api/ip-rules/adaptive": reply(204),
      "PUT /api/ip-rules/honeypots": reply(400, { error: "invalid", message: "bad", fields: { honeypot_paths: '"x" is not a path' } }),
      "POST /api/ip-rules": reply(500, {}),
    });
    const { user } = await renderRoute("/ip-rules");
    await user.click(await screen.findByLabelText("Adjust enforcement automatically"));
    await user.click(screen.getAllByRole("button", { name: "Save & apply" })[1]!);
    await vi.waitFor(() => expect(api.calls("PUT /api/ip-rules/adaptive")).toHaveLength(1));
    expect(api.calls("PUT /api/ip-rules/adaptive")[0]!.json).toEqual({ ...settings.adaptive, enabled: true });

    await user.click(screen.getAllByRole("button", { name: "Save & apply" })[2]!);
    expect(await screen.findByText('"x" is not a path')).toBeInTheDocument();
    expect(screen.getByLabelText("Honeypot paths")).toHaveAttribute("aria-invalid", "true");

    await user.type(screen.getByLabelText("IP addresses"), "1.2.3.4");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText("Couldn't save. Try again.")).toBeInTheDocument();
  });

  it("shows a scope error from the server", async () => {
    mockApi({ ...base, "POST /api/ip-rules": reply(400, { error: "invalid", message: "x", fields: { app_name: "No service has that name." } }) });
    const { user } = await renderRoute("/ip-rules");
    await user.type(await screen.findByLabelText("IP addresses"), "1.2.3.4");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText("No service has that name.")).toBeInTheDocument();
    expect(screen.getByLabelText("Scope")).toHaveAttribute("aria-invalid", "true");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("selects all on the page, unticks, and cancels a removal", async () => {
    const api = mockApi({ ...base, "GET /api/ip-rules?page=3": { ...page, page: 3, total_pages: 3 } });
    const { user } = await renderRoute("/ip-rules?page=3");
    expect(await screen.findByRole("link", { name: "← Prev" })).toHaveAttribute("href", "/admin/ip-rules?page=2");
    await user.click(screen.getByLabelText("Select all on this page"));
    expect(screen.getByRole("button", { name: "Remove selected (2)" })).toBeEnabled();
    await user.click(screen.getByLabelText("Select 10.0.0.0/8"));
    expect(screen.getByRole("button", { name: "Remove selected (1)" })).toBeEnabled();
    await user.click(screen.getByLabelText("Select all on this page"));
    await user.click(screen.getByLabelText("Select all on this page"));
    expect(screen.getByRole("button", { name: "Remove selected" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Remove 203.0.113.9" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.calls("POST /api/ip-rules/remove")).toHaveLength(0);
  });

  it("is read-only for viewers", async () => {
    asRole("viewer");
    mockApi({ "GET /api/notifications": base["GET /api/notifications"], "GET /api/ip-rules?page=1": page, "GET /api/ip-rules/settings": settings });
    await renderRoute("/ip-rules");
    expect(await screen.findByText("203.0.113.9")).toBeInTheDocument();
    expect(screen.queryByText("Add IP Rules")).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /Select/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save & apply" })).not.toBeInTheDocument();
    expect(await screen.findByLabelText("Ban score")).toBeDisabled();
  });
});
