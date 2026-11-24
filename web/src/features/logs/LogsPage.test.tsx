import { act, screen, waitFor, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { FakeEventSource } from "@/test/events";
import { renderRoute } from "@/test/render";
import type { LogDetail, StatEvent } from "./api";

const row = (id: number, over = {}) => ({
  ID: id,
  Timestamp: "2026-11-24T10:00:00Z",
  AppName: "shop",
  RealIP: "198.51.100.7",
  Country: "NL",
  Method: "GET",
  Host: "",
  Path: `/p${id}`,
  Status: 200,
  Blocked: false,
  RuleID: 0,
  Action: "",
  UserAgent: "",
  Duration: 3,
  ...over,
});

const event = (id: number, over: Partial<StatEvent> = {}): StatEvent => ({ id, t: Date.now(), app: "shop", ip: "203.0.113.5", cc: "DE", m: "POST", p: `/live${id}`, s: 403, blk: true, why: "waf_blocked #942100", rule: 942100, ms: 4, br: "Firefox", os: "Linux", ...over });

const detail: LogDetail = {
  id: 7, request_id: "abc123", timestamp: "2026-11-24T10:00:00Z", app_name: "shop", real_ip: "198.51.100.7", proxy_ip: "10.0.0.1", country: "NL",
  method: "POST", host: "shop.example", path: "/login", query: "next=%2F", status: 403, blocked: true, rule_id: 942100, action: "waf_blocked",
  user_agent: "sqlmap/1.7", duration_ms: 12, proto: "HTTP/2.0", tls_version: "TLS 1.3", tls_cipher: "TLS_AES_128_GCM_SHA256", tls_sni: "shop.example",
  asn: 64500, org: "Example Net", ja4: "", visitor_id: "", bot_score: 0, cache_status: "", headers: { "User-Agent": "sqlmap/1.7", Accept: "*/*" },
  has_threat_score: true, threat_score: 42, threat_autoban: 30, threat_bot: 12, threat_asn: 0, threat_geo: 0, threat_ja4: 0,
};

const base = {
  "GET /api/notifications": { unread: 0, blocks: [] },
  "GET /api/logs/apps": ["shop", "api"],
};
const liveList = "GET /api/logs?limit=50&offset=0";
const stream = () => FakeEventSource.all.find((s) => s.url === "/admin/logs/stream")!;
const rows = () => screen.queryAllByRole("button", { name: /Show details/ });

describe("logs page", () => {
  afterEach(() => sessionStorage.clear());

  it("is the live feed: database rows first, then streamed rows on top", async () => {
    mockApi({ ...base, [liveList]: { total: 2, logs: [row(2), row(1)] } });
    await renderRoute("/logs");
    expect(await screen.findByText("/p2")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Connecting…");
    act(() => stream().emit("open", ""));
    expect(screen.getByRole("status")).toHaveTextContent("Live");

    act(() => {
      stream().emit("message", JSON.stringify(event(2))); // already listed: not twice
      stream().emit("message", JSON.stringify(event(3)));
      stream().emit("message", "not json");
    });
    await waitFor(() => expect(rows()).toHaveLength(3));
    expect(rows()[0]).toHaveAccessibleName("POST /live3, status 403, blocked. Show details");
    expect(within(rows()[0]!).getByText("#942100")).toBeInTheDocument();
  });

  it("holds new rows while paused and shows them on resume", async () => {
    mockApi({ ...base, [liveList]: { total: 0, logs: [] } });
    const { user } = await renderRoute("/logs");
    expect(await screen.findByText("Waiting for requests…")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Pause" }));
    expect(screen.getByRole("status")).toHaveTextContent("Paused");
    act(() => stream().emit("message", JSON.stringify(event(1))));
    const pill = await screen.findByRole("button", { name: "1 new · show" });
    expect(rows()).toHaveLength(0);
    await user.click(pill);
    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(screen.getByRole("button", { name: "Pause" })).toHaveAttribute("aria-pressed", "false");
  });

  it("turns filters into a history page with the filters in the URL", async () => {
    const api = mockApi({
      ...base,
      [liveList]: { total: 0, logs: [] },
      "GET /api/logs": (req) => (req.path.includes("status=blocked") ? { total: 120, logs: [row(9, { Blocked: true })] } : { total: 0, logs: [] }),
    });
    const { user, router } = await renderRoute("/logs");
    await screen.findByText("Waiting for requests…");
    await user.selectOptions(screen.getByLabelText("Status"), "blocked");
    await user.selectOptions(screen.getByLabelText("App"), "api");
    await user.type(screen.getByLabelText("From (UTC)"), "2026-11-01T00:00");
    await user.click(screen.getByRole("button", { name: "Filter" }));

    expect(await screen.findByText("Showing 1 of 120 matching requests")).toBeInTheDocument();
    expect(router.state.location.search).toEqual({ status: "blocked", app: "api", from: "2026-11-01T00:00", mode: "history" });
    const q = new URLSearchParams(api.calls("GET /api/logs").at(-1)!.path.split("?")[1]);
    expect(Object.fromEntries(q)).toEqual({ limit: "50", offset: "0", app: "api", status: "blocked", from: "2026-11-01T00:00:00Z" });
    expect(FakeEventSource.all.find((s) => s.url === "/admin/logs/stream")!.closed).toBe(true);
    expect(screen.queryByRole("tab")).toBeNull();
    expect(screen.getByRole("link", { name: "Export NDJSON" })).toHaveAttribute("href", "/admin/logs/export?app=api&status=blocked&from=2026-11-01T00%3A00");

    await user.click(screen.getByRole("link", { name: "Next →" }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ page: 2 }));
    expect(api.calls("GET /api/logs").at(-1)!.path).toContain("offset=50");
    expect(screen.getByText("Page 2 of 3")).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Back to live" }));
    expect(await screen.findByRole("button", { name: "Pause" })).toBeInTheDocument();
  });

  it("opens old HTMX links (status=blocked&mode=history) as history", async () => {
    mockApi({ ...base, "GET /api/logs?limit=50&offset=0&status=blocked": { total: 0, logs: [] } });
    await renderRoute("/logs?status=blocked&mode=history");
    expect(await screen.findByText("No requests match these filters.")).toBeInTheDocument();
    expect(screen.getByLabelText("Status")).toHaveValue("blocked");
  });

  it("shows a failed read as an error, not an empty feed", async () => {
    mockApi({ ...base, [liveList]: reply(500, { error: "internal", message: "x" }) });
    await renderRoute("/logs");
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load requests");
    expect(screen.queryByText("Waiting for requests…")).toBeNull();
  });

  it("inspects a request, and an admin can give rule feedback and make an exception", async () => {
    const api = mockApi({
      ...base,
      [liveList]: { total: 1, logs: [row(7, { Blocked: true, RuleID: 942100, Status: 403 })] },
      "GET /logs/7": detail,
      "POST /logs/feedback/7": { status: "ok" },
      "POST /logs/exception/7": reply(400, { error: "invalid", message: "Service shop no longer exists." }),
    });
    const { user } = await renderRoute("/logs");
    await user.click(await screen.findByRole("button", { name: /POST|GET \/p7/ }));
    const sheet = await screen.findByRole("dialog", { name: "Request inspector" });
    expect(await within(sheet).findByText("abc123")).toBeInTheDocument();
    expect(within(sheet).getByText("Rule #942100 · waf_blocked")).toBeInTheDocument();
    expect(within(sheet).getByText("AS64500")).toBeInTheDocument();
    expect(within(sheet).getByText("sqlmap/1.7", { selector: "span" })).toBeInTheDocument();
    expect(within(sheet).getByText(/autoban 30 · bot 12/)).toBeInTheDocument();

    await user.click(within(sheet).getByRole("button", { name: "False positive" }));
    expect(await within(sheet).findByText("Marked false positive.")).toBeInTheDocument();
    const sent = api.calls("POST /logs/feedback/7")[0]!;
    expect(sent.headers.get("X-CSRF-Token")).toBe("test-csrf");

    vi.spyOn(window, "confirm").mockReturnValue(true);
    await user.click(within(sheet).getByRole("button", { name: "Create exception" }));
    expect(await within(sheet).findByText("Service shop no longer exists.")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("is read-only for a viewer: no export, no rule actions", async () => {
    asRole("viewer");
    mockApi({ ...base, [liveList]: { total: 1, logs: [row(7, { Blocked: true, RuleID: 942100 })] }, "GET /logs/7": detail });
    const { user } = await renderRoute("/logs");
    await user.click(await screen.findByRole("button", { name: /\/p7/ }));
    const sheet = await screen.findByRole("dialog");
    await within(sheet).findByText("abc123");
    expect(within(sheet).queryByRole("button", { name: /false positive|correct block|exception/i })).toBeNull();
    expect(screen.queryByRole("link", { name: "Export NDJSON" })).toBeNull();
  });

  it("says when a request can't be loaded", async () => {
    mockApi({ ...base, [liveList]: { total: 1, logs: [row(7)] }, "GET /logs/7": reply(404, { error: "not_found", message: "not found" }) });
    const { user } = await renderRoute("/logs");
    await user.click(await screen.findByRole("button", { name: /\/p7/ }));
    expect(await within(await screen.findByRole("dialog")).findByRole("alert")).toHaveTextContent(/may have been pruned/);
  });

  it("stats: seeds the last hour once, then counts the stream, and remembers the tab", async () => {
    const api = mockApi({
      ...base,
      [liveList]: { total: 0, logs: [] },
      "GET /logs/stats": { since: Date.now() - 3600_000, events: [event(1, { blk: false, s: 200, p: "/" }), event(2, { s: 404, blk: false, p: "/gone" })] },
    });
    const { user, unmount } = await renderRoute("/logs");
    await screen.findByText("Waiting for requests…");
    await user.click(screen.getByRole("tab", { name: "Stats" }));
    expect(await screen.findByText(/updates live/)).toBeInTheDocument();
    const requests = () => screen.getAllByText("Requests", { selector: "p" })[0]!.nextElementSibling!;
    expect(requests()).toHaveTextContent("2");

    act(() => stream().emit("message", JSON.stringify(event(3))));
    await waitFor(() => expect(requests()).toHaveTextContent("3"), { timeout: 2000 });
    expect(within(screen.getByRole("region", { name: "Block reasons" })).getByText("waf_blocked #942100")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Not found (404)" })).getByText("/gone")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Countries" })).getByText("Germany (DE)")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Table" }));
    await user.click(screen.getByRole("tab", { name: "Stats" }));
    expect(api.calls("GET /logs/stats")).toHaveLength(1);
    unmount();

    mockApi({ ...base, [liveList]: { total: 0, logs: [] }, "GET /logs/stats": pending });
    await renderRoute("/logs");
    expect(await screen.findByRole("tab", { name: "Stats" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Loading the last hour…")).toBeInTheDocument();
  });

  it("docks the inspector on wide screens and opens rows from the keyboard", async () => {
    vi.spyOn(window, "matchMedia").mockImplementation((query: string) => ({ matches: true, media: query, addEventListener: () => {}, removeEventListener: () => {} }) as unknown as MediaQueryList);
    const sparse: LogDetail = {
      ...detail, request_id: "", query: "", country: "", asn: 0, org: "", tls_version: "", tls_cipher: "", action: "", status: 502,
      bot_score: 3, ja4: "t13d1516h2", headers: {}, has_threat_score: false, cache_status: "HIT", proxy_ip: "",
    };
    const api = mockApi({
      ...base,
      [liveList]: { total: 1, logs: [row(7, { Blocked: true, RuleID: 942100, Status: 502 })] },
      "GET /logs/7": sparse,
      "POST /logs/feedback/7": () => (api.calls("POST /logs/feedback/7").length === 1 ? reply(500, {}) : { status: "ok" }),
      "POST /logs/exception/7": { service: "shop" },
    });
    const { user } = await renderRoute("/logs");
    expect(await screen.findByText("Select a request to inspect it")).toBeInTheDocument();
    const r = (await screen.findAllByRole("button", { name: /\/p7/ }))[0]!;
    r.focus();
    await user.keyboard("a");
    expect(api.calls("GET /logs/7")).toHaveLength(0);
    await user.keyboard("{Enter}");
    expect(await screen.findByText("No headers captured.")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("Rule #942100 · blocked")).toBeInTheDocument();
    expect(screen.getByText("Plaintext / terminated upstream")).toBeInTheDocument();
    expect(screen.getByText("(none)")).toBeInTheDocument();
    expect(screen.getByText(/cache HIT/)).toBeInTheDocument();
    expect(screen.getByText("t13d1516h2")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Correct block" }));
    expect(await screen.findByText("Failed to save. Try again.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Correct block" }));
    expect(await screen.findByText("Marked correct.")).toBeInTheDocument();

    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    await user.click(screen.getByRole("button", { name: "Create exception" }));
    expect(api.calls("POST /logs/exception/7")).toHaveLength(0);
    confirm.mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Create exception" }));
    expect(await screen.findByText("Rule disabled for shop.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Close request details" }));
    expect(await screen.findByText("Select a request to inspect it")).toBeInTheDocument();
  });

  it("switches tabs with the arrow keys and says when the last hour can't load", async () => {
    mockApi({ ...base, [liveList]: { total: 0, logs: [] }, "GET /logs/stats": reply(500, {}) });
    const { user } = await renderRoute("/logs");
    await screen.findByText("Waiting for requests…");
    screen.getByRole("tab", { name: "Table" }).focus();
    await user.keyboard("{Enter}{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Stats" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Stats" })).toHaveFocus();
    expect(await screen.findByText(/Could not load the last hour/)).toBeInTheDocument();
    act(() => stream().emit("message", JSON.stringify(event(1, { rule: undefined, cc: "", ms: 0 }))));
    await waitFor(() => expect(within(screen.getByRole("region", { name: "Countries" })).getByText("Unknown")).toBeInTheDocument(), { timeout: 2000 });
    await user.keyboard("{ArrowLeft}");
    expect(screen.getByRole("tab", { name: "Table" })).toHaveAttribute("aria-selected", "true");
  });
});
