import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { setBoot } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { Dashboard } from "./api";
import { meterCells } from "./DashboardPage";

const row = { ID: 1, Timestamp: "2026-11-24T10:00:00Z", AppName: "shop", RealIP: "198.51.100.7", Country: "NL", Method: "POST", Host: "shop.example", Path: "/login", Status: 403, Blocked: true, RuleID: 942100, Action: "waf_blocked", UserAgent: "", Duration: 12 };

const dash: Dashboard = {
  requests_today: 1234,
  blocked_today: 56,
  blocked_all: 9001,
  block_rate: 4,
  challenged: 7,
  passed: 30,
  visitors: 88,
  glance: [{ label: "Requests/sec", value: "2.5", trend: "+10.0%" }],
  traffic: { labels: Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, "0")}:00`), allowed: Array(24).fill(1), blocked: Array(24).fill(0) },
  countries: [{ code: "NL", name: "Netherlands", count: 10 }],
  threats: [{ code: "CN", count: 5 }],
  enforcement: [{ label: "WAF rules", icon: "hgi-security-block", count: 3 }],
  services: [{ name: "shop", route: "shop.example", tls: "auto", healthy: false, known: true, cache: true }],
  recent: [{ ...row, ID: 2, Blocked: false, Status: 200, Path: "/" }],
  blocked: [row],
  changes: [{ ID: 1, TS: "2026-11-24T09:00:00Z", Actor: "owner@example.com", Action: "POST /services" }],
};

const notifications = { "GET /api/notifications": { unread: 0, blocks: [] } };

describe("dashboard page", () => {
  it("shows the day's numbers, services, blocks and changes", async () => {
    mockApi({ ...notifications, "GET /api/dashboard": dash });
    await renderRoute("/");
    expect(await screen.findByText("1234")).toBeInTheDocument();
    expect(screen.getByText("4%")).toBeInTheDocument();
    expect(screen.getByText("Netherlands")).toBeInTheDocument();
    expect(screen.getByText("Down")).toBeInTheDocument();
    expect(screen.getByText("Varnish")).toBeInTheDocument();
    expect(screen.getByText("waf_blocked · 942100")).toBeInTheDocument();
    expect(screen.getByText("POST /services")).toBeInTheDocument();
    expect(screen.getByText("9001")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /requests per hour/i })).toBeInTheDocument();
    // Links into the app stay in it; areas not moved yet go to their HTMX page.
    for (const l of screen.getAllByRole("link", { name: "Live feed" })) expect(l).toHaveAttribute("href", "/admin/app/logs");
    const blocked = screen.getByRole("heading", { name: "Latest blocked requests" }).parentElement!;
    expect(within(blocked).getByRole("link", { name: "View all" })).toHaveAttribute("href", "/admin/app/logs?status=blocked");
    expect(screen.getByRole("link", { name: "Geo rules" })).toHaveAttribute("href", "/admin/app/geo-rules");
  });

  it("says when there is nothing yet", async () => {
    mockApi({ ...notifications, "GET /api/dashboard": { ...dash, countries: [], threats: [], services: [], recent: [], blocked: [], changes: [] } });
    await renderRoute("/");
    expect(await screen.findByText("Nothing blocked yet")).toBeInTheDocument();
    expect(screen.getByText(/No requests yet/)).toBeInTheDocument();
    expect(screen.getByText(/No services yet/)).toBeInTheDocument();
    expect(screen.getByText("No changes yet")).toBeInTheDocument();
    expect(screen.getByText("No country data yet")).toBeInTheDocument();
  });

  it("shows healthy and unknown services, rule-less blocks and a switched-off WAF", async () => {
    setBoot({ waf: false });
    mockApi({
      ...notifications,
      "GET /api/dashboard": {
        ...dash,
        countries: [{ code: "NL", name: "Netherlands", count: 10 }, { code: "DE", name: "Germany", count: 1 }],
        traffic: { ...dash.traffic, blocked: Array(24).fill(1) },
        services: [
          { name: "api", route: "api.example", tls: "", healthy: true, known: true, cache: false },
          { name: "old", route: "old.example", tls: "custom", healthy: false, known: false, cache: false },
        ],
        blocked: [{ ...row, RuleID: 0, Action: "" }],
        recent: [row],
      },
    });
    await renderRoute("/");
    expect(await screen.findByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getAllByText("Off").length).toBeGreaterThan(1);
    expect(screen.getByText("none")).toBeInTheDocument();
    // The rule-less block in "Latest blocked", and the tag on the blocked recent row.
    expect(screen.getAllByText("blocked", { selector: "span" }).length).toBeGreaterThan(1);
  });

  it("shows loading, then an error rather than empty numbers", async () => {
    mockApi({ ...notifications, "GET /api/dashboard": pending });
    const { unmount } = await renderRoute("/");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    unmount();

    mockApi({ ...notifications, "GET /api/dashboard": reply(500, { error: "internal", message: "x" }) });
    await renderRoute("/");
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load the dashboard");
    expect(screen.queryByText("Overview")).toBeNull();
  });

  it.each([
    [0, 0, 0],
    [0, 10, 0],
    [1, 12, 1],
    [7, 12, 7],
    [12, 12, 12],
    [1, 1000, 1],
  ])("meter %i of %i fills %i cells", (count, max, want) => {
    expect(meterCells(count, max)).toBe(want);
  });
});
