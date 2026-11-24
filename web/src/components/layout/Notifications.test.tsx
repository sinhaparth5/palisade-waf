import { act, screen } from "@testing-library/react";
import { Toaster } from "sonner";
import { mockApi, reply } from "@/test/api-mock";
import { FakeEventSource } from "@/test/events";
import { renderWithProviders } from "@/test/render";
import { Notifications, blockTitle } from "./Notifications";

const block = { time: "2026-11-24T10:00:00Z", ip: "198.51.100.7", country: "NL", method: "POST", path: "/login", app: "shop", rule_id: 942100, action: "waf_blocked" };

describe("notifications", () => {
  it("shows the unread count and the latest blocks", async () => {
    mockApi({ "GET /api/notifications": { unread: 12, blocks: [block, { ...block, ip: "203.0.113.1", rule_id: 0 }] } });
    const { user } = renderWithProviders(<Notifications />);
    const bell = await screen.findByRole("button", { name: "Notifications, 12 unread" });
    expect(bell).toHaveTextContent("9+");
    await user.click(bell);
    expect(await screen.findByText("198.51.100.7")).toBeInTheDocument();
    expect(screen.getByText(/shop · .* · rule #942100/)).toBeInTheDocument();
    expect(screen.getAllByText(/rule #/)).toHaveLength(1); // rule 0: none shown
    expect(screen.getByRole("link", { name: /view all blocked/i })).toHaveAttribute("href", "/admin/logs?status=blocked&mode=history");
  });

  it("marks all as read with a POST", async () => {
    const api = mockApi({ "GET /api/notifications": { unread: 3, blocks: [block] }, "POST /api/notifications/seen": reply(204) });
    const { user } = renderWithProviders(<Notifications />);
    await user.click(await screen.findByRole("button", { name: "Notifications, 3 unread" }));
    await user.click(screen.getByRole("button", { name: "Mark all as read" }));
    expect(await screen.findByRole("button", { name: "Notifications" })).toBeInTheDocument();
    expect(api.calls("POST /api/notifications/seen")[0]!.headers.get("X-CSRF-Token")).toBe("test-csrf");
  });

  it("says when there is nothing, and when loading failed", async () => {
    mockApi({ "GET /api/notifications": { unread: 0, blocks: [] } });
    const { user, unmount } = renderWithProviders(<Notifications />);
    await user.click(screen.getByRole("button", { name: "Notifications" }));
    expect(await screen.findByText("No blocked requests yet.")).toBeInTheDocument();
    unmount();

    mockApi({ "GET /api/notifications": reply(500, { error: "db" }) });
    const r = renderWithProviders(<Notifications />);
    await r.user.click(screen.getByRole("button", { name: "Notifications" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load");
  });

  it("follows the live stream: count updates and a toast per block", async () => {
    mockApi({ "GET /api/notifications": { unread: 1, blocks: [] } });
    const { unmount } = renderWithProviders(
      <>
        <Notifications />
        <Toaster />
      </>,
    );
    await screen.findByRole("button", { name: "Notifications, 1 unread" });
    const stream = FakeEventSource.last!;
    expect(stream.url).toBe("/admin/api/notifications/stream");

    act(() => stream.emit("count", "4"));
    expect(await screen.findByRole("button", { name: "Notifications, 4 unread" })).toBeInTheDocument();
    act(() => stream.emit("toast", JSON.stringify({ action: "geo_blocked", ip: "192.0.2.9", country: "CN", method: "GET", path: "/x" })));
    expect(await screen.findByText("Country Blocked")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.9 · CN — GET /x")).toBeInTheDocument();
    act(() => stream.emit("toast", JSON.stringify({ action: "waf_blocked", ip: "192.0.2.10", country: "", method: "", path: "" })));
    expect(await screen.findByText("192.0.2.10 — GET /")).toBeInTheDocument();

    unmount();
    expect(stream.closed).toBe(true);
  });

  it("ignores a count before the first load", () => {
    mockApi({ "GET /api/notifications": () => new Promise(() => {}) });
    renderWithProviders(<Notifications />);
    act(() => FakeEventSource.last!.emit("count", "4"));
    expect(screen.getByRole("button", { name: "Notifications" })).toBeInTheDocument();
  });

  it.each([
    ["rate_limited:adaptive", "Too Many Requests"],
    ["geo_blocked", "Country Blocked"],
    ["ip_blocked", "IP Address Blocked"],
    ["waf_blocked", "Request Blocked"],
  ])("titles %s as %s", (action, title) => expect(blockTitle(action)).toBe(title));
});
