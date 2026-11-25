import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import { since, type IntelPage, type Source } from "./api";

const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();

const tor: Source = { id: 1, label: "Tor Exit Nodes", kind: "feed", url: "https://check.torproject.org/torbulkexitlist", interval_hours: 6, enabled: true, last_synced_at: ago(125), last_error: "", ips: 1200, ranges: 0, push: false };
const lapi: Source = { id: 2, label: "CrowdSec", kind: "crowdsec", url: "http://lapi:8080", interval_hours: 1, enabled: true, last_synced_at: ago(0), last_error: "", ips: 40, ranges: 3, push: true };
const broken: Source = { id: 3, label: "Mirror", kind: "feed", url: "https://intel.example/list.txt", interval_hours: 24, enabled: false, last_synced_at: "", last_error: "fetch: 503 Service Unavailable", ips: 0, ranges: 0, push: false };

const page: IntelPage = {
  sources: [tor, lapi, broken],
  presets: [
    { label: "Tor Exit Nodes", url: tor.url, interval_hours: 6 },
    { label: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop.txt", interval_hours: 24 },
  ],
};

const base = { "GET /api/notifications": { unread: 0, blocks: [] }, "GET /api/threat-intel": page };

describe("threat intel page", () => {
  it("lists every source with its counts, sync state and errors", async () => {
    mockApi(base);
    await renderRoute("/threat-intel");
    expect(await screen.findByText("Pushes autobans")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Curated intelligence, enforced locally." })).toBeInTheDocument();
    expect(screen.getByText("2 of 3 sources active")).toBeInTheDocument();
    expect(screen.getByText("1,243 entries blocking")).toBeInTheDocument();
    expect(screen.getByText("1 failing to sync")).toBeInTheDocument();
    expect(screen.getByText("3 feeds")).toBeInTheDocument();
    expect(screen.getByText("1,200 IPs")).toBeInTheDocument();
    expect(screen.getByText("3 ranges")).toBeInTheDocument();
    expect(screen.getByText("Synced 2 h ago · every 6 h")).toBeInTheDocument();
    expect(screen.getByText("Synced just now")).toBeInTheDocument();
    expect(screen.getByText("Never synced · every 24 h")).toBeInTheDocument();
    expect(screen.getByText("fetch: 503 Service Unavailable")).toBeInTheDocument();
    expect(screen.getByText("No entries")).toBeInTheDocument();
    expect(screen.getByText("Paused")).toBeInTheDocument();
  });

  it("shows loading, empty and error states", async () => {
    mockApi({ ...base, "GET /api/threat-intel": pending });
    const r = await renderRoute("/threat-intel");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    r.unmount();

    mockApi({ ...base, "GET /api/threat-intel": { sources: [], presets: [] } });
    const r2 = await renderRoute("/threat-intel");
    expect(await screen.findByText("No feeds yet. Add one or pick a preset.")).toBeInTheDocument();
    expect(screen.getByText("0 feeds")).toBeInTheDocument();
    r2.unmount();

    mockApi({ ...base, "GET /api/threat-intel": reply(500, {}) });
    await renderRoute("/threat-intel");
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load the feeds");
    expect(screen.queryByText(/No feeds yet/)).toBeNull();
  });

  it("adds a feed, showing field errors, and adds a preset not yet added", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/threat-intel": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { url: "Use an absolute http:// or https:// URL." } }) : reply(201)),
    });
    const { user } = await renderRoute("/threat-intel");
    expect(await screen.findByRole("button", { name: /Tor Exit Nodes\s*Added/ })).toBeDisabled();

    const card = within(screen.getByText("Quick-add presets").closest("section")!);
    await user.type(card.getAllByLabelText("Label")[0]!, "Mine");
    await user.type(card.getByLabelText("URL"), "ftp://x");
    await user.clear(card.getByLabelText("Sync every (hours)"));
    await user.type(card.getByLabelText("Sync every (hours)"), "12");
    await user.click(card.getByRole("button", { name: "Add Feed" }));
    expect(await screen.findByText("Use an absolute http:// or https:// URL.")).toBeInTheDocument();
    expect(card.getByLabelText("URL")).toHaveAttribute("aria-invalid", "true");
    expect(api.calls("POST /api/threat-intel")[0]!.json).toEqual({ label: "Mine", url: "ftp://x", interval_hours: 12 });

    fail = false;
    await user.click(card.getByRole("button", { name: "Add Feed" }));
    await vi.waitFor(() => expect(card.getByLabelText("URL")).toHaveValue(""));

    await user.click(screen.getByRole("button", { name: /Spamhaus DROP/ }));
    await vi.waitFor(() => expect(api.calls("POST /api/threat-intel")).toHaveLength(3));
    expect(api.calls("POST /api/threat-intel")[2]!.json).toEqual(page.presets[1]);
  });

  it("adds a CrowdSec LAPI with its secrets and shows their field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/threat-intel/crowdsec": () =>
        fail ? reply(400, { error: "invalid", message: "x", fields: { machine_password: "Enter the machine password, or clear the login." } }) : reply(201),
    });
    const { user } = await renderRoute("/threat-intel");
    await user.type(await screen.findByLabelText("LAPI URL"), "http://lapi:8080");
    await user.type(screen.getByLabelText("Bouncer API key"), "key");
    await user.type(screen.getByLabelText("Machine login (optional)"), "palisade");
    await user.click(screen.getByRole("button", { name: "Add LAPI" }));
    expect(await screen.findByText("Enter the machine password, or clear the login.")).toBeInTheDocument();
    expect(screen.getByLabelText("Machine password (optional)")).toHaveAttribute("aria-invalid", "true");

    fail = false;
    await user.type(screen.getByLabelText("Machine password (optional)"), "pw");
    await user.click(screen.getByRole("button", { name: "Add LAPI" }));
    await vi.waitFor(() => expect(screen.getByLabelText("Bouncer API key")).toHaveValue(""));
    expect(api.calls("POST /api/threat-intel/crowdsec")[1]!.json).toEqual({ label: "CrowdSec", url: "http://lapi:8080", api_key: "key", machine_login: "palisade", machine_password: "pw" });
  });

  it("syncs one source and shows its new state", async () => {
    const api = mockApi({ ...base, "POST /api/threat-intel/3/sync": { ...broken, last_error: "", last_synced_at: ago(0), ips: 7 } });
    const { user } = await renderRoute("/threat-intel");
    await user.click(await screen.findByRole("button", { name: "Sync Mirror now" }));
    expect(await screen.findByText("7 IPs")).toBeInTheDocument();
    expect(screen.queryByText("fetch: 503 Service Unavailable")).toBeNull();
    expect(api.calls("POST /api/threat-intel/3/sync")[0]!.headers.get("X-CSRF-Token")).toBeTruthy();
  });

  it("pauses at once and puts the source back when the server refuses", async () => {
    let answer: () => unknown = () => reply(500, { error: "internal", message: "Disk is full." });
    const api = mockApi({ ...base, "PUT /api/threat-intel/1": () => answer() });
    const { user } = await renderRoute("/threat-intel");
    await user.click(await screen.findByRole("button", { name: "Pause Tor Exit Nodes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Disk is full.");
    expect(screen.getByRole("button", { name: "Pause Tor Exit Nodes" })).toBeInTheDocument();
    expect(api.calls("PUT /api/threat-intel/1")[0]!.json).toEqual({ enabled: false });

    answer = pending;
    await user.click(screen.getByRole("button", { name: "Pause Tor Exit Nodes" }));
    expect(await screen.findByRole("button", { name: "Resume Tor Exit Nodes" })).toBeInTheDocument();
    expect(screen.getAllByText("Paused")).toHaveLength(2);
  });

  it("deletes after a confirmation", async () => {
    const api = mockApi({ ...base, "DELETE /api/threat-intel/2": reply(204) });
    const { user } = await renderRoute("/threat-intel");
    await user.click(await screen.findByRole("button", { name: "Delete CrowdSec" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete CrowdSec?" });
    expect(dialog).toHaveTextContent("bouncer key and machine credentials are removed");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.calls("DELETE /api/threat-intel/2")).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Delete Tor Exit Nodes" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("You can add the feed again later");
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "Delete CrowdSec" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete" }));
    await vi.waitFor(() => expect(api.calls("DELETE /api/threat-intel/2")).toHaveLength(1));
  });

  it("is read-only for viewers", async () => {
    asRole("viewer");
    mockApi(base);
    await renderRoute("/threat-intel");
    expect(await screen.findByText("Pushes autobans")).toBeInTheDocument();
    expect(screen.queryByText("Add Feed")).toBeNull();
    expect(screen.queryByText("CrowdSec LAPI")).toBeNull();
    expect(screen.queryByRole("button", { name: /Sync|Pause|Resume|Delete/ })).toBeNull();
  });
});

describe("since", () => {
  const now = Date.parse("2026-11-25T12:00:00Z");
  it.each([
    ["", "Never synced"],
    ["2026-11-25T11:59:30Z", "Synced just now"],
    ["2026-11-25T12:05:00Z", "Synced just now"],
    ["2026-11-25T11:15:00Z", "Synced 45 min ago"],
    ["2026-11-24T12:00:00Z", "Synced 24 h ago"],
    ["2026-11-20T12:00:00Z", "Synced 5 days ago"],
  ])("%s → %s", (at, label) => expect(since(at, now)).toBe(label));
});
