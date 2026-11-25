import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { WAFPage } from "./api";

const at = "2026-11-24T10:00:00Z";
const rule = `SecRule ARGS "@contains evil" "id:1000001,phase:2,deny"`;

const page: WAFPage = {
  vpatches: [
    { cve: "CVE-2026-0001", product: "Acme Gateway", reference: "https://nvd.example/1", added: "2026-10-01", rule_id: 2000001, hits: 1234, global_off: false, off_for: ["shop"] },
    { cve: "CVE-2026-0002", product: "Widget CMS", reference: "https://nvd.example/2", added: "2026-09-01", rule_id: 2000002, hits: 0, global_off: true, off_for: [] },
  ],
  suggestions: [{ rule_id: 941100, service: "shop", false_positives: 6, last_marked: at }],
  feedback: { threshold: 5, window_days: 7 },
  top_rules: [
    { rule_id: 942100, hits: 50, last_seen: at, disabled: false },
    { rule_id: 920420, hits: 3, last_seen: at, disabled: true },
  ],
  custom: [{ id: 4, service: "", rule, note: "evil probe", enabled: true, created_at: at }],
  exceptions: [
    { id: 1, rule_id: 920420, service: "", reason: "", created_at: at },
    { id: 7, rule_id: 2000001, service: "shop", reason: "Virtual patch CVE-2026-0001 turned off", created_at: at },
  ],
  services: ["shop", "api"],
  waf_enabled: false,
};

const base = { "GET /api/notifications": { unread: 0, blocks: [] }, "GET /api/waf-rules": page };
const card = (title: string) => within(screen.getByRole("heading", { name: title }).closest("section")!);
const findCard = async (title: string) => within((await screen.findByRole("heading", { name: title })).closest("section")!);
const confirm = async (user: { click: (e: Element) => Promise<void> }, label: string) => user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: label }));

describe("WAF rules page", () => {
  it("lists patches, suggestions, top rules, custom rules and exceptions", async () => {
    mockApi(base);
    await renderRoute("/waf-rules");
    expect(await screen.findByRole("link", { name: "CVE-2026-0001" })).toHaveAttribute("href", "https://nvd.example/1");
    expect(screen.getByRole("heading", { name: "Tune CRS enforcement without losing visibility." })).toBeInTheDocument();
    expect(screen.getByText("WAF disabled")).toBeInTheDocument();
    expect(screen.getByText("1 of 2 patches on")).toBeInTheDocument();
    expect(screen.getByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("Off: shop")).toBeInTheDocument();
    expect(screen.getByText("Off everywhere")).toBeInTheDocument();
    expect(card("Suggested Exceptions").getByText(/Marked false positive 6 times/)).toBeInTheDocument();
    expect(card("Top Firing Rules").getAllByText("Disabled")).toHaveLength(1);
    expect(card("Top Firing Rules").getAllByRole("button", { name: "Disable" })).toHaveLength(1);
    expect(card("Custom Rules").getByText(rule)).toBeInTheDocument();
    expect(card("Rule Exceptions").getByText("No reason given", { exact: false })).toBeInTheDocument();
    expect(card("Rule Exceptions").getByText("2 exceptions")).toBeInTheDocument();
  });

  it("shows loading, empty and error states", async () => {
    mockApi({ ...base, "GET /api/waf-rules": pending });
    const r = await renderRoute("/waf-rules");
    expect(screen.getAllByText("Loading…")).toHaveLength(5);
    r.unmount();

    mockApi({ ...base, "GET /api/waf-rules": { ...page, vpatches: [], suggestions: [], top_rules: [], custom: [], exceptions: [], waf_enabled: true } });
    const r2 = await renderRoute("/waf-rules");
    expect(await screen.findByText("All WAF rules are active")).toBeInTheDocument();
    expect(screen.getByText("No custom rules yet")).toBeInTheDocument();
    expect(screen.getByText("No WAF blocks recorded yet")).toBeInTheDocument();
    expect(screen.getByText(/No suggestions yet/)).toBeInTheDocument();
    expect(screen.queryByText("WAF disabled")).toBeNull();
    r2.unmount();

    mockApi({ ...base, "GET /api/waf-rules": reply(500, {}) });
    await renderRoute("/waf-rules");
    expect(await screen.findAllByRole("alert")).toHaveLength(5);
    expect(screen.queryByText("All WAF rules are active")).toBeNull();
  });

  it("disables a rule, showing field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/waf-rules/exceptions": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { rule_id: "Enter the rule id, a positive number." } }) : reply(201)),
    });
    const { user } = await renderRoute("/waf-rules");
    const c = await findCard("Disable Rule");
    await user.click(await c.findByRole("button", { name: "Disable Rule" }));
    expect(await c.findByText("Enter the rule id, a positive number.")).toBeInTheDocument();

    fail = false;
    await user.type(c.getByLabelText("CRS rule ID"), "942100");
    await user.selectOptions(c.getByLabelText("Scope"), "api");
    await user.type(c.getByLabelText("Reason (optional)"), "login form");
    await user.click(c.getByRole("button", { name: "Disable Rule" }));
    await vi.waitFor(() => expect(c.getByLabelText("CRS rule ID")).toHaveValue(null));
    expect(api.calls("POST /api/waf-rules/exceptions")[1]!.json).toEqual({ rule_id: 942100, service: "api", reason: "login form" });
  });

  it("dry runs and saves a custom rule, with field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/waf-rules/dry-run": () =>
        fail
          ? reply(400, { error: "invalid", message: "x", fields: { rule: "The rule doesn't compile: bad" } })
          : { replayed: 500, hits: [{ id: 9, app: "shop", method: "GET", host: "shop.test", target: "/?q=evil", before: { blocked: false, rule_id: 0 }, after: { blocked: true, rule_id: 1000001 } }] },
      "POST /api/waf-rules/custom": () => (fail ? reply(409, { error: "conflict", message: "Something else went wrong." }) : reply(201)),
    });
    const { user } = await renderRoute("/waf-rules");
    const c = await findCard("Write Custom Rule");
    await user.type(c.getByLabelText("Rule"), "nope");
    await user.click(c.getByRole("button", { name: "Dry run" }));
    expect(await c.findByText("The rule doesn't compile: bad")).toBeInTheDocument();

    fail = false;
    await user.clear(c.getByLabelText("Replay last N requests"));
    await user.type(c.getByLabelText("Replay last N requests"), "50");
    await user.click(c.getByRole("button", { name: "Dry run" }));
    expect(await c.findByText(/Replayed 500 requests/)).toBeInTheDocument();
    expect(c.getByText("Block · 1000001")).toBeInTheDocument();
    expect(c.getByText("Pass")).toBeInTheDocument();
    expect(api.calls("POST /api/waf-rules/dry-run")[1]!.json).toEqual({ rule: "nope", limit: 50 });

    fail = true;
    await user.click(c.getByRole("button", { name: "Save rule" }));
    expect(await c.findByRole("alert")).toHaveTextContent("Something else went wrong.");
    fail = false;
    await user.selectOptions(c.getByLabelText("Scope"), "shop");
    await user.type(c.getByLabelText("Note (optional)"), "n");
    await user.click(c.getByRole("button", { name: "Save rule" }));
    await vi.waitFor(() => expect(c.getByLabelText("Rule")).toHaveValue(""));
    expect(api.calls("POST /api/waf-rules/custom")[1]!.json).toEqual({ rule: "nope", service: "shop", note: "n" });
  });

  it("edits a custom rule in place and cancels an edit", async () => {
    const api = mockApi({ ...base, "PUT /api/waf-rules/custom/4": reply(204) });
    const { user } = await renderRoute("/waf-rules");
    // The editor remounts per rule, so look its card up again each time.
    const editor = () => card("Write Custom Rule");
    await user.click(await screen.findByRole("button", { name: "Edit evil probe" }));
    expect(editor().getByText("Editing #4")).toBeInTheDocument();
    expect(editor().getByLabelText("Rule")).toHaveValue(rule);
    await user.click(editor().getByRole("button", { name: "Cancel edit" }));
    expect(editor().getByLabelText("Rule")).toHaveValue("");

    await user.click(screen.getByRole("button", { name: "Edit evil probe" }));
    await user.click(editor().getByRole("button", { name: "Update rule" }));
    await vi.waitFor(() => expect(editor().queryByText("Editing #4")).toBeNull());
    expect(api.calls("PUT /api/waf-rules/custom/4")[0]!.json).toEqual({ rule, service: "", note: "evil probe" });
  });

  it("turns off a patch, disables a top rule and takes a suggestion", async () => {
    const api = mockApi({ ...base, "POST /api/waf-rules/exceptions": reply(201) });
    const { user } = await renderRoute("/waf-rules");
    await user.selectOptions(await screen.findByLabelText("Turn CVE-2026-0001 off for"), "api");
    await user.click(screen.getByRole("button", { name: "Turn off" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("api stops blocking this exploit");
    await confirm(user, "Turn off");

    await user.click(card("Top Firing Rules").getByRole("button", { name: "Disable" }));
    await confirm(user, "Disable");
    await user.click(screen.getByRole("button", { name: "Add exception" }));
    await vi.waitFor(() => expect(api.calls("POST /api/waf-rules/exceptions")).toHaveLength(3));
    expect(api.calls("POST /api/waf-rules/exceptions").map((c) => c.json)).toEqual([
      { rule_id: 2000001, service: "api", reason: "Virtual patch CVE-2026-0001 turned off" },
      { rule_id: 942100, service: "", reason: "" },
      { rule_id: 941100, service: "shop", reason: "Suggested: 6 false-positive marks in the last 7 days" },
    ]);
  });

  it("saves the suggestion thresholds and shows their errors", async () => {
    let fail = true;
    const api = mockApi({ ...base, "PUT /api/waf-rules/feedback": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { window_days: "Use 1 to 90 days." } }) : reply(204)) });
    const { user } = await renderRoute("/waf-rules");
    const c = card("Suggested Exceptions");
    await user.clear(await c.findByLabelText("Window (days)"));
    await user.type(c.getByLabelText("Window (days)"), "30");
    await user.click(c.getByRole("button", { name: "Save" }));
    expect(await c.findByText("Use 1 to 90 days.")).toBeInTheDocument();
    fail = false;
    await user.clear(c.getByLabelText("False-positive marks"));
    await user.type(c.getByLabelText("False-positive marks"), "3");
    await user.click(c.getByRole("button", { name: "Save" }));
    await vi.waitFor(() => expect(api.calls("PUT /api/waf-rules/feedback")).toHaveLength(2));
    expect(api.calls("PUT /api/waf-rules/feedback")[1]!.json).toEqual({ threshold: 3, window_days: 30 });
  });

  it("turns a custom rule off at once and back when the server refuses", async () => {
    let answer: () => unknown = () => reply(500, { error: "internal", message: "Disk is full." });
    const api = mockApi({ ...base, "PUT /api/waf-rules/custom/4/enabled": () => answer() });
    const { user } = await renderRoute("/waf-rules");
    await user.click(await screen.findByRole("checkbox", { name: "evil probe on" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Disk is full.");
    expect(screen.getByRole("checkbox", { name: "evil probe on" })).toBeChecked();
    expect(api.calls("PUT /api/waf-rules/custom/4/enabled")[0]!.json).toEqual({ enabled: false });

    answer = pending;
    await user.click(screen.getByRole("checkbox", { name: "evil probe on" }));
    await vi.waitFor(() => expect(screen.getByRole("checkbox", { name: "evil probe on" })).not.toBeChecked());
  });

  it("deletes a custom rule and re-enables exceptions after a confirmation", async () => {
    const api = mockApi({
      ...base,
      "DELETE /api/waf-rules/custom/4": reply(204),
      "DELETE /api/waf-rules/exceptions/global/1": reply(204),
      "DELETE /api/waf-rules/exceptions/services/7": reply(500, { error: "internal", message: "Nope." }),
    });
    const { user } = await renderRoute("/waf-rules");
    await user.click(await screen.findByRole("button", { name: "Delete evil probe" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(api.calls("DELETE /api/waf-rules/custom/4")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Delete evil probe" }));
    await confirm(user, "Delete");

    await user.click(screen.getByRole("button", { name: "Re-enable rule 920420 everywhere" }));
    await confirm(user, "Re-enable");
    await user.click(screen.getByRole("button", { name: "Re-enable rule 2000001 for shop" }));
    await confirm(user, "Re-enable");
    expect(await card("Rule Exceptions").findByRole("alert")).toHaveTextContent("Nope.");
    expect(api.calls("DELETE /api/waf-rules/custom/4")).toHaveLength(1);
    expect(api.calls("DELETE /api/waf-rules/exceptions/global/1")).toHaveLength(1);
  });

  it("is read-only for viewers", async () => {
    asRole("viewer");
    mockApi(base);
    await renderRoute("/waf-rules");
    expect(await screen.findByText("evil probe", { exact: false })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Disable Rule" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Write Custom Rule" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Turn off|Disable|Add exception|Edit|Delete|Re-enable|Save/ })).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(card("Custom Rules").getByText("On")).toBeInTheDocument();
    expect(screen.getByLabelText("Window (days)")).toBeDisabled();
  });
});
