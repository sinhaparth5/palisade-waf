import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { GeoRule } from "./api";

const rules: GeoRule[] = [
  { ID: 1, AppName: "", CountryCode: "CN", RuleType: "block", CreatedAt: "2026-11-24T10:00:00Z" },
  { ID: 2, AppName: "shop", CountryCode: "US", RuleType: "allow", CreatedAt: "2026-11-24T10:00:00Z" },
];

const base = {
  "GET /api/notifications": { unread: 0, blocks: [] },
  "GET /api/geo-rules": rules,
  "GET /api/logs/apps": ["shop"],
};

describe("geo rules page", () => {
  it("lists rules with country names and counts", async () => {
    mockApi(base);
    await renderRoute("/geo-rules");
    expect(await screen.findByText("China")).toBeInTheDocument();
    expect(screen.getByText("United States")).toBeInTheDocument();
    expect(screen.getByText("2 rules")).toBeInTheDocument();
    expect(screen.getByText(/shop ·/)).toBeInTheDocument();
    expect(screen.getByText("GeoIP database bundled")).toBeInTheDocument();
  });

  it("shows loading, empty and error states", async () => {
    mockApi({ ...base, "GET /api/geo-rules": pending });
    const r = await renderRoute("/geo-rules");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    r.unmount();

    mockApi({ ...base, "GET /api/geo-rules": [] });
    const r2 = await renderRoute("/geo-rules");
    expect(await screen.findByText("No geo rules yet")).toBeInTheDocument();
    r2.unmount();

    mockApi({ ...base, "GET /api/geo-rules": reply(500, {}) });
    await renderRoute("/geo-rules");
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load the geo rules");
  });

  it("adds countries picked from the list", async () => {
    const api = mockApi({ ...base, "POST /api/geo-rules": reply(201, { added: 2 }) });
    const { user } = await renderRoute("/geo-rules");
    await screen.findByText("China");
    expect(screen.getByRole("button", { name: "Add" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: /Choose countries/ }));
    await user.type(screen.getByPlaceholderText("Search countries…"), "ru");
    await user.click(await screen.findByRole("option", { name: /Russia/ }));
    await user.clear(screen.getByPlaceholderText("Search countries…"));
    await user.type(screen.getByPlaceholderText("Search countries…"), "IR");
    await user.click(await screen.findByRole("option", { name: /Iran/ }));
    await user.keyboard("{Escape}");
    expect(within(screen.getByRole("list", { name: "Chosen countries" })).getAllByRole("button")).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: "Add" }));
    await vi.waitFor(() => expect(api.calls("GET /api/geo-rules").length).toBeGreaterThan(1));
    expect(api.calls("POST /api/geo-rules")[0]!.json).toEqual({ country_code: ["RU", "IR"], app_name: "", rule_type: "block" });
    expect(screen.queryByRole("list", { name: "Chosen countries" })).not.toBeInTheDocument();
  });

  it("unpicks countries from the list or the chips, and shows a server error", async () => {
    const api = mockApi({ ...base, "POST /api/geo-rules": reply(400, { error: "invalid", message: "x", fields: { country_code: '"ZZ" is not a two-letter ISO country code.' } }) });
    const { user } = await renderRoute("/geo-rules");
    await user.click(await screen.findByRole("button", { name: /Choose countries/ }));
    const search = screen.getByPlaceholderText("Search countries…");
    for (const q of ["germany", "france", "germany"]) {
      await user.clear(search);
      await user.type(search, q);
      await user.click(await screen.findByRole("option", { name: new RegExp(q, "i") }));
    }
    await user.keyboard("{Escape}");
    const chips = screen.getByRole("list", { name: "Chosen countries" });
    expect(within(chips).getAllByRole("button")).toHaveLength(1);
    await user.click(within(chips).getByRole("button", { name: "Remove France" }));
    expect(screen.queryByRole("list", { name: "Chosen countries" })).toBeNull();

    await user.click(screen.getByRole("button", { name: /Choose countries/ }));
    await user.type(screen.getByPlaceholderText("Search countries…"), "japan");
    await user.click(await screen.findByRole("option", { name: /Japan/ }));
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText('"ZZ" is not a two-letter ISO country code.')).toBeInTheDocument();
    expect(api.calls("POST /api/geo-rules")[0]!.json).toMatchObject({ country_code: ["JP"] });
  }, 15_000); // types into a ~250-country list: past 5s under coverage with every file in parallel

  it("drops removed rules at once and puts them back if the server refuses", async () => {
    let answer: unknown = reply(500, {});
    mockApi({ ...base, "POST /api/geo-rules/remove": () => answer });
    const { user } = await renderRoute("/geo-rules");
    await user.click(await screen.findByRole("button", { name: "Remove China" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't remove. Try again.");
    expect(screen.getByText("China")).toBeInTheDocument();

    // In flight: already gone.
    answer = pending() as never;
    await user.click(screen.getByRole("button", { name: "Remove China" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove" }));
    await vi.waitFor(() => expect(screen.queryByText("China")).not.toBeInTheDocument());
  });

  it("is read-only for viewers", async () => {
    asRole("viewer");
    mockApi({ "GET /api/notifications": base["GET /api/notifications"], "GET /api/geo-rules": rules });
    await renderRoute("/geo-rules");
    expect(await screen.findByText("China")).toBeInTheDocument();
    expect(screen.queryByText("Add Geo Rules")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
  });
});
