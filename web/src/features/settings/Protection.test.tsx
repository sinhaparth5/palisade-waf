import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { Protection } from "./api";

const protection: Protection = {
  bot: { enabled: true, threshold: 8, ttl: 3600, captcha_provider: "turnstile", captcha_site_key: "site", captcha_secret_set: true, ai_training: "block", ai_search: "", ai_user: "allow" },
  rate_limit: { enabled: false, rps: 10, burst: 20 },
  trusted_ips: ["203.0.113.10"],
  varnish: { enabled: false, addr: "127.0.0.1:6081" },
};

const base = {
  "GET /api/notifications": { unread: 0, blocks: [] },
  "GET /api/settings/account": pending,
  "GET /api/settings/team": pending,
  "GET /api/settings/protection": protection,
};
const card = async (title: string) => within((await screen.findByRole("heading", { name: title })).closest("section")!);

describe("settings: protection and infrastructure", () => {
  it("shows a failed read", async () => {
    mockApi({ ...base, "GET /api/settings/protection": reply(500, {}) });
    await renderRoute("/settings");
    expect(await within(screen.getByRole("region", { name: "Protection" })).findByRole("alert")).toHaveTextContent("Couldn't load these settings");
  });

  it("saves bot protection, keeping a blank secret, and shows field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "PUT /api/settings/bot": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { threshold: "Between 1 and 100." } }) : reply(204)),
    });
    const { user } = await renderRoute("/settings");
    const c = await card("Bot Protection");
    expect(c.getByLabelText("Secret key (saved; blank keeps it)")).toHaveValue("");
    await user.selectOptions(c.getByLabelText("AI search"), "challenge");
    await user.click(c.getByRole("button", { name: /Save/ }));
    expect(await c.findByText("Between 1 and 100.")).toBeInTheDocument();
    fail = false;
    await user.click(c.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/bot")).toHaveLength(2));
    expect(api.calls("PUT /api/settings/bot")[1]!.json).toEqual({
      enabled: true,
      threshold: 8,
      ttl: 3600,
      captcha_provider: "turnstile",
      captcha_site_key: "site",
      captcha_secret: "",
      ai_training: "block",
      ai_search: "challenge",
      ai_user: "allow",
    });
  });

  it("saves the rate limit, trusted IPs and Varnish", async () => {
    const api = mockApi({
      ...base,
      "PUT /api/settings/rate-limit": reply(204),
      "PUT /api/settings/trusted-ips": reply(400, { error: "invalid", message: "x", fields: { trusted_ips: "nope is not an IP." } }),
      "PUT /api/settings/varnish": reply(204),
    });
    const { user } = await renderRoute("/settings");
    const rl = await card("Rate Limiting");
    await user.click(rl.getByLabelText("Enable global rate limiting"));
    await user.click(rl.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/rate-limit")[0]?.json).toEqual({ enabled: true, rps: 10, burst: 20 }));

    const t = await card("Trusted IPs");
    await user.type(t.getByLabelText("Trusted IPs"), "\nnope");
    await user.click(t.getByRole("button", { name: /Save/ }));
    expect(await t.findByText("nope is not an IP.")).toBeInTheDocument();
    expect(api.calls("PUT /api/settings/trusted-ips")[0]!.json).toEqual({ trusted_ips: "203.0.113.10\nnope" });

    const v = await card("Varnish Cache");
    await user.click(v.getByLabelText("Route cache-enabled services through Varnish"));
    await user.click(v.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/varnish")[0]?.json).toEqual({ enabled: true, addr: "127.0.0.1:6081" }));
  });

  it("gives owners the downloads as form posts with the CSRF token", async () => {
    mockApi(base);
    await renderRoute("/settings");
    const b = await card("Database backup");
    const form = b.getByRole("button", { name: "Download waf.db" }).closest("form")!;
    expect(form).toHaveAttribute("method", "POST");
    expect(form.getAttribute("action")).toMatch(/\/settings\/backup$/);
    expect(form.querySelector("input[name=_csrf]")).not.toBeNull();
    expect((await card("Configuration export")).getByRole("button", { name: "Download config" })).toBeInTheDocument();
  });

  it("shows viewers the settings read-only, without the downloads", async () => {
    asRole("viewer");
    mockApi(base);
    await renderRoute("/settings");
    const c = await card("Bot Protection");
    expect(c.getByLabelText("Anomaly threshold")).toBeDisabled();
    expect(screen.queryAllByRole("button", { name: /Save & apply/ })).toHaveLength(0);
    expect(screen.queryByRole("heading", { name: "Database backup" })).toBeNull();
    expect(await card("WAF rules")).toBeTruthy();
  });
});
