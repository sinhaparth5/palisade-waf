import { screen } from "@testing-library/react";
import { mockApi, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import { base, openEdit, svc } from "./fixtures";

describe("services: bot, availability and uploads", () => {
  it("saves the bot tab and shows field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base([svc({ bot: { mode: "inherit", ai: { user: "allow" }, login_paths: [], breach_action: "", breach_fields: [] } })]),
      "PUT /api/services/1/bot": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { login_paths: `"login" is not a path` } }) : reply(204)),
    });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Bot" }));
    await user.click(d.getByLabelText(/Always challenge/));
    await user.selectOptions(d.getByLabelText("Training"), "block");
    await user.type(d.getByLabelText(/Login paths/), "/login\n/wp-login.php");
    await user.selectOptions(d.getByLabelText("Action"), "block");
    await user.type(d.getByLabelText("Password field names"), "pw, password");
    await user.click(d.getByRole("button", { name: /Save/ }));
    expect(await d.findByText(`"login" is not a path`)).toBeInTheDocument();
    fail = false;
    await user.click(d.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/bot")).toHaveLength(2));
    expect(api.calls("PUT /api/services/1/bot")[1]!.json).toEqual({
      mode: "always",
      ai: { training: "block", user: "allow" },
      login_paths: ["/login", "/wp-login.php"],
      breach_action: "block",
      breach_fields: ["pw", "password"],
    });
  });

  it("saves maintenance and the waiting room, with the bypass link", async () => {
    const api = mockApi({
      ...base([svc({ gate: { maintenance: true, message: "", start: "2026-12-01T10:00", end: "", bypass: "t0k3n", waiting_room: false, max_active: 0, idle_mins: 0, wait_message: "", crawlers: "bypass" } })]),
      "PUT /api/services/1/gate": reply(400, { error: "invalid", message: "x", fields: { max_active: "Between 1 and 1000000." } }),
    });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Availability" }));
    expect(d.getByText("https://blog.example.com/?palisade_bypass=t0k3n")).toBeInTheDocument();
    await user.click(d.getByLabelText(/Replace it/));
    await user.click(d.getByLabelText("Waiting room"));
    await user.selectOptions(d.getByLabelText("Verified search crawlers"), "deny");
    await user.click(d.getByRole("button", { name: /Save/ }));
    expect(await d.findByText("Between 1 and 1000000.")).toBeInTheDocument();
    expect(api.calls("PUT /api/services/1/gate")[0]!.json).toEqual({
      maintenance: true,
      message: "",
      start: "2026-12-01T10:00",
      end: "",
      new_bypass: true,
      waiting_room: true,
      max_active: 0,
      idle_mins: 10,
      wait_message: "",
      crawlers: "deny",
    });
  });

  it("saves uploads", async () => {
    const api = mockApi({ ...base([svc()]), "PUT /api/services/1/uploads": reply(204) });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Uploads" }));
    await user.click(d.getByLabelText("Allow large JavaScript uploads"));
    await user.clear(d.getByLabelText("Multipart upload limit (MiB)"));
    await user.type(d.getByLabelText("Multipart upload limit (MiB)"), "64");
    await user.selectOptions(d.getByLabelText("Malware scan"), "log");
    await user.click(d.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/uploads")[0]?.json).toEqual({ large_js: true, multipart_mb: 64, malware_scan: "log" }));
  });

  it("shows viewers the tabs read-only, without a bypass link", async () => {
    asRole("viewer");
    mockApi(base([svc({ gate: { ...svc().gate, maintenance: true, bypass: undefined } })]));
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Availability" }));
    expect(d.getByLabelText("Maintenance mode")).toBeDisabled();
    expect(d.queryByText(/palisade_bypass/)).toBeNull();
    await user.click(d.getByRole("tab", { name: "Bot" }));
    expect(d.getByLabelText("Training")).toBeDisabled();
    expect(screen.queryByRole("button", { name: /Save/ })).toBeNull();
  });
});
