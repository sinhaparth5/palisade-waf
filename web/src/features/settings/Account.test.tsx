import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { Account } from "./api";

const at = "2026-11-24T10:00:00Z";
const account: Account = {
  email: "me@example.com",
  totp: false,
  secure_context: true,
  passkeys: [{ id: 3, name: "MacBook", created_at: at, last_used_at: "" }],
  devices: [
    { id: "cur", device: "Firefox on Linux", ip: "198.51.100.7", location: "Germany", flag: "DE", first_seen: at, last_seen: at, current: true, live: true },
    { id: "a/b", device: "Chrome on Windows", ip: "203.0.113.9", location: "Unknown", flag: "", first_seen: at, last_seen: at, current: false, live: true },
    { id: "old", device: "Safari on iPhone", ip: "203.0.113.10", location: "Unknown", flag: "", first_seen: at, last_seen: at, current: false, live: false },
  ],
};

const base = { "GET /api/notifications": { unread: 0, blocks: [] }, "GET /api/settings/account": account, "GET /api/settings/protection": pending };
const card = (title: string) => within(screen.getByRole("heading", { name: title }).closest("section")!);
const dialogButton = async (name: string) => within(await screen.findByRole("dialog")).getByRole("button", { name });

describe("settings: account & access", () => {
  // Admins see only this section; the owner-only one has its own tests.
  beforeEach(() => asRole("admin"));

  it("shows loading and error states", async () => {
    mockApi({ ...base, "GET /api/settings/account": pending });
    const r = await renderRoute("/settings");
    expect(within(screen.getByRole("region", { name: "Account & access" })).getByText("Loading…")).toBeInTheDocument();
    r.unmount();
    mockApi({ ...base, "GET /api/settings/account": reply(500, {}) });
    await renderRoute("/settings");
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load your account");
  });

  it("changes credentials, showing field errors, then goes to sign-in", async () => {
    let fail = true;
    const api = mockApi({ ...base, "PUT /api/settings/credentials": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { current_password: "The current password is wrong." } }) : reply(204)) });
    const { user } = await renderRoute("/settings");
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    expect(await screen.findByText("me@example.com")).toBeInTheDocument();
    const c = card("Account");
    await user.type(c.getByLabelText("New email (blank keeps it)"), "new@example.com");
    await user.type(c.getByLabelText("Current password"), "nope");
    await user.click(c.getByRole("button", { name: "Save and sign out" }));
    expect(await c.findByText("The current password is wrong.")).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();

    fail = false;
    await user.click(c.getByRole("button", { name: "Save and sign out" }));
    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith("/admin/login"));
    expect(api.calls("PUT /api/settings/credentials")[1]!.json).toEqual({ current_password: "nope", new_email: "new@example.com", new_password: "", confirm_password: "" });
  });

  it("turns on 2FA with a code and shows the backup codes once", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/settings/2fa/start": { qr: "data:image/png;base64,AAAA", key: "ABCD EFGH" },
      "POST /api/settings/2fa/confirm": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { code: "That code didn't match." } }) : { backup_codes: ["AAAA-BBBB", "CCCC-DDDD"] }),
    });
    const { user } = await renderRoute("/settings");
    await user.click(await screen.findByRole("button", { name: "Turn on 2FA" }));
    expect(await screen.findByRole("img", { name: "QR code for your authenticator app" })).toHaveAttribute("src", "data:image/png;base64,AAAA");
    expect(screen.getByText("ABCD EFGH")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Code from the app"), "000000");
    await user.click(screen.getByRole("button", { name: "Confirm and turn on" }));
    expect(await screen.findByText("That code didn't match.")).toBeInTheDocument();

    fail = false;
    await user.click(screen.getByRole("button", { name: "Confirm and turn on" }));
    expect(await screen.findByRole("list", { name: "Backup codes" })).toHaveTextContent("AAAA-BBBBCCCC-DDDD");
    expect(api.calls("POST /api/settings/2fa/confirm")[1]!.json).toEqual({ code: "000000" });
    await user.click(screen.getByRole("button", { name: "I've saved them" }));
    expect(screen.queryByRole("list", { name: "Backup codes" })).toBeNull();
  });

  it("shows a failed 2FA start", async () => {
    mockApi({ ...base, "POST /api/settings/2fa/start": reply(409, { error: "conflict", message: "Already on." }) });
    const { user } = await renderRoute("/settings");
    await user.click(await screen.findByRole("button", { name: "Turn on 2FA" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Already on.");
  });

  it("turns 2FA off with a code after a confirmation", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "GET /api/settings/account": { ...account, totp: true },
      "POST /api/settings/2fa/disable": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { code: "Enter a current code." } }) : reply(204)),
    });
    const { user } = await renderRoute("/settings");
    await user.type(await screen.findByLabelText("Code to turn off"), "123456");
    await user.click(screen.getByRole("button", { name: "Turn off 2FA" }));
    await user.click(await dialogButton("Turn off"));
    expect(await screen.findByText("Enter a current code.")).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Turn off 2FA" }));
    await user.click(await dialogButton("Turn off"));
    await vi.waitFor(() => expect(api.calls("POST /api/settings/2fa/disable")).toHaveLength(2));
    expect(api.calls("POST /api/settings/2fa/disable")[1]!.json).toEqual({ code: "123456" });
  });

  it("registers a passkey through WebAuthn and removes one", async () => {
    const create = vi.fn(async () => ({
      id: "cred",
      rawId: new Uint8Array([1, 2, 3]).buffer,
      type: "public-key",
      response: { attestationObject: new Uint8Array([255, 254]).buffer, clientDataJSON: new Uint8Array([123]).buffer },
    }));
    vi.stubGlobal("navigator", { ...navigator, credentials: { create } });
    const api = mockApi({
      ...base,
      "POST /api/settings/passkeys/begin": { publicKey: { challenge: "AQID", user: { id: "BAU", name: "me", displayName: "me" }, excludeCredentials: [{ id: "Bg", type: "public-key" }], rp: { name: "Palisade" }, pubKeyCredParams: [] } },
      "POST /api/settings/passkeys/finish": reply(201),
      "DELETE /api/settings/passkeys/3": reply(204),
    });
    const { user } = await renderRoute("/settings");
    const c = await screen.findByRole("heading", { name: "Passkeys" }).then((h) => within(h.closest("section")!));
    await user.type(c.getByLabelText("Name"), "Key");
    await user.click(c.getByRole("button", { name: "Add a passkey" }));
    await vi.waitFor(() => expect(api.calls("POST /api/settings/passkeys/finish")).toHaveLength(1));
    expect(api.calls("POST /api/settings/passkeys/begin")[0]!.json).toEqual({ name: "Key" });
    const opts = (create.mock.calls[0] as unknown as [{ publicKey: { challenge: Uint8Array; user: { id: Uint8Array }; excludeCredentials: { id: Uint8Array }[] } }])[0].publicKey;
    expect([...opts.challenge]).toEqual([1, 2, 3]);
    expect([...opts.user.id]).toEqual([4, 5]);
    expect([...opts.excludeCredentials[0]!.id]).toEqual([6]);
    expect(api.calls("POST /api/settings/passkeys/finish")[0]!.json).toEqual({ id: "cred", rawId: "AQID", type: "public-key", response: { attestationObject: "__4", clientDataJSON: "ew" } });

    await user.click(c.getByRole("button", { name: "Remove MacBook" }));
    await user.click(await dialogButton("Remove"));
    await vi.waitFor(() => expect(api.calls("DELETE /api/settings/passkeys/3")).toHaveLength(1));
  });

  it("says why a passkey can't be added", async () => {
    vi.stubGlobal("navigator", { ...navigator, credentials: { create: async () => null } });
    mockApi({ ...base, "POST /api/settings/passkeys/begin": { publicKey: { challenge: "AA", user: { id: "AA", name: "m", displayName: "m" } } } });
    const { user } = await renderRoute("/settings");
    await user.click(await screen.findByRole("button", { name: "Add a passkey" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't add the passkey");
  });

  it("warns when the page isn't a secure context", async () => {
    mockApi({ ...base, "GET /api/settings/account": { ...account, secure_context: false, passkeys: [], devices: [] } });
    await renderRoute("/settings");
    expect(await screen.findByText(/Passkeys need HTTPS/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add a passkey" })).toBeNull();
    expect(screen.getByText("No passkeys registered yet.")).toBeInTheDocument();
    expect(screen.getByText("No devices recorded yet")).toBeInTheDocument();
  });

  it("signs devices out, forgets old ones and signs out the others", async () => {
    const api = mockApi({
      ...base,
      "DELETE /api/settings/devices/a%2Fb": reply(204),
      "DELETE /api/settings/devices/old": reply(500, { error: "internal", message: "Nope." }),
      "POST /api/settings/devices/sign-out-others": reply(204),
    });
    const { user } = await renderRoute("/settings");
    expect(await screen.findByText("This device")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign out Firefox on Linux" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Sign out Chrome on Windows" }));
    await user.click(await dialogButton("Sign out"));
    await user.click(screen.getByRole("button", { name: "Forget Safari on iPhone" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("already signed out");
    await user.click(await dialogButton("Forget"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Nope.");
    await user.click(screen.getByRole("button", { name: "Sign out others" }));
    await user.click(await dialogButton("Sign out"));
    await vi.waitFor(() => expect(api.calls("POST /api/settings/devices/sign-out-others")).toHaveLength(1));
    expect(api.calls("DELETE /api/settings/devices/a%2Fb")).toHaveLength(1);
  });

  it("gives viewers their own account controls", async () => {
    asRole("viewer");
    mockApi(base);
    await renderRoute("/settings");
    expect(await screen.findByRole("button", { name: "Turn on 2FA" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save and sign out" })).toBeInTheDocument();
  });
});
