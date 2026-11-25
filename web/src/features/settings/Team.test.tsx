import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { Account, Team } from "./api";

const at = "2026-11-24T10:00:00Z";
const account: Account = { email: "me@example.com", totp: false, secure_context: true, passkeys: [], devices: [] };
const team: Team = {
  users: [
    { id: 1, email: "me@example.com", role: "owner", disabled: false, totp: true, sso: false, invited: false, created_at: at, you: true },
    { id: 2, email: "new@example.com", role: "admin", disabled: false, totp: false, sso: false, invited: true, created_at: at, you: false },
    { id: 3, email: "off@example.com", role: "viewer", disabled: true, totp: false, sso: false, invited: false, created_at: at, you: false },
  ],
  invites: [{ id: 7, email: "sso@example.com", role: "viewer", expires_at: at, expired: true }],
  api_keys: [{ id: 4, name: "ci", prefix: "cwaf_ab12", read_only: true, created_at: at, last_used_at: "" }],
  sso: { issuer: "https://auth.example.com", client_id: "palisade", secret_set: true, group: "", callback_url: "https://waf.example.com/admin/login/sso/callback" },
};

const base = { "GET /api/notifications": { unread: 0, blocks: [] }, "GET /api/settings/account": account, "GET /api/settings/team": team, "GET /api/settings/protection": pending, "GET /api/settings/alerts": pending, "GET /api/settings/audit?page=1": pending };
const card = async (title: string) => within((await screen.findByRole("heading", { name: title })).closest("section")!);
const dialogButton = async (name: string) => within(await screen.findByRole("dialog")).getByRole("button", { name });

describe("settings: users, SSO and API keys", () => {
  it("is only for owners", async () => {
    asRole("admin");
    mockApi({ ...base, "GET /api/settings/team": pending });
    await renderRoute("/settings");
    expect(await screen.findByRole("heading", { name: "Account" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Users & API keys" })).toBeNull();
  });

  it("shows a failed read", async () => {
    mockApi({ ...base, "GET /api/settings/team": reply(500, {}) });
    await renderRoute("/settings");
    expect(await screen.findByText(/Couldn't load users and API keys/)).toBeInTheDocument();
  });

  it("adds a user and shows the link when the email wasn't sent", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/settings/users": () =>
        fail
          ? reply(409, { error: "conflict", message: "x", fields: { email: "A user with that email already exists." } })
          : reply(201, { email: "x@example.com", sent: false, link: "https://waf.example.com/admin/invite/tok", send_error: "email is not set up" }),
    });
    const { user } = await renderRoute("/settings");
    const c = await card("Users");
    expect(c.getByText("You")).toBeInTheDocument();
    expect(c.getByText("Hasn't set a password yet", { exact: false })).toBeInTheDocument();
    await user.type(c.getByLabelText("Email"), "x@example.com");
    await user.selectOptions(c.getAllByLabelText("Role")[0]!, "admin");
    await user.click(c.getByRole("button", { name: "Add user" }));
    expect(await screen.findByText("A user with that email already exists.")).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Add user" }));
    expect(await screen.findByText("https://waf.example.com/admin/invite/tok")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("email is not set up");
    expect(api.calls("POST /api/settings/users")[1]!.json).toEqual({ email: "x@example.com", role: "admin" });
  });

  it("changes roles, resets 2FA, disables, enables and removes users", async () => {
    const api = mockApi({
      ...base,
      "PUT /api/settings/users/2": reply(204),
      "PUT /api/settings/users/3": reply(409, { error: "conflict", message: "The last owner can't be demoted, disabled or removed." }),
      "POST /api/settings/users/2/invite": { email: "new@example.com", sent: true },
      "PUT /api/settings/users/1": reply(204),
      "DELETE /api/settings/users/3": reply(204),
    });
    const { user } = await renderRoute("/settings");
    await card("Users");
    await user.selectOptions(screen.getByLabelText("Role for new@example.com"), "viewer");
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/users/2")[0]?.json).toEqual({ role: "viewer" }));
    await user.click(screen.getByRole("button", { name: "Resend invite to new@example.com" }));
    await vi.waitFor(() => expect(api.calls("POST /api/settings/users/2/invite")).toHaveLength(1));
    expect(screen.queryByRole("button", { name: "Reset 2FA for me@example.com" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Enable off@example.com" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The last owner");
    await user.click(screen.getByRole("button", { name: "Disable me@example.com" }));
    await user.click(await dialogButton("Disable"));
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/users/1")[0]?.json).toEqual({ disabled: true }));
    await user.click(screen.getByRole("button", { name: "Remove off@example.com" }));
    await user.click(await dialogButton("Remove"));
    await vi.waitFor(() => expect(api.calls("DELETE /api/settings/users/3")).toHaveLength(1));
  });

  it("invites, renews and revokes SSO invites", async () => {
    const api = mockApi({
      ...base,
      "POST /api/settings/sso-invites": reply(201),
      "POST /api/settings/sso-invites/7/renew": reply(204),
      "DELETE /api/settings/sso-invites/7": reply(204),
    });
    const { user } = await renderRoute("/settings");
    const c = await card("Users");
    expect(c.getByText(/SSO invite · viewer · expired/)).toBeInTheDocument();
    await user.type(c.getByLabelText("Invite to sign in with SSO"), "s@example.com");
    await user.click(c.getByRole("button", { name: "Invite" }));
    await vi.waitFor(() => expect(api.calls("POST /api/settings/sso-invites")[0]?.json).toEqual({ email: "s@example.com", role: "viewer" }));
    await user.click(c.getByRole("button", { name: "Renew invite for sso@example.com" }));
    await user.click(c.getByRole("button", { name: "Revoke invite for sso@example.com" }));
    await vi.waitFor(() => expect(api.calls("DELETE /api/settings/sso-invites/7")).toHaveLength(1));
    expect(api.calls("POST /api/settings/sso-invites/7/renew")).toHaveLength(1);
  });

  it("hides the SSO invite form while SSO is off", async () => {
    mockApi({ ...base, "GET /api/settings/team": { ...team, invites: [], sso: { ...team.sso, issuer: "", secret_set: false } } });
    await renderRoute("/settings");
    const c = await card("Users");
    expect(c.queryByLabelText("Invite to sign in with SSO")).toBeNull();
    expect((await card("Single Sign-On")).getByText("Off")).toBeInTheDocument();
  });

  it("saves SSO, keeping a blank secret, and shows field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "PUT /api/settings/sso": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { issuer: "Discovery failed: 404" } }) : reply(204)),
    });
    const { user } = await renderRoute("/settings");
    const c = await card("Single Sign-On");
    expect(c.getByText("https://waf.example.com/admin/login/sso/callback")).toBeInTheDocument();
    expect(c.getByLabelText("Client secret (saved; blank keeps it)")).toHaveValue("");
    await user.type(c.getByLabelText("Required group (optional)"), "ops");
    await user.click(c.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Discovery failed: 404")).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Save" }));
    await vi.waitFor(() => expect(api.calls("PUT /api/settings/sso")).toHaveLength(2));
    expect(api.calls("PUT /api/settings/sso")[1]!.json).toEqual({ issuer: "https://auth.example.com", client_id: "palisade", client_secret: "", group: "ops" });
  });

  it("generates an API key shown once and revokes one", async () => {
    const api = mockApi({ ...base, "POST /api/settings/api-keys": reply(201, { key: "cwaf_secretvalue" }), "DELETE /api/settings/api-keys/4": reply(204) });
    const { user } = await renderRoute("/settings");
    const c = await card("API Keys");
    expect(c.getByText(/last used never/)).toBeInTheDocument();
    await user.type(c.getByLabelText("Key name"), "deploy");
    await user.click(c.getByLabelText("Read-only"));
    await user.click(c.getByRole("button", { name: "Generate key" }));
    expect(await screen.findByText("cwaf_secretvalue")).toBeInTheDocument();
    expect(api.calls("POST /api/settings/api-keys")[0]!.json).toEqual({ name: "deploy", read_only: true });
    await user.click(screen.getByRole("button", { name: "Revoke ci" }));
    await user.click(await dialogButton("Revoke"));
    await vi.waitFor(() => expect(api.calls("DELETE /api/settings/api-keys/4")).toHaveLength(1));
  });
});
