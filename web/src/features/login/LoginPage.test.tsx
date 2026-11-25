import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { mockApi, reply } from "@/test/api-mock";
import { LoginPage, readLogin, type LoginState } from "./LoginPage";

const base = readLogin({ admin: "/admin" });
const page = (s: Partial<LoginState> = {}) => render(<LoginPage state={{ ...base, ...s }} />);
const form = (name: RegExp) => screen.getByRole("button", { name }).closest("form")!;

describe("login page", () => {
  it("reads Go's <body data-*>", () => {
    expect(readLogin({ admin: "/x", stage: "totp", passkeys: "true", emailCode: "false", demoEmail: "d@x" })).toMatchObject({
      admin: "/x",
      stage: "totp",
      passkeys: true,
      emailCode: false,
      demoEmail: "d@x",
    });
    expect(readLogin({ stage: "<nope>" }).stage).toBe("");
  });

  it("signs in with a password, error and SSO shown", () => {
    page({ error: "Invalid email or password.", sso: "Authelia" });
    expect(screen.getByRole("heading", { name: "Welcome back" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Invalid email or password.");
    expect(form(/^sign in$/i)).toHaveAttribute("action", "/admin/login");
    expect(screen.getByRole("link", { name: "Sign in with Authelia" })).toHaveAttribute("href", "/admin/login/sso");
    const pw = screen.getByLabelText("Password");
    expect(pw).toHaveAttribute("type", "password");
    fireEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(pw).toHaveAttribute("type", "text");
    expect(screen.getByRole("button", { name: "Hide password" })).toHaveAttribute("aria-pressed", "true");
    // Go sends the plain admin CSP here, no style nonce: nothing may inject one.
    expect(document.querySelectorAll("style")).toHaveLength(0);
  });

  it("prefills the demo account", () => {
    page({ demoEmail: "demo@example.com", demoPass: "demo-pass" });
    expect(screen.getByRole("note")).toHaveTextContent("Live demo");
    expect(screen.getByLabelText("Email")).toHaveValue("demo@example.com");
    expect(screen.getByLabelText("Password")).toHaveValue("demo-pass");
    expect(screen.queryByRole("link", { name: /sign in with/i })).not.toBeInTheDocument();
  });

  it("submits a 6-digit code by itself; offers passkey and email recovery", () => {
    const submit = vi.fn((e: SubmitEvent) => e.preventDefault());
    page({ stage: "totp", notice: "Code sent.", passkeys: true, emailCode: true });
    expect(screen.getByRole("status")).toHaveTextContent("Code sent.");
    const f = form(/verify/i);
    f.addEventListener("submit", submit);
    expect(f).toHaveAttribute("action", "/admin/login/totp");
    expect(form(/email me a recovery code/i)).toHaveAttribute("action", "/admin/login/totp/email");
    const code = screen.getByLabelText("Authentication code");
    fireEvent.input(code, { target: { value: "1234-ABCD" } });
    expect(submit).not.toHaveBeenCalled();
    fireEvent.input(code, { target: { value: "123 456" } });
    expect(submit).toHaveBeenCalledTimes(1);
    expect(code).toHaveAttribute("readonly");
    expect(screen.getByRole("link", { name: "Back to sign in" })).toHaveAttribute("href", "/admin/login");
  });

  it("hides passkey and email recovery when Go says they're off", () => {
    page({ stage: "totp" });
    expect(screen.queryByRole("button", { name: /passkey/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /recovery code/i })).not.toBeInTheDocument();
  });

  it("shows a failed passkey sign-in", async () => {
    mockApi({ "POST /login/webauthn/begin": reply(400, { error: "No passkeys for this account." }) });
    page({ stage: "totp", passkeys: true });
    fireEvent.click(screen.getByRole("button", { name: "Use a passkey instead" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("No passkeys for this account.");
  });

  it("follows a passkey sign-in to where Go sends it", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const buf = new Uint8Array([1, 2]).buffer;
    Object.defineProperty(navigator, "credentials", {
      configurable: true,
      value: {
        get: vi.fn(async () => ({ id: "k", rawId: buf, type: "public-key", response: { authenticatorData: buf, clientDataJSON: buf, signature: buf, userHandle: null } })),
      },
    });
    const api = mockApi({
      "POST /login/webauthn/begin": { publicKey: { challenge: "AQI", allowCredentials: [{ id: "AQI", type: "public-key" }] } },
      "POST /login/webauthn/finish": { redirect: "/admin" },
    });
    page({ stage: "totp", passkeys: true });
    fireEvent.click(screen.getByRole("button", { name: "Use a passkey instead" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/admin"));
    expect(api.calls("POST /login/webauthn/finish")[0]!.json).toEqual({
      id: "k",
      rawId: "AQI",
      type: "public-key",
      response: { authenticatorData: "AQI", clientDataJSON: "AQI", signature: "AQI" },
    });
  });

  it("sets a password from an invite, or says the link is dead", () => {
    const { unmount } = page({ stage: "invite", inviteEmail: "new@example.com", token: "t/k" });
    expect(screen.getByRole("heading", { name: "Set your password" })).toBeInTheDocument();
    expect(screen.getByText("new@example.com")).toBeInTheDocument();
    expect(form(/set password and sign in/i)).toHaveAttribute("action", "/admin/invite/t%2Fk");
    unmount();
    page({ stage: "invite", error: "This invite link has expired." });
    expect(screen.getByRole("alert")).toHaveTextContent("expired");
    expect(screen.getByText("Invite links work once, for 7 days.")).toBeInTheDocument();
    expect(screen.queryByLabelText("New password")).not.toBeInTheDocument();
  });
});
