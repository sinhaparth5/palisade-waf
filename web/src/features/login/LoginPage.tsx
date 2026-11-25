import { useState, type ReactNode } from "react";
import { fromB64, toB64 } from "@/lib/b64";
import { cn } from "@/lib/utils";

// The public sign-in page (web/login.html, its own build): password, the 2FA
// step and an invite's set-password step. Forms post to Go as before, and Go
// answers with the next stage, rendered onto <body data-*>.

export type LoginState = {
  admin: string;
  stage: "" | "totp" | "invite";
  error: string;
  notice: string;
  sso: string;
  demoEmail: string;
  demoPass: string;
  passkeys: boolean;
  emailCode: boolean;
  inviteEmail: string;
  token: string;
};

export function readLogin(d: DOMStringMap = document.body.dataset): LoginState {
  const stage = d.stage === "totp" || d.stage === "invite" ? d.stage : "";
  return {
    admin: d.admin ?? "/admin",
    stage,
    error: d.error ?? "",
    notice: d.notice ?? "",
    sso: d.sso ?? "",
    demoEmail: d.demoEmail ?? "",
    demoPass: d.demoPass ?? "",
    passkeys: d.passkeys === "true",
    emailCode: d.emailCode === "true",
    inviteEmail: d.inviteEmail ?? "",
    token: d.token ?? "",
  };
}

const field = "w-full rounded-xs border border-edge bg-card px-4 py-3.5 text-[14px] text-ink outline-hidden focus:ring-3 focus:ring-ring";
const label = "mb-2 block font-mono text-[11px] font-medium uppercase tracking-[.08em] text-slate-500";
const primary =
  "mt-6 flex min-h-11 w-full cursor-pointer items-center justify-center rounded-xs border border-ink bg-ink py-3.5 font-mono text-[13px] font-medium uppercase tracking-[.04em] text-canvas hover:bg-ink/90 active:scale-[.97]";
const ghost =
  "flex min-h-11 w-full cursor-pointer items-center justify-center rounded-xs border border-edge bg-transparent py-3 font-mono text-[12px] font-medium uppercase tracking-[.06em] text-ink no-underline hover:bg-surface";
const back = "mt-4 text-center";
const backLink = "text-xs text-slate-500 hover:text-slate-600";

const heads = {
  "": ["Welcome back", "Sign in to manage your services, rules, and traffic."],
  totp: ["Two-factor authentication", "Enter the 6-digit code from your authenticator app, or one of your backup codes."],
  invite: ["Set your password", ""],
} as const;

export function LoginPage({ state = readLogin() }: { state?: LoginState }) {
  const s = state;
  const [title, intro] = heads[s.stage];
  return (
    <div className="min-h-dvh w-full bg-canvas text-ink lg:flex lg:items-stretch lg:gap-8 lg:p-8">
      <div className="flex flex-1 flex-col lg:overflow-hidden lg:border lg:border-edge lg:bg-card">
        <div className="relative h-52 w-full shrink-0 overflow-hidden sm:h-64 lg:hidden">
          <Art admin={s.admin} />
          <div className="absolute inset-0 bg-linear-to-t from-black/35 via-transparent to-transparent" />
          <span className="absolute bottom-4 left-5 flex items-center gap-2">
            <img src={`${s.admin}/static/imgs/logo.svg`} alt="" className="h-6 w-6 drop-shadow-sm" />
            <span className="font-mono text-sm uppercase tracking-[.16em] text-white drop-shadow-sm">Palisade</span>
          </span>
        </div>

        <div className="flex flex-1 items-center justify-center px-6 py-10 sm:px-10 lg:px-16">
          <div className="w-full max-w-[400px]">
            <span className="mb-3 hidden items-center gap-2 lg:flex">
              <img src={`${s.admin}/static/imgs/logo.svg`} alt="" className="h-6 w-6" />
              <span className="font-mono text-sm uppercase tracking-[.16em] text-ink">Palisade</span>
            </span>
            <h1 className="mb-2 font-mono text-2xl leading-tight font-medium uppercase tracking-[.04em] text-ink sm:text-3xl">{title}</h1>
            <p className="mb-8 text-sm text-slate-500 sm:text-base">
              {s.stage === "invite" ? (
                s.inviteEmail ? (
                  <>
                    You were added to Palisade as <span className="text-ink">{s.inviteEmail}</span>. Choose a password to finish.
                  </>
                ) : (
                  "Invite links work once, for 7 days."
                )
              ) : (
                intro
              )}
            </p>

            {s.error && (
              <div role="alert" className="mb-5 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-600">
                {s.error}
              </div>
            )}
            {s.notice && (
              <div role="status" className="mb-5 rounded-lg border border-green-500/40 bg-green-500/10 px-4 py-3 text-sm text-green-600">
                {s.notice}
              </div>
            )}

            {s.stage === "invite" ? <Invite s={s} /> : s.stage === "totp" ? <TOTP s={s} /> : <Password s={s} />}
          </div>
        </div>
      </div>

      <div className="relative hidden overflow-hidden border border-edge lg:block lg:w-[42%] xl:w-[45%]">
        <Art admin={s.admin} />
        <div className="absolute inset-0 bg-linear-to-t from-black/25 via-transparent to-transparent" />
      </div>
    </div>
  );
}

const Art = ({ admin }: { admin: string }) => (
  <img
    src={`${admin}/static/imgs/login-security-v2.webp`}
    alt=""
    aria-hidden
    width={1000}
    height={1250}
    fetchPriority="high"
    className="absolute inset-0 h-full w-full object-cover object-center grayscale-[.6] sepia-[.25]"
  />
);

const Back = ({ admin }: { admin: string }) => (
  <p className={back}>
    <a href={`${admin}/login`} className={backLink}>
      Back to sign in
    </a>
  </p>
);

function Password({ s }: { s: LoginState }) {
  const [shown, setShown] = useState(false);
  return (
    <>
      {s.demoEmail && (
        <div role="note" className="mb-5 rounded-lg border border-blue-500/40 bg-blue-500/10 px-4 py-3 text-sm text-blue-600">
          <strong>Live demo.</strong> Sign in as <span className="font-mono">{s.demoEmail}</span> with password{" "}
          <span className="font-mono">{s.demoPass}</span>. Read-only; the data resets nightly.
        </div>
      )}
      <form action={`${s.admin}/login`} method="post" noValidate>
        <div className="mb-5">
          <label className={label} htmlFor="login-email">
            Email
          </label>
          <input id="login-email" name="email" type="email" autoComplete="email" placeholder="admin@example.com" defaultValue={s.demoEmail} required className={field} />
        </div>
        <div className="mb-2">
          <div className="mb-2 flex items-center justify-between">
            <label className={cn(label, "mb-0")} htmlFor="login-password">
              Password
            </label>
            <span className="cursor-default text-xs text-slate-500" title="Password resets aren't available yet. Contact whoever ran palisade setup.">
              Forgot password?
            </span>
          </div>
          <div className="relative">
            <input
              id="login-password"
              name="password"
              type={shown ? "text" : "password"}
              autoComplete="current-password"
              placeholder="Password"
              defaultValue={s.demoPass}
              required
              className={cn(field, "pr-12")}
            />
            <button
              type="button"
              aria-label={shown ? "Hide password" : "Show password"}
              aria-pressed={shown}
              onClick={() => setShown(!shown)}
              className="absolute top-1/2 right-2 -translate-y-1/2 cursor-pointer rounded-md p-2 text-slate-500 transition hover:text-slate-600"
            >
              <Eye open={shown} />
            </button>
          </div>
        </div>
        <button type="submit" className={primary}>
          Sign in
        </button>
      </form>
      {s.sso && (
        <>
          <div aria-hidden className="my-6 flex items-center gap-3 text-xs text-slate-500">
            <span className="h-px flex-1 bg-edge" />
            or
            <span className="h-px flex-1 bg-edge" />
          </div>
          <a href={`${s.admin}/login/sso`} className={ghost}>
            Sign in with {s.sso}
          </a>
        </>
      )}
    </>
  );
}

const Eye = ({ open }: { open: boolean }) => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8} aria-hidden>
    {open ? (
      <>
        <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      </>
    ) : (
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88"
      />
    )}
  </svg>
);

function TOTP({ s }: { s: LoginState }) {
  // A 6-digit code (typed, pasted or autofilled) submits itself; backup codes
  // are 8 characters, so they still need Verify.
  const onInput = (e: React.FormEvent<HTMLInputElement>) => {
    const el = e.currentTarget;
    if (/^\d{6}$/.test(el.value.replace(/\s/g, ""))) {
      el.readOnly = true;
      el.form?.requestSubmit();
    }
  };
  return (
    <>
      <form action={`${s.admin}/login/totp`} method="post" noValidate>
        <div className="mb-2">
          <label className={label} htmlFor="login-code">
            Authentication code
          </label>
          <input
            id="login-code"
            name="code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            autoFocus
            required
            onInput={onInput}
            className={cn(field, "text-center text-lg tracking-[0.25em]")}
          />
        </div>
        <button type="submit" className={primary}>
          Verify
        </button>
      </form>
      {s.passkeys && <Passkey admin={s.admin} />}
      {s.emailCode && (
        <form action={`${s.admin}/login/totp/email`} method="post" className="mt-5 text-center">
          <button type="submit" className="cursor-pointer border-none bg-transparent font-mono text-[12px] uppercase tracking-[.06em] text-ink underline">
            Email me a recovery code
          </button>
        </form>
      )}
      <Back admin={s.admin} />
    </>
  );
}

type RequestJSON = { publicKey: Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
  challenge: string;
  allowCredentials?: (Omit<PublicKeyCredentialDescriptor, "id"> & { id: string })[];
} };

// signInWithPasskey runs the WebAuthn assertion between Go's begin and finish
// (same pending-login stage as the code form) and returns where to go next.
export async function signInWithPasskey(admin: string): Promise<string> {
  const post = async (path: string, body?: unknown) => {
    const r = await fetch(admin + path, {
      method: "POST",
      credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const j = await r.json().catch(() => ({}));
    if (j.error) throw new Error(j.error);
    return j;
  };
  const { publicKey: o } = (await post("/login/webauthn/begin")) as RequestJSON;
  const cred = (await navigator.credentials.get({
    publicKey: { ...o, challenge: fromB64(o.challenge), allowCredentials: o.allowCredentials?.map((c) => ({ ...c, id: fromB64(c.id) })) },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Passkey sign-in failed.");
  const r = cred.response as AuthenticatorAssertionResponse;
  const done = await post("/login/webauthn/finish", {
    id: cred.id,
    rawId: toB64(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: toB64(r.authenticatorData),
      clientDataJSON: toB64(r.clientDataJSON),
      signature: toB64(r.signature),
      ...(r.userHandle && { userHandle: toB64(r.userHandle) }),
    },
  });
  if (!done.redirect) throw new Error("Passkey sign-in failed.");
  return done.redirect;
}

function Passkey({ admin }: { admin: string }) {
  const [status, setStatus] = useState<{ msg: string; error: boolean } | null>(null);
  const start = () => {
    setStatus({ msg: "Waiting for your passkey…", error: false });
    signInWithPasskey(admin).then(
      (to) => window.location.assign(to),
      (e: Error) => setStatus({ msg: e.message || "Passkey sign-in failed.", error: true }),
    );
  };
  return (
    <div className="mt-5 text-center">
      <button type="button" onClick={start} className={ghost}>
        Use a passkey instead
      </button>
      {status && (
        <p role={status.error ? "alert" : "status"} className={cn("mt-2 text-xs", status.error ? "text-red-600" : "text-slate-500")}>
          {status.msg}
        </p>
      )}
    </div>
  );
}

function Invite({ s }: { s: LoginState }): ReactNode {
  return (
    <>
      {s.token && (
        <form action={`${s.admin}/invite/${encodeURIComponent(s.token)}`} method="post" noValidate>
          <input type="text" name="email" value={s.inviteEmail} autoComplete="username" readOnly hidden />
          <div className="mb-5">
            <label className={label} htmlFor="invite-password">
              New password
            </label>
            <input id="invite-password" name="password" type="password" autoComplete="new-password" placeholder="Min 12 characters" autoFocus required minLength={12} className={field} />
          </div>
          <div className="mb-2">
            <label className={label} htmlFor="invite-confirm">
              Confirm password
            </label>
            <input id="invite-confirm" name="confirm_password" type="password" autoComplete="new-password" required minLength={12} className={field} />
          </div>
          <button type="submit" className={primary}>
            Set password and sign in
          </button>
        </form>
      )}
      <Back admin={s.admin} />
    </>
  );
}
