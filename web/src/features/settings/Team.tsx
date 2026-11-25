import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useConfirm } from "@/components/Confirm";
import { Card, FormRow, labelMono } from "@/components/layout/Page";
import { FormError, btn, field, fieldError, help, primary, tag } from "@/features/rules/shared";
import { boot } from "@/lib/boot";
import { fmtTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Failed, danger, note } from "./Account";
import {
  useAddAPIKey,
  useAddSSOInvite,
  useAddUser,
  useRemoveAPIKey,
  useRemoveSSOInvite,
  useRemoveUser,
  useRenewSSOInvite,
  useResendInvite,
  useResetUser2FA,
  useSetSSO,
  useUpdateUser,
  type InviteSent,
  type Role,
  type Team,
} from "./api";

// Owner only: users and their invites, single sign-on, API keys.

const roles: Role[] = ["viewer", "admin", "owner"];
const small = cn(btn, "min-h-9 px-3");
const code = "bg-surface px-1 font-mono text-[11px]";

// Secret shows a value once with a copy button: an invite link or a new key.
function Secret({ label, value, tone = "warn" }: { label: string; value: string; tone?: "warn" | "ok" }) {
  const copy = () =>
    navigator.clipboard.writeText(value).then(
      () => toast.success("Copied."),
      () => toast.error("Couldn't copy. Select the text instead."),
    );
  return (
    <div className={note(tone)}>
      <p className="mb-2 font-medium">{label}</p>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 select-all break-all border border-line bg-card px-3 py-2 font-mono text-[12px] text-ink">{value}</code>
        <button type="button" onClick={copy} className={small}>
          <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-copy-01 text-[13px]" />
          Copy
        </button>
      </div>
    </div>
  );
}

function RoleSelect({ label, value, onChange, error }: { label: string; value: Role; onChange: (r: Role) => void; error?: string }) {
  return (
    <FormRow label={label} error={error}>
      <select value={value} onChange={(e) => onChange(e.target.value as Role)} className={cn(field, "capitalize")}>
        {roles.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
    </FormRow>
  );
}

// InviteForm is the email + role + button row both invite kinds use.
function InviteForm({ email, button, submit, pending, error }: { email: string; button: string; submit: (v: { email: string; role: Role }, done: () => void) => void; pending: boolean; error: unknown }) {
  const [v, setV] = useState<{ email: string; role: Role }>({ email: "", role: "viewer" });
  return (
    <form
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        submit(v, () => setV({ email: "", role: v.role }));
      }}
      className="flex flex-col gap-2"
    >
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-[200px] flex-1">
          <FormRow label={email} error={fieldError(error, "email")}>
            <input type="email" autoComplete="off" required value={v.email} onChange={(e) => setV({ ...v, email: e.target.value })} placeholder="teammate@example.com" className={field} />
          </FormRow>
        </div>
        <div className="w-36">
          <RoleSelect label="Role" value={v.role} onChange={(role) => setV({ ...v, role })} error={fieldError(error, "role")} />
        </div>
        <button type="submit" disabled={pending} className={cn(primary, "mt-[22px]")}>
          {button}
        </button>
      </div>
      <FormError error={error} fields={["email", "role"]} />
    </form>
  );
}

export function UsersCard({ t }: { t: Team }) {
  const add = useAddUser();
  const resend = useResendInvite();
  const update = useUpdateUser();
  const reset = useResetUser2FA();
  const remove = useRemoveUser();
  const ssoInvite = useAddSSOInvite();
  const renew = useRenewSSOInvite();
  const revoke = useRemoveSSOInvite();
  const [sent, setSent] = useState<InviteSent | null>(null);
  const [dialog, ask] = useConfirm();
  const mailed = (r: InviteSent) => {
    setSent(r);
    if (r.sent) toast.success(`Invite sent to ${r.email}.`);
  };
  return (
    <Card title="Users" action={<span className={cn(tag, "text-slate-600")}>{t.users.length === 1 ? "1 user" : `${t.users.length} users`}</span>}>
      <p className={cn(help, "mb-4 leading-[1.6]")}>
        Each user signs in with their own password, 2FA and sessions, and the audit log records who made each change. <strong className="text-ink">Owners</strong> also manage users, secrets and API keys;{" "}
        <strong className="text-ink">admins</strong> change everything else; <strong className="text-ink">viewers</strong> can look but not change anything.
      </p>
      <div className="flex flex-col gap-4">
        <InviteForm email="Email" button="Add user" pending={add.isPending} error={add.error} submit={(v, done) => add.mutate(v, { onSuccess: (r) => (mailed(r), done()) })} />
        <p className={help}>They get an email with a link to set their own password. It works once, for 7 days. Without email set up under Alerts, you get the link to send yourself.</p>
        {sent && !sent.sent && sent.link && (
          <div className="flex flex-col gap-2">
            <p role="status" className={note("warn")}>
              {sent.email} was added, but the invite email wasn't sent ({sent.send_error}).
            </p>
            <Secret label="Invite link: send it yourself, it isn't shown again" value={sent.link} />
          </div>
        )}

        {t.sso.issuer && (
          <>
            <InviteForm
              email="Invite to sign in with SSO"
              button="Invite"
              pending={ssoInvite.isPending}
              error={ssoInvite.error}
              submit={(v, done) => ssoInvite.mutate(v, { onSuccess: () => (toast.success(`Invited ${v.email.trim()}.`), done()) })}
            />
            <p className={help}>
              The invite works once, for 7 days: the first single sign-on with this verified email creates the user and ties it to their identity-provider account. For an existing user it links SSO and keeps its
              role and password.
            </p>
          </>
        )}

        <Failed error={resend.error ?? update.error ?? reset.error ?? remove.error ?? renew.error ?? revoke.error} />

        {t.invites.length > 0 && (
          <ul aria-label="SSO invites" className="flex flex-col gap-2">
            {t.invites.map((i) => (
              <li key={i.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 border border-dashed border-line px-3 py-3">
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-mail-01 text-base text-slate-500" />
                <div className="min-w-0 flex-1 basis-52">
                  <p className="wrap-anywhere text-[14px] font-medium text-ink">{i.email}</p>
                  <p className={cn("text-[12px]", i.expired ? "text-red-600" : "text-slate-500")}>
                    SSO invite · {i.role} · {i.expired ? "expired" : "expires"} {fmtTime(i.expires_at)}
                  </p>
                </div>
                <button type="button" aria-label={`Renew invite for ${i.email}`} onClick={() => renew.mutate(i.id, { onSuccess: () => toast.success("Invite renewed for 7 days.") })} className={small}>
                  Renew
                </button>
                <button type="button" aria-label={`Revoke invite for ${i.email}`} onClick={() => revoke.mutate(i.id)} className={cn(danger, "min-h-9 px-3")}>
                  Revoke
                </button>
              </li>
            ))}
          </ul>
        )}

        <ul aria-label="Users">
          {t.users.map((u) => (
            <li key={u.id} className={cn("flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line py-3 last:border-b-0", u.disabled && "opacity-70")}>
              <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-user text-base text-ink" />
              <div className="min-w-0 flex-1 basis-52">
                <p className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-ink">
                  <span className="wrap-anywhere">{u.email}</span>
                  {u.you && <span className={cn(tag, "text-green-700")}>You</span>}
                  {u.disabled && <span className={cn(tag, "text-slate-500")}>Disabled</span>}
                  {u.invited && <span className={cn(tag, "text-amber-700")}>Invited</span>}
                </p>
                <p className="text-[12px] text-slate-500">
                  {u.invited ? "Hasn't set a password yet" : u.sso ? "Single sign-on" : u.totp ? "2FA on" : "2FA off"} · added {fmtTime(u.created_at)}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label={`Role for ${u.email}`}
                  value={u.role}
                  onChange={(e) => update.mutate({ id: u.id, role: e.target.value as Role }, { onSuccess: () => toast.success(`${u.email} is now ${e.target.value}.`) })}
                  className={cn(field, "min-h-9 w-auto py-1 text-[12px] capitalize")}
                >
                  {roles.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                {u.invited ? (
                  <button type="button" aria-label={`Resend invite to ${u.email}`} onClick={() => resend.mutate(u.id, { onSuccess: mailed })} className={small}>
                    Resend invite
                  </button>
                ) : (
                  !u.you && (
                    <button
                      type="button"
                      aria-label={`Reset 2FA for ${u.email}`}
                      onClick={() =>
                        ask({
                          title: `Reset 2FA for ${u.email}?`,
                          body: "Their authenticator and every passkey are removed. Their password still works.",
                          label: "Reset",
                          run: () => reset.mutate(u.id, { onSuccess: () => toast.success(`2FA reset for ${u.email}.`) }),
                        })
                      }
                      className={small}
                    >
                      Reset 2FA
                    </button>
                  )
                )}
                {u.disabled ? (
                  <button type="button" aria-label={`Enable ${u.email}`} onClick={() => update.mutate({ id: u.id, disabled: false })} className={small}>
                    Enable
                  </button>
                ) : (
                  <button
                    type="button"
                    aria-label={`Disable ${u.email}`}
                    onClick={() =>
                      ask({ title: `Disable ${u.email}?`, body: "They're signed out now and can't sign in until enabled again.", label: "Disable", run: () => update.mutate({ id: u.id, disabled: true }) })
                    }
                    className={cn(danger, "min-h-9 px-3")}
                  >
                    Disable
                  </button>
                )}
                <button
                  type="button"
                  aria-label={`Remove ${u.email}`}
                  onClick={() =>
                    ask({
                      title: `Remove ${u.email}?`,
                      body: "Their sessions and passkeys are deleted. Audit entries keep their email.",
                      label: "Remove",
                      run: () => remove.mutate(u.id, { onSuccess: () => toast.success(`Removed ${u.email}.`) }),
                    })
                  }
                  className={cn(danger, "min-h-9 px-3")}
                >
                  Remove
                </button>
              </div>
            </li>
          ))}
        </ul>
      </div>
      {dialog}
    </Card>
  );
}

export function SSOCard({ t }: { t: Team }) {
  const save = useSetSSO();
  const [form, setForm] = useState({ issuer: t.sso.issuer, client_id: t.sso.client_id, client_secret: "", group: t.sso.group });
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const err = (k: string) => fieldError(save.error, k);
  return (
    <Card title="Single Sign-On" action={<span className={cn(tag, t.sso.issuer ? "text-green-700" : "text-slate-500")}>{t.sso.issuer ? "On" : "Off"}</span>}>
      <p className={cn(help, "mb-4 leading-[1.6]")}>
        Sign in through your OpenID Connect provider (Google, Entra, Okta, Keycloak, Authentik, Authelia). Invite-only: the provider proves who someone is, and an invite under Users decides whether they get in and
        with which role. SSO users skip Palisade's own 2FA, so enforce MFA at the provider. Password sign-in always stays available.
      </p>
      <div className="mb-4">
        <p className={cn(labelMono, "mb-[6px]")}>Redirect URI</p>
        <p className="wrap-anywhere border border-line bg-surface px-3 py-2 font-mono text-[13px] text-slate-600">{t.sso.callback_url}</p>
        <p className={cn(help, "mt-1")}>Register this with the provider. It's built from the address you're using now, so open Settings on the admin host people sign in at.</p>
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(form, { onSuccess: () => (setForm((f) => ({ ...f, client_secret: "" })), toast.success(form.issuer.trim() ? "Single sign-on saved." : "Single sign-on turned off.")) });
        }}
        className="grid grid-cols-1 gap-4 md:grid-cols-2"
      >
        <div className="md:col-span-2">
          <FormRow label="Issuer URL (empty turns SSO off)" error={err("issuer")}>
            <input type="url" autoComplete="off" value={form.issuer} onChange={set("issuer")} placeholder="https://auth.example.com" className={field} />
          </FormRow>
        </div>
        <FormRow label="Client ID" error={err("client_id")}>
          <input autoComplete="off" value={form.client_id} onChange={set("client_id")} className={field} />
        </FormRow>
        <FormRow label={t.sso.secret_set ? "Client secret (saved; blank keeps it)" : "Client secret"} error={err("client_secret")}>
          <input type="password" autoComplete="off" value={form.client_secret} onChange={set("client_secret")} placeholder={t.sso.secret_set ? "••••••••••••" : ""} className={field} />
        </FormRow>
        <div className="md:col-span-2">
          <FormRow
            label="Required group (optional)"
            help={
              <>
                Only users whose <code className={code}>groups</code> claim contains this can sign in. Roles always come from the invite, never the provider.
              </>
            }
          >
            <input autoComplete="off" value={form.group} onChange={set("group")} placeholder="palisade" className={field} />
          </FormRow>
        </div>
        <div className="flex flex-col gap-2 md:col-span-2">
          <FormError error={save.error} fields={["issuer", "client_id", "client_secret", "group"]} />
          <button type="submit" disabled={save.isPending} className={cn(primary, "self-start")}>
            Save
          </button>
        </div>
      </form>
    </Card>
  );
}

export function APIKeysCard({ t }: { t: Team }) {
  const add = useAddAPIKey();
  const remove = useRemoveAPIKey();
  const [form, setForm] = useState({ name: "", read_only: false });
  const [dialog, ask] = useConfirm();
  return (
    <Card title="API Keys">
      <p className={cn(help, "mb-4 leading-[1.6]")}>
        Bearer tokens for <code className={code}>{boot.admin}/api/v1/*</code>: send <code className={code}>Authorization: Bearer &lt;key&gt;</code>, no session or CSRF token. A read-only key can call every GET and
        gets a 403 on anything that changes something.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate(form, { onSuccess: () => setForm({ name: "", read_only: false }) });
        }}
        className="mb-4 flex flex-col gap-2"
      >
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-[200px] flex-1">
            <FormRow label="Key name" error={fieldError(add.error, "name")}>
              <input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="ci-deploy, terraform, …" className={field} />
            </FormRow>
          </div>
          <label className="mt-[22px] flex min-h-11 cursor-pointer items-center gap-2 text-[13px] text-slate-600">
            <input type="checkbox" checked={form.read_only} onChange={(e) => setForm((f) => ({ ...f, read_only: e.target.checked }))} className="h-4 w-4 accent-ink" />
            Read-only
          </label>
          <button type="submit" disabled={add.isPending} className={cn(primary, "mt-[22px]")}>
            Generate key
          </button>
        </div>
        <FormError error={add.error} fields={["name"]} />
      </form>
      {add.data && (
        <div className="mb-4">
          <Secret label="Copy this key now. It won't be shown again." value={add.data.key} />
        </div>
      )}
      <Failed error={remove.error} what="revoke the key" />
      {t.api_keys.length === 0 ? (
        <p className={cn(labelMono, "py-8 text-center")}>No API keys yet</p>
      ) : (
        <ul>
          {t.api_keys.map((k) => (
            <li key={k.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line py-3 last:border-b-0">
              <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-key-01 text-base text-ink" />
              <div className="min-w-0 flex-1 basis-52">
                <p className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-ink">
                  <span className="wrap-anywhere">{k.name}</span>
                  {k.read_only && <span className={cn(tag, "text-slate-500")}>Read-only</span>}
                </p>
                <p className="text-[12px] text-slate-500">
                  <span className="font-mono">{k.prefix}••••••••</span> · created {fmtTime(k.created_at)} · last used {k.last_used_at ? fmtTime(k.last_used_at) : "never"}
                </p>
              </div>
              <button
                type="button"
                aria-label={`Revoke ${k.name}`}
                onClick={() =>
                  ask({ title: `Revoke ${k.name}?`, body: "Anything using it gets a 401 from its next call.", label: "Revoke", run: () => remove.mutate(k.id, { onSuccess: () => toast.success(`Revoked ${k.name}.`) }) })
                }
                className={cn(danger, "min-h-9 px-3")}
              >
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
      {dialog}
    </Card>
  );
}
