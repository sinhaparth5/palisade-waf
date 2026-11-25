import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useConfirm } from "@/components/Confirm";
import { Flag } from "@/components/Flag";
import { Card, FormRow, labelMono } from "@/components/layout/Page";
import { FormError, btn, field, fieldError, help, primary, tag } from "@/features/rules/shared";
import { ApiError } from "@/lib/api";
import { boot } from "@/lib/boot";
import { fmtTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useAddPasskey, useConfirmTOTP, useDisableTOTP, useRemovePasskey, useSetCredentials, useSignOutDevice, useSignOutOthers, useStartTOTP, type Account, type Credentials } from "./api";

// Account & access: the signed-in user's own credentials, second factors
// and devices. Every role has these.

export const danger = cn(btn, "border-red-300 text-red-600 hover:bg-red-50");
export const note = (tone: "ok" | "warn" | "bad") =>
  cn("border px-4 py-3 text-[13px] leading-normal", tone === "ok" ? "border-green-300 bg-green-50 text-green-800" : tone === "warn" ? "border-amber-300 bg-amber-50 text-amber-800" : "border-red-300 bg-red-50 text-red-700");

export function Failed({ error, what = "save" }: { error: unknown; what?: string }) {
  if (error == null) return null;
  return (
    <p role="alert" className="text-[13px] text-red-600">
      {(error instanceof ApiError && error.message) || `Couldn't ${what}. Try again.`}
    </p>
  );
}

export function CredentialsCard({ email }: { email: string }) {
  const save = useSetCredentials();
  const [form, setForm] = useState<Credentials>({ current_password: "", new_email: "", new_password: "", confirm_password: "" });
  const set = (k: keyof Credentials) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const err = (k: keyof Credentials) => fieldError(save.error, k);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(form, { onSuccess: () => window.location.assign(`${boot.admin}/login`) });
  };
  return (
    <Card title="Account">
      <p className={cn(help, "mb-4")}>Change your sign-in email or password. Every device, this one included, is signed out after saving.</p>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <div>
          <p className={cn(labelMono, "mb-[6px]")}>Current email</p>
          <p className="border border-line bg-surface px-3 py-2 font-mono text-[13px] text-slate-600">{email}</p>
        </div>
        <FormRow label="New email (blank keeps it)" error={err("new_email")}>
          <input type="email" autoComplete="email" value={form.new_email} onChange={set("new_email")} placeholder="new@example.com" className={field} />
        </FormRow>
        <FormRow label="New password (blank keeps it)" error={err("new_password")}>
          <input type="password" autoComplete="new-password" value={form.new_password} onChange={set("new_password")} placeholder="At least 12 characters" className={field} />
        </FormRow>
        <FormRow label="Confirm new password" error={err("confirm_password")}>
          <input type="password" autoComplete="new-password" value={form.confirm_password} onChange={set("confirm_password")} className={field} />
        </FormRow>
        <FormRow label="Current password" error={err("current_password")}>
          <input type="password" autoComplete="current-password" required value={form.current_password} onChange={set("current_password")} className={field} />
        </FormRow>
        <FormError error={save.error} fields={Object.keys(form)} />
        <button type="submit" disabled={save.isPending} className={cn(primary, "self-start")}>
          Save and sign out
        </button>
      </form>
    </Card>
  );
}

export function TwoFactorCard({ on }: { on: boolean }) {
  const start = useStartTOTP();
  const confirm = useConfirmTOTP();
  const disable = useDisableTOTP();
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [dialog, ask] = useConfirm();
  const codeInput = (label: string, error: unknown) => (
    <div className="w-36">
      <FormRow label={label} error={fieldError(error, "code")}>
        <input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" className={cn(field, "text-center font-mono")} />
      </FormRow>
    </div>
  );

  let body;
  if (codes) {
    body = (
      <div className="flex flex-col gap-3">
        <p role="status" className={note("ok")}>
          Two-factor authentication is on. The next sign-in asks for a code.
        </p>
        <div className={note("warn")}>
          <p className="font-medium">Save these backup codes now. They won't be shown again.</p>
          <p className="mb-3">Each one signs you in once if the authenticator is unavailable.</p>
          <ul aria-label="Backup codes" className="grid grid-cols-2 gap-[6px] sm:grid-cols-3">
            {codes.map((c) => (
              <li key={c} className="select-all border border-amber-300 bg-card px-2 py-[6px] text-center font-mono text-[12px] text-ink">
                {c}
              </li>
            ))}
          </ul>
        </div>
        <button type="button" onClick={() => setCodes(null)} className={cn(btn, "self-start")}>
          I've saved them
        </button>
      </div>
    );
  } else if (on) {
    body = (
      <form
        onSubmit={(e) => {
          e.preventDefault();
          ask({
            title: "Turn off two-factor authentication?",
            body: "Sign-in goes back to the password alone.",
            label: "Turn off",
            run: () => disable.mutate(code, { onSuccess: () => (setCode(""), toast.success("Two-factor authentication is off.")) }),
          });
        }}
        className="flex flex-col gap-3"
      >
        <p className={note("ok")}>On. Sign-in asks for an authenticator code after the password.</p>
        <div className="flex flex-wrap items-end gap-3">
          {codeInput("Code to turn off", disable.error)}
          <button type="submit" disabled={disable.isPending} className={danger}>
            Turn off 2FA
          </button>
        </div>
        <FormError error={disable.error} fields={["code"]} />
        <p className={help}>Needs a current authenticator code or a backup code, so a stolen session alone can't turn it off.</p>
      </form>
    );
  } else if (start.data) {
    body = (
      <div className="flex flex-col items-start gap-5 sm:flex-row">
        <img src={start.data.qr} alt="QR code for your authenticator app" width={160} height={160} className="shrink-0 border border-line" />
        <form
          onSubmit={(e) => {
            e.preventDefault();
            confirm.mutate(code, { onSuccess: (r) => (setCode(""), setCodes(r.backup_codes), start.reset()) });
          }}
          className="flex min-w-0 flex-1 flex-col gap-3"
        >
          <p className="text-[13px] text-slate-600">Scan the code with your authenticator app, or type this key:</p>
          <code className="block select-all break-all border border-line bg-surface px-3 py-2 font-mono text-[12px] text-ink">{start.data.key}</code>
          <div className="flex flex-wrap items-end gap-3">
            {codeInput("Code from the app", confirm.error)}
            <button type="submit" disabled={confirm.isPending} className={primary}>
              Confirm and turn on
            </button>
          </div>
          <FormError error={confirm.error} fields={["code"]} />
        </form>
      </div>
    );
  } else {
    body = (
      <div className="flex flex-col gap-3">
        <button type="button" disabled={start.isPending} onClick={() => start.mutate()} className={cn(primary, "self-start")}>
          Turn on 2FA
        </button>
        <Failed error={start.error} />
      </div>
    );
  }
  return (
    <Card title="Two-Factor Authentication" action={<span className={cn(tag, on ? "text-green-700" : "text-slate-500")}>{on ? "On" : "Off"}</span>}>
      <p className={cn(help, "mb-4")}>
        Adds a one-time code (TOTP) to sign-in. Works with any RFC 6238 app, such as Aegis, 1Password or Google Authenticator. Codes are checked locally.
      </p>
      {body}
      {dialog}
    </Card>
  );
}

export function PasskeysCard({ a }: { a: Account }) {
  const add = useAddPasskey();
  const remove = useRemovePasskey();
  const [name, setName] = useState("");
  const [dialog, ask] = useConfirm();
  return (
    <Card title="Passkeys">
      <p className={cn(help, "mb-4")}>
        A fingerprint, face, PIN or security key tied to this site. Accepted as the second factor at sign-in alongside TOTP, and you can register more than one.
      </p>
      {a.secure_context ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate(name, { onSuccess: () => (setName(""), toast.success("Passkey added.")) });
          }}
          className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end"
        >
          <div className="min-w-0 flex-1">
            <FormRow label="Name">
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. MacBook" className={field} />
            </FormRow>
          </div>
          <button type="submit" disabled={add.isPending} className={primary}>
            Add a passkey
          </button>
        </form>
      ) : (
        <p className={cn(note("warn"), "mb-4")}>Passkeys need HTTPS with a real hostname (or localhost). This page is reached over plain HTTP or a bare IP, so you can't add one here.</p>
      )}
      <div className="flex flex-col gap-2">
        <Failed error={add.error} what="add the passkey" />
        <Failed error={remove.error} what="remove the passkey" />
      </div>
      {a.passkeys.length === 0 ? (
        <p className={cn(help, "pt-2")}>No passkeys registered yet.</p>
      ) : (
        <ul className="border-t border-line">
          {a.passkeys.map((p) => (
            <li key={p.id} className="flex items-center justify-between gap-3 border-b border-line py-3 last:border-b-0">
              <div className="min-w-0">
                <p className="truncate text-[13px] font-medium text-ink">{p.name}</p>
                <p className="text-[12px] text-slate-500">
                  Added {fmtTime(p.created_at)}
                  {p.last_used_at && ` · last used ${p.last_used_at}`}
                </p>
              </div>
              <button
                type="button"
                aria-label={`Remove ${p.name}`}
                onClick={() => ask({ title: `Remove ${p.name}?`, body: "It can't be used to sign in any more.", label: "Remove", run: () => remove.mutate(p.id) })}
                className={cn(danger, "min-h-9 px-3")}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {dialog}
    </Card>
  );
}

export function DevicesCard({ a }: { a: Account }) {
  const out = useSignOutDevice();
  const others = useSignOutOthers();
  const [dialog, ask] = useConfirm();
  return (
    <Card
      title="Registered Devices"
      action={
        <button
          type="button"
          disabled={others.isPending}
          onClick={() =>
            ask({
              title: "Sign out every other device?",
              body: "They go back to the sign-in screen on their next action.",
              label: "Sign out",
              run: () => others.mutate(undefined, { onSuccess: () => toast.success("Other devices signed out.") }),
            })
          }
          className={cn(danger, "min-h-9 px-3")}
        >
          Sign out others
        </button>
      }
    >
      <p className={cn(help, "mb-4")}>One active session per account: signing in on a new device signs the previous one out. Devices stay listed for 30 days.</p>
      <div className="flex flex-col gap-2">
        <Failed error={out.error ?? others.error} what="sign the device out" />
      </div>
      {a.devices.length === 0 ? (
        <p className={cn(labelMono, "py-10 text-center")}>No devices recorded yet</p>
      ) : (
        <ul>
          {a.devices.map((d) => (
            <li key={d.id} className={cn("flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line py-3 last:border-b-0", !d.live && "opacity-70")}>
              <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded hgi-computer text-base", d.current ? "text-ink" : "text-slate-500")} />
              <div className="min-w-0 flex-1 basis-52">
                <p className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-ink">
                  {d.device}
                  {d.current ? (
                    <span className={cn(tag, "text-green-700")}>This device</span>
                  ) : (
                    !d.live && <span className={cn(tag, "text-slate-500")}>Signed out</span>
                  )}
                </p>
                <p className="mt-[2px] flex items-center gap-[6px] text-[12px] text-slate-500">
                  {d.flag && <Flag code={d.flag} />}
                  <span className="min-w-0 wrap-anywhere">
                    {d.location} · <span className="font-mono">{d.ip}</span> · last active {fmtTime(d.last_seen)}
                  </span>
                </p>
              </div>
              {!d.current && (
                <button
                  type="button"
                  aria-label={`${d.live ? "Sign out" : "Forget"} ${d.device}`}
                  onClick={() =>
                    ask(
                      d.live
                        ? { title: `Sign out ${d.device}?`, body: "It goes back to the sign-in screen on its next action.", label: "Sign out", run: () => out.mutate(d.id) }
                        : { title: `Forget ${d.device}?`, body: "It's already signed out. This only removes it from the history.", label: "Forget", run: () => out.mutate(d.id) },
                    )
                  }
                  className={cn(d.live ? danger : btn, "min-h-9 px-3")}
                >
                  {d.live ? "Sign out" : "Forget"}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {dialog}
    </Card>
  );
}
