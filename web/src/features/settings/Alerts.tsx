import { useState } from "react";
import { toast } from "sonner";
import { Card, FormRow, labelMono } from "@/components/layout/Page";
import { SettingsCard, Toggle, btn, field, fieldError, help } from "@/features/rules/shared";
import { boot } from "@/lib/boot";
import { fmtTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Failed } from "./Account";
import { Loaded } from "./SettingsPage";
import { useAudit, useSendTest, useSetEmail, useSetWebhook, type Email, type Webhook, type WebhookEvent } from "./api";

// Alerts (owner only) and the audit log (every role).

const code = "bg-surface px-1 font-mono text-[11px]";
const str = (f: FormData, k: string) => String(f.get(k) ?? "");
const events: { value: WebhookEvent; label: string }[] = [
  { value: "blocked", label: "Blocked requests" },
  { value: "challenged", label: "Bot challenges" },
  { value: "scripts", label: "New script sources (CSP)" },
];

// TestSend sends with the saved settings and says how it went.
function TestSend({ what, label, icon, children }: { what: "webhook" | "email"; label: string; icon: string; children: React.ReactNode }) {
  const send = useSendTest(what);
  return (
    <div className="flex flex-col gap-2 border-t border-line pt-3">
      <button type="button" disabled={send.isPending} onClick={() => send.mutate(undefined, { onSuccess: () => toast.success("Sent.") })} className={cn(btn, "self-start")}>
        <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded text-base", icon)} />
        {label}
      </button>
      <Failed error={send.error} what="send" />
      <p className={help}>{children}</p>
    </div>
  );
}

export function WebhookCard({ v }: { v: Webhook }) {
  const save = useSetWebhook();
  const e = save.error;
  return (
    <SettingsCard
      title="Webhook / SIEM Export"
      intro={
        <>
          Push security events to any HTTP endpoint as they happen: Splunk HEC, Elastic, Loki or your own receiver. Logs can also be downloaded as NDJSON from the{" "}
          <a href={`${boot.admin}/app/logs`} className="text-ink underline">
            Logs
          </a>{" "}
          page.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["url", "events"]}
      onSubmit={(f) =>
        save.mutate(
          {
            enabled: f.has("enabled"),
            url: str(f, "url"),
            secret: str(f, "secret"),
            events: f.getAll("events").map(String) as WebhookEvent[],
            destination_type: str(f, "destination_type") as Webhook["destination_type"],
          },
          { onSuccess: () => toast.success("Webhook saved.") },
        )
      }
    >
      <Toggle name="enabled" label="Enable webhook delivery" on={v.enabled} />
      <FormRow label="Destination type" help="Slack and Discord: paste that platform's incoming webhook URL below. No app install needed.">
        <select name="destination_type" defaultValue={v.destination_type} className={field}>
          <option value="generic">Generic (raw JSON)</option>
          <option value="slack">Slack (Block Kit)</option>
          <option value="discord">Discord (embed)</option>
        </select>
      </FormRow>
      <FormRow label="Endpoint URL (empty turns it off)" error={fieldError(e, "url")}>
        <input name="url" type="url" defaultValue={v.url} placeholder="https://your-siem.example.com/ingest" className={cn(field, "font-mono")} />
      </FormRow>
      <FormRow
        label="Secret"
        help={
          <>
            Sent as the <code className={code}>X-WAF-Secret</code> header; Slack and Discord ignore it. Blank sends none.
          </>
        }
      >
        <input name="secret" autoComplete="off" defaultValue={v.secret} className={cn(field, "font-mono")} />
      </FormRow>
      <fieldset>
        <legend className="mb-2 text-[13px] font-medium text-ink">Events to push</legend>
        <div className="flex flex-col gap-2 sm:flex-row sm:gap-4">
          {events.map((ev) => (
            <label key={ev.value} className="flex min-h-9 cursor-pointer items-center gap-2 text-[13px] text-ink">
              <input type="checkbox" name="events" value={ev.value} defaultChecked={v.events.includes(ev.value)} className="h-4 w-4 accent-ink" />
              {ev.label}
            </label>
          ))}
        </div>
        {fieldError(e, "events") && <p className="mt-1 text-[12px] text-red-600">{fieldError(e, "events")}</p>}
      </fieldset>
      <TestSend what="webhook" label="Send test alert" icon="hgi-notification-03">
        The test uses the saved settings, ignoring the switch and event filters, so save first.
      </TestSend>
    </SettingsCard>
  );
}

export function EmailCard({ v }: { v: Email }) {
  const save = useSetEmail();
  const e = save.error;
  return (
    <SettingsCard
      title="Email Alerts"
      intro="Just after midnight, a summary of the previous day (blocked requests, 403 responses and a per-stage breakdown) goes to the recipients below through Cloudflare Email Service."
      pending={save.isPending}
      error={e}
      fields={["to", "token"]}
      onSubmit={(f) => save.mutate({ enabled: f.has("enabled"), to: str(f, "to"), token: str(f, "token") }, { onSuccess: () => toast.success("Email settings saved.") })}
    >
      <Toggle name="enabled" label="Enable daily report email" on={v.enabled} />
      <div>
        <p className={cn(labelMono, "mb-[6px]")}>Sender</p>
        <p className="border border-line bg-surface px-3 py-2 font-mono text-[13px] text-slate-600">{v.sender}</p>
      </div>
      <FormRow label="Recipients" error={fieldError(e, "to")} help="Comma-separated list.">
        <input name="to" defaultValue={v.to} placeholder="you@example.com, ops@example.com" className={cn(field, "font-mono")} />
      </FormRow>
      <FormRow
        label={v.token_set ? "Cloudflare API token (saved; blank keeps it)" : "Cloudflare API token"}
        error={fieldError(e, "token")}
        help="Needs the Email Sending: Edit permission. Kept only in this server's database and never shown again."
      >
        <input name="token" type="password" autoComplete="off" placeholder={v.token_set ? "••••••••••••" : ""} className={field} />
      </FormRow>
      <TestSend what="email" label="Send test report" icon="hgi-mail-01">
        The test uses the saved settings and covers the last 24 hours, so save first.
      </TestSend>
    </SettingsCard>
  );
}

export function AuditCard() {
  const [page, setPage] = useState(1);
  const q = useAudit(page);
  return (
    <Card title="Audit log">
      <p className={cn(help, "mb-4")}>Who made each change, from where, and to what. Entries are kept for at least a year. Secret values are never recorded.</p>
      <Loaded q={q} what="the audit log">
        {(d) =>
          d.entries.length === 0 ? (
            <p className="py-6 text-center text-[13px] text-slate-500">No changes recorded yet.</p>
          ) : (
            <>
              <ul className="divide-y divide-line">
                {d.entries.map((a, i) => (
                  <li key={`${a.ts}-${i}`} className="grid grid-cols-1 gap-1 py-3 text-[12px] md:grid-cols-[170px_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.6fr)] md:gap-4">
                    <span className="whitespace-nowrap text-slate-500">{fmtTime(a.ts)}</span>
                    <span className="min-w-0 wrap-anywhere text-ink">
                      {a.actor}
                      <span className="block font-mono text-slate-500">{a.ip}</span>
                    </span>
                    <span className="min-w-0 wrap-anywhere font-mono font-medium text-ink">{a.action}</span>
                    <span className="min-w-0 wrap-anywhere font-mono text-slate-600">{[a.target, a.summary].filter(Boolean).join(" · ")}</span>
                  </li>
                ))}
              </ul>
              {d.pages > 1 && (
                <nav aria-label="Audit log pages" className="mt-3 flex items-center justify-between gap-3 border-t border-line pt-3">
                  <button type="button" disabled={d.page <= 1} onClick={() => setPage(d.page - 1)} className={btn}>
                    ← Prev
                  </button>
                  <span className={labelMono}>
                    Page {d.page} of {d.pages} · {d.total} entries
                  </span>
                  <button type="button" disabled={d.page >= d.pages} onClick={() => setPage(d.page + 1)} className={btn}>
                    Next →
                  </button>
                </nav>
              )}
            </>
          )
        }
      </Loaded>
    </Card>
  );
}
