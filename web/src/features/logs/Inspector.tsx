import { useState, type ReactNode } from "react";
import { labelMono } from "@/components/layout/Page";
import { Flag } from "@/components/Flag";
import { can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { useLogDetail, useLogException, useRuleFeedback, type LogDetail } from "./api";

// Request inspector: one request log in full. LogsPage docks it beside the
// table on wide screens and opens it as a sheet below that.

const dt = cn(labelMono, "text-[10px]");
const section = cn(labelMono, "mb-[10px] text-ink");

const statusInk = (s: number) => (s >= 500 ? "text-red-600" : s >= 400 ? "text-amber-600" : s >= 300 ? "text-blue-600" : "text-brand-dark");

export function Inspector({ id, onClose, heading }: { id: number | null; onClose: () => void; heading: ReactNode }) {
  const { data, isError, isPending } = useLogDetail(id);
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-edge px-5 py-3">
        {heading}
        {id !== null && (
          <button type="button" aria-label="Close request details" onClick={onClose} className="flex h-11 w-11 items-center justify-center rounded-sm border border-edge text-ink hover:bg-surface xl:h-8 xl:w-8">
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-cancel-01 text-[13px]" />
          </button>
        )}
      </div>
      {id === null ? (
        <p className={cn(labelMono, "m-auto px-8 text-center text-[12px]")}>Select a request to inspect it</p>
      ) : isError ? (
        <p role="alert" className="m-auto px-8 text-center text-[13px] text-red-600">
          Couldn't load that request. It may have been pruned; try again.
        </p>
      ) : isPending ? (
        <p className={cn(labelMono, "m-auto")}>Loading…</p>
      ) : (
        <Detail key={data.id} d={data} />
      )}
    </div>
  );
}

function Detail({ d }: { d: LogDetail }) {
  const full = (d.host || "") + d.path + (d.query ? `?${d.query}` : "");
  const headers = Object.keys(d.headers ?? {}).sort();
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto overscroll-contain p-5">
      <div className="border border-edge bg-card">
        <div className="border-b border-line px-4 py-3">
          <p className={dt}>Request ID</p>
          <p className="font-mono text-[13px] break-all text-ink select-all">{d.request_id || "—"}</p>
        </div>
        <Fields>
          <Field name="Method" mono>
            {d.method}
          </Field>
          <Field name="Status">
            <span className={cn("font-mono tabular-nums", statusInk(d.status))}>{d.status}</span>
          </Field>
          <Field name="Service">{d.app_name}</Field>
        </Fields>
      </div>

      <div>
        <p className="font-mono text-[15px] leading-snug break-all text-ink" title={full}>
          {full}
        </p>
        {d.host && <p className="mt-1 font-mono text-[12px] break-all text-slate-500">{d.host}</p>}
      </div>

      {d.blocked && (
        <div>
          <p className={section}>Security decision</p>
          <div className="border border-red-300 bg-red-50 px-4 py-3">
            <p className="flex items-center gap-2 font-mono text-[12px] uppercase text-red-600">
              <span className="h-2 w-2 rounded-full bg-danger" />
              Request blocked
            </p>
            <p className="mt-1 font-mono text-[12px] text-red-600">
              {d.rule_id ? `Rule #${d.rule_id} · ` : ""}
              {d.action || "blocked"}
            </p>
          </div>
          {d.rule_id > 0 && can("admin") && <RuleActions id={d.id} />}
        </div>
      )}

      <Fields className="border-t border-line px-0 pt-4">
        <Field name="Time (UTC)" mono>
          {new Date(d.timestamp).toUTCString()}
        </Field>
        <Field name="Duration" mono>
          {d.duration_ms}ms{d.cache_status ? ` · cache ${d.cache_status}` : ""}
        </Field>
        <Field name="Country">
          {d.country ? (
            <span className="flex items-center gap-2">
              <Flag code={d.country} />
              {d.country}
            </span>
          ) : (
            "—"
          )}
        </Field>
        <Field name="Query" mono>
          {d.query || "(none)"}
        </Field>
        <Field name="User agent">{d.user_agent}</Field>
      </Fields>

      <div className="border-t border-line pt-4">
        <p className={section}>Client</p>
        <Fields className="p-0">
          <Field name="Real IP" mono title="CF-Connecting-IP / X-Forwarded-For, from trusted peers only">
            {d.real_ip}
          </Field>
          <Field name="Proxy IP" mono title="direct TCP connection source">
            {d.proxy_ip}
          </Field>
          <Field name="ASN" mono>
            {d.asn ? `AS${d.asn}` : ""}
          </Field>
          <Field name="Org">{d.org}</Field>
          <Field name="Protocol" mono>
            {d.proto}
          </Field>
          <Field name="TLS" mono>
            {d.tls_version ? d.tls_version + (d.tls_cipher ? ` · ${d.tls_cipher}` : "") : "Plaintext / terminated upstream"}
          </Field>
          {d.tls_version && (
            <Field name="SNI" mono>
              {d.tls_sni}
            </Field>
          )}
        </Fields>
      </div>

      {d.has_threat_score && (
        <div className="border-t border-line pt-4">
          <p className={section}>Threat score</p>
          <div className="flex items-center gap-4">
            <div className="relative h-16 w-16 shrink-0">
              <svg viewBox="0 0 40 40" aria-hidden className="h-16 w-16 -rotate-90">
                <circle cx="20" cy="20" r="16" fill="none" strokeWidth="4" className="stroke-slate-200" />
                <circle cx="20" cy="20" r="16" fill="none" strokeWidth="4" pathLength={100} strokeDasharray={`${Math.max(0, Math.min(100, d.threat_score))} 100`} className="stroke-danger" />
              </svg>
              <span className="absolute inset-0 flex items-center justify-center font-mono text-[13px]">{d.threat_score}</span>
            </div>
            <p className="font-mono text-[12px] leading-relaxed text-slate-600">
              autoban {d.threat_autoban} · bot {d.threat_bot} · asn {d.threat_asn} · geo {d.threat_geo} · ja4 {d.threat_ja4}
            </p>
          </div>
        </div>
      )}

      {(d.bot_score > 0 || d.ja4 || d.visitor_id) && (
        <div className="border-t border-line pt-4">
          <p className={section}>Bot signals</p>
          <Fields className="p-0">
            <Field name="Anomaly" mono>
              {String(d.bot_score || 0)}
            </Field>
            <Field name="JA4" mono>
              {d.ja4}
            </Field>
            <Field name="Visitor" mono>
              {d.visitor_id}
            </Field>
          </Fields>
        </div>
      )}

      <div className="border-t border-line pt-4">
        <p className={section}>Request headers</p>
        <div className="overflow-hidden border border-edge bg-card text-[12px]">
          {headers.length === 0 && <p className="p-4 text-slate-500">No headers captured.</p>}
          {headers.map((k) => (
            <div key={k} className="flex flex-col gap-1 border-b border-line px-4 py-[9px] last:border-b-0 sm:flex-row sm:items-start sm:gap-3">
              <span className="shrink-0 pt-[1px] font-mono break-all text-slate-500 sm:w-[190px]">{k}</span>
              <span className="flex-1 font-mono break-all text-slate-700">{d.headers![k]}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Fields({ className, children }: { className?: string; children: ReactNode }) {
  return <dl className={cn("grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 px-4 py-3 text-[13px]", className)}>{children}</dl>;
}

function Field({ name, mono, title, children }: { name: string; mono?: boolean; title?: string; children: ReactNode }) {
  return (
    <>
      <dt className={cn(dt, "self-center")} title={title}>
        {name}
      </dt>
      <dd className={cn("break-all", mono && "font-mono text-[12px]")}>{children || "—"}</dd>
    </>
  );
}

const ghost = "rounded-sm border border-edge px-3 py-2 font-mono text-[11px] uppercase text-ink hover:bg-surface disabled:opacity-50";

// RuleActions: admin-only feedback on the rule that blocked, and a one-click
// exception for this service.
function RuleActions({ id }: { id: number }) {
  const feedback = useRuleFeedback(id);
  const exception = useLogException(id);
  const [msg, setMsg] = useState("");
  const busy = feedback.isPending || exception.isPending;
  const mark = (fp: boolean) => {
    setMsg("Saving…");
    feedback.mutate(fp, {
      onSuccess: () => setMsg(`Marked ${fp ? "false positive" : "correct"}.`),
      onError: (e) => setMsg(e.message || "Failed to save. Try again."),
    });
  };
  const except = () => {
    if (!window.confirm("Disable this rule for this service? The WAF reloads immediately.")) return;
    setMsg("Saving…");
    exception.mutate(undefined, {
      onSuccess: (r) => setMsg(`Rule disabled for ${r.service}.`),
      onError: (e) => setMsg(e.message || "Failed to save. Try again."),
    });
  };
  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <span className="w-full text-[11px] text-slate-500">Was this rule correct?</span>
      <button type="button" disabled={busy} onClick={() => mark(true)} className={ghost}>
        False positive
      </button>
      <button type="button" disabled={busy} onClick={() => mark(false)} className={ghost}>
        Correct block
      </button>
      <button type="button" disabled={busy} onClick={except} className={ghost}>
        Create exception
      </button>
      <span role="status" className="w-full text-[11px] text-slate-500">
        {msg}
      </span>
    </div>
  );
}
