import { useRef, useState, type ChangeEvent, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import { ArtHero } from "@/components/Art";
import { Card, FormRow, Page, PageHeader, labelMono } from "@/components/layout/Page";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { FormError, btn, field, fieldError, help, primary, tag } from "@/features/rules/shared";
import { ApiError } from "@/lib/api";
import { can } from "@/lib/boot";
import { fmtTime, plural } from "@/lib/format";
import { cn } from "@/lib/utils";
import {
  useAddException,
  useDeleteCustom,
  useDryRun,
  useRemoveException,
  useSaveCustom,
  useSetCustomEnabled,
  useSetFeedback,
  useWAF,
  type CustomRule,
  type DryRun,
  type Verdict,
  type WAFPage,
} from "./api";

// WAF Rules (issue #354): rule exceptions (global and per service), virtual
// patches, false-positive suggestions, top firing rules, and custom rules
// with a dry run against logged traffic. Every change reloads the WAF.

export function WAFRulesPage() {
  const { data, isError } = useWAF();
  const [editing, setEditing] = useState<CustomRule | null>(null);
  const editor = useRef<HTMLDivElement>(null);
  const body = (render: (d: WAFPage) => ReactNode) =>
    isError ? (
      <p role="alert" className="py-6 text-red-600">
        Couldn't load the WAF rules. Reload to try again.
      </p>
    ) : !data ? (
      <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>
    ) : (
      render(data)
    );
  const count = (n?: number, one = "rule") => n !== undefined && <span className={cn(tag, "text-slate-600")}>{plural(n, one)}</span>;
  return (
    <Page>
      <PageHeader title="WAF Rules" />
      <ArtHero art="sieve" eyebrow="Rule tuning" title="Tune CRS enforcement without losing visibility.">
        <p className="max-w-[56ch] text-[14px] leading-relaxed text-slate-600">
          Suppress false positives globally or per service, review the rules that fire most, and add your own. Every change reloads the WAF straight away, no restart needed.
        </p>
        {data && <Summary d={data} />}
      </ArtHero>
      {can("admin") && data && (
        <>
          <DisableRule services={data.services} />
          <div ref={editor}>
            <CustomEditor key={editing?.id ?? 0} rule={editing} services={data.services} done={() => setEditing(null)} />
          </div>
        </>
      )}
      <Card cat="Shipped with Palisade" title="Virtual Patches" action={count(data?.vpatches.length, "CVE")}>
        {body((d) => (
          <VPatches d={d} />
        ))}
      </Card>
      <div className="grid grid-cols-1 items-start gap-6 xl:grid-cols-2">
        <Card cat="Feedback" title="Suggested Exceptions" action={count(data?.suggestions.length, "suggestion")}>
          {body((d) => (
            <Suggestions d={d} />
          ))}
        </Card>
        <Card cat="Analytics" title="Top Firing Rules" action={<span className={cn(tag, "text-slate-600")}>Last 30 days</span>}>
          {body((d) => (
            <TopRules d={d} />
          ))}
        </Card>
      </div>
      <Card cat="Firewall" title="Custom Rules" action={count(data?.custom.length)}>
        {body((d) => (
          <CustomRules
            rules={d.custom}
            edit={(r) => {
              setEditing(r);
              editor.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
            }}
          />
        ))}
      </Card>
      <Card cat="Firewall" title="Rule Exceptions" action={count(data?.exceptions.length, "exception")}>
        {body((d) => (
          <Exceptions d={d} />
        ))}
      </Card>
    </Page>
  );
}

function Summary({ d }: { d: WAFPage }) {
  const patchesOn = d.vpatches.filter((p) => !p.global_off).length;
  return (
    <p className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-[12px] uppercase tracking-[.06em] text-ink">
      {!d.waf_enabled && (
        <span className="flex items-center gap-2 text-red-600">
          <span className="h-2 w-2 rounded-full bg-danger" />
          WAF disabled
        </span>
      )}
      <span>
        {patchesOn} of {plural(d.vpatches.length, "patch", "patches")} on
      </span>
      <span>{plural(d.exceptions.length, "exception")}</span>
      <span>{d.custom.filter((r) => r.enabled).length} custom on</span>
    </p>
  );
}

// Confirm asks before a change that reloads the WAF.
type Ask = { title: string; body: string; label: string; run: () => void };

function useConfirm() {
  const [ask, setAsk] = useState<Ask | null>(null);
  const dialog = (
    <Dialog open={ask !== null} onOpenChange={(open) => !open && setAsk(null)}>
      <DialogContent className="rounded-none border-edge bg-canvas sm:max-w-md">
        <DialogTitle className="text-[16px] text-ink">{ask?.title}</DialogTitle>
        <DialogDescription className="text-[13px] text-slate-600">{ask?.body}</DialogDescription>
        <DialogFooter>
          <button type="button" onClick={() => setAsk(null)} className={btn}>
            Cancel
          </button>
          <button
            type="button"
            onClick={() => {
              ask!.run();
              setAsk(null);
            }}
            className={cn(btn, "border-red-600 bg-red-600 text-white hover:bg-red-700")}
          >
            {ask?.label}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
  return [dialog, setAsk] as const;
}

function Failed({ error, what = "save" }: { error: unknown; what?: string }) {
  if (error == null) return null;
  return (
    <p role="alert" className="pb-3 text-[13px] text-red-600">
      {(error instanceof ApiError && error.message) || `Couldn't ${what}. Try again.`}
    </p>
  );
}

const scopeTag = (service: string) => <span className={cn(tag, "text-slate-600")}>{service || "Global"}</span>;
const danger = cn(btn, "min-h-9 border-red-300 px-3 text-red-600 hover:bg-red-50");
const rowBtn = cn(btn, "min-h-9 px-3");
const code = "bg-surface px-1 font-mono text-[11px]";

function ScopeSelect({ services, value, onChange, label = "Scope", all = "Global (all services)", error }: { services: string[]; value: string; onChange: (v: string) => void; label?: string; all?: string; error?: string }) {
  return (
    <FormRow label={label} error={error}>
      <select value={value} onChange={(e) => onChange(e.target.value)} className={field}>
        <option value="">{all}</option>
        {services.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
    </FormRow>
  );
}

function DisableRule({ services }: { services: string[] }) {
  const add = useAddException();
  const empty = { rule_id: "", service: "", reason: "" };
  const [form, setForm] = useState(empty);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const id = Number(form.rule_id) || 0;
    add.mutate(
      { rule_id: id, service: form.service, reason: form.reason },
      {
        onSuccess: () => {
          toast.success(`Rule ${id} is off ${form.service ? `for ${form.service}` : "everywhere"}.`);
          setForm(empty);
        },
      },
    );
  };
  return (
    <Card title="Disable Rule">
      <form onSubmit={submit} className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-[1fr_1fr_1.35fr_auto]">
        <FormRow label="CRS rule ID" error={fieldError(add.error, "rule_id")}>
          <input type="number" min={1} value={form.rule_id} onChange={(e) => setForm((f) => ({ ...f, rule_id: e.target.value }))} placeholder="e.g. 942100" className={cn(field, "font-mono")} />
        </FormRow>
        <ScopeSelect services={services} value={form.service} onChange={(service) => setForm((f) => ({ ...f, service }))} error={fieldError(add.error, "service")} />
        <FormRow label="Reason (optional)">
          <input value={form.reason} onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))} placeholder="e.g. false positive on the login form" className={field} />
        </FormRow>
        <button type="submit" disabled={add.isPending} className={cn(primary, "xl:mt-[22px]")}>
          <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-security-block text-sm" />
          Disable Rule
        </button>
        <div className="md:col-span-2 xl:col-span-4">
          <FormError error={add.error} fields={["rule_id", "service"]} />
        </div>
      </form>
      <div className={cn(help, "mt-4 grid grid-cols-1 gap-2 border-t border-line pt-4 leading-[1.6] md:grid-cols-3")}>
        <p>
          A disabled rule is removed with <code className={code}>SecRuleRemoveById</code> and the WAF reloads at once.
        </p>
        <p>Leave the scope on Global to disable it everywhere, or pick a service: every other service keeps enforcing it.</p>
        <p>Turn it back on any time from Rule Exceptions below.</p>
      </div>
    </Card>
  );
}

function CustomEditor({ rule, services, done }: { rule: CustomRule | null; services: string[]; done: () => void }) {
  const save = useSaveCustom();
  const dry = useDryRun();
  const [form, setForm] = useState({ rule: rule?.rule ?? "", service: rule?.service ?? "", note: rule?.note ?? "", limit: "500" });
  const set = (k: keyof typeof form) => (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    dry.reset();
    save.mutate(
      { id: rule?.id, rule: form.rule, service: form.service, note: form.note },
      {
        onSuccess: () => {
          toast.success(rule ? "Rule updated and live." : "Rule saved and live.");
          setForm({ rule: "", service: "", note: "", limit: form.limit });
          done();
        },
      },
    );
  };
  const run = () => {
    save.reset();
    dry.mutate({ rule: form.rule, limit: Number(form.limit) || 500 });
  };
  const ruleErr = fieldError(save.error, "rule") ?? fieldError(dry.error, "rule");
  return (
    <Card title="Write Custom Rule" action={rule && <span className={cn(tag, "text-slate-600")}>Editing #{rule.id}</span>}>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <FormRow label="Rule" error={ruleErr}>
          <textarea
            value={form.rule}
            onChange={set("rule")}
            rows={5}
            autoFocus={rule !== null}
            spellCheck={false}
            placeholder={`SecRule ARGS "@contains badword" "id:1000001,phase:2,deny,status:403,msg:'test'"`}
            className={cn(field, "min-h-28 resize-y font-mono text-[12px]")}
          />
        </FormRow>
        <div className="grid grid-cols-1 items-start gap-4 md:grid-cols-[1fr_1.35fr_auto]">
          <ScopeSelect services={services} value={form.service} onChange={(service) => setForm((f) => ({ ...f, service }))} error={fieldError(save.error, "service")} />
          <FormRow label="Note (optional)">
            <input value={form.note} onChange={set("note")} placeholder="e.g. CVE-2026-1234 probe" className={field} />
          </FormRow>
          <FormRow label="Replay last N requests">
            <input type="number" min={1} max={2000} value={form.limit} onChange={set("limit")} className={cn(field, "md:w-32")} />
          </FormRow>
        </div>
        <FormError error={save.error} fields={["rule", "service"]} />
        <FormError error={dry.error} fields={["rule"]} />
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={run} disabled={dry.isPending} className={btn}>
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-play text-sm" />
            Dry run
          </button>
          <button type="submit" disabled={save.isPending} className={primary}>
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-floppy-disk text-sm" />
            {rule ? "Update rule" : "Save rule"}
          </button>
          {rule && (
            <button type="button" onClick={done} className="min-h-11 px-2 text-[13px] text-slate-500 hover:text-ink">
              Cancel edit
            </button>
          )}
          {dry.isPending && (
            <span role="status" className={help}>
              Compiling engines and replaying…
            </span>
          )}
        </div>
      </form>
      {dry.data && <DryRunResult r={dry.data} />}
      <div className={cn(help, "mt-5 grid grid-cols-1 gap-2 border-t border-line pt-4 leading-[1.6] md:grid-cols-3")}>
        <p>
          Saving compiles the rule and makes it live on the next request. Only <code className={code}>SecRule</code> and <code className={code}>SecAction</code> are allowed, with ids from 1000000 to 1999999.
        </p>
        <p>Dry run first: it replays logged method, URL and headers through the current rules with and without yours, and lists each request whose verdict changes. Bodies aren't logged, so body rules can't match.</p>
        <p>Scope a rule to one service to apply it only there. Turn it off or delete it from Custom Rules below.</p>
      </div>
    </Card>
  );
}

function VerdictTag({ v }: { v: Verdict }) {
  return (
    <span className={cn(tag, v.blocked ? "text-red-600" : "text-green-700")}>
      <span aria-hidden className={cn("h-2 w-2 rounded-full", v.blocked ? "bg-danger" : "bg-success")} />
      {v.blocked ? `Block${v.rule_id ? ` · ${v.rule_id}` : ""}` : "Pass"}
    </span>
  );
}

function DryRunResult({ r }: { r: DryRun }) {
  return (
    <div className="mt-4">
      <p role="status" className="mb-2 text-[13px] text-slate-600">
        Replayed {plural(r.replayed, "request")} · <strong className="text-ink">{r.hits.length}</strong> would change verdict.
      </p>
      {r.hits.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className={cn(labelMono, "border-b border-edge text-left")}>
                <th className="px-3 py-2 font-medium">Log</th>
                <th className="px-3 py-2 font-medium">Request</th>
                <th className="px-3 py-2 font-medium">Now</th>
                <th className="px-3 py-2 font-medium">With your rule</th>
              </tr>
            </thead>
            <tbody>
              {r.hits.map((h) => (
                <tr key={h.id} className="border-b border-line align-top last:border-b-0">
                  <td className="px-3 py-2 font-mono text-slate-500">#{h.id}</td>
                  <td className="break-all px-3 py-2 font-mono text-ink">
                    <strong>{h.method}</strong> {h.host}
                    {h.target} <span className="font-sans text-[11px] text-slate-500">{h.app}</span>
                  </td>
                  <td className="px-3 py-2">
                    <VerdictTag v={h.before} />
                  </td>
                  <td className="px-3 py-2">
                    <VerdictTag v={h.after} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Status({ on, label }: { on: boolean; label?: string }) {
  return (
    <span className={cn(tag, "text-ink")}>
      <span aria-hidden className={cn("h-2 w-2 rounded-full", on ? "bg-success" : "bg-warning")} />
      {label ?? (on ? "Active" : "Disabled")}
    </span>
  );
}

function VPatches({ d }: { d: WAFPage }) {
  const add = useAddException();
  const [dialog, ask] = useConfirm();
  const [scope, setScope] = useState<Record<number, string>>({});
  return (
    <>
      <p className={cn(help, "mb-3 leading-[1.6]")}>
        Rules for actively exploited CVEs, on for every service and blocking. They load ahead of CRS, so a hit is logged under the patch's own rule id and counts as critical for autoban. Turning one off adds a normal
        rule exception. New patches arrive with Palisade releases.
      </p>
      <Failed error={add.error} />
      <div className="overflow-x-auto">
        <table className="w-full text-[13px]">
          <thead>
            <tr className={cn(labelMono, "border-b border-edge text-left")}>
              <th className="px-3 py-2 font-medium">CVE</th>
              <th className="px-3 py-2 font-medium">Product</th>
              <th className="px-3 py-2 text-right font-medium">Hits</th>
              <th className="px-3 py-2 font-medium">Status</th>
              {can("admin") && <th className="px-3 py-2" />}
            </tr>
          </thead>
          <tbody>
            {d.vpatches.map((p) => {
              const svc = scope[p.rule_id] ?? "";
              return (
                <tr key={p.rule_id} className="border-b border-line align-top last:border-b-0 hover:bg-surface">
                  <td className="whitespace-nowrap px-3 py-3">
                    <a href={p.reference} target="_blank" rel="noopener noreferrer" className="font-mono font-medium text-ink underline hover:text-slate-600">
                      {p.cve}
                    </a>
                    <p className="font-mono text-[11px] text-slate-500">
                      rule {p.rule_id} · added {p.added}
                    </p>
                  </td>
                  <td className="min-w-[200px] px-3 py-3 text-slate-600">{p.product}</td>
                  <td className="px-3 py-3 text-right font-mono tabular-nums text-ink">{p.hits.toLocaleString("en-GB")}</td>
                  <td className="px-3 py-3">
                    <div className="flex flex-wrap gap-1">
                      {p.global_off ? <Status on={false} label="Off everywhere" /> : <Status on />}
                      {!p.global_off && p.off_for.map((s) => <Status key={s} on={false} label={`Off: ${s}`} />)}
                    </div>
                  </td>
                  {can("admin") && (
                    <td className="px-3 py-3">
                      {!p.global_off && (
                        <div className="flex items-center justify-end gap-2">
                          <select aria-label={`Turn ${p.cve} off for`} value={svc} onChange={(e) => setScope((s) => ({ ...s, [p.rule_id]: e.target.value }))} className={cn(field, "min-h-9 w-auto py-1 text-[12px]")}>
                            <option value="">All services</option>
                            {d.services.map((s) => (
                              <option key={s} value={s}>
                                {s}
                              </option>
                            ))}
                          </select>
                          <button
                            type="button"
                            className={danger}
                            onClick={() =>
                              ask({
                                title: `Turn off ${p.cve}?`,
                                body: `${svc ? svc : "Every service"} stops blocking this exploit. The WAF reloads at once.`,
                                label: "Turn off",
                                run: () => add.mutate({ rule_id: p.rule_id, service: svc, reason: `Virtual patch ${p.cve} turned off` }, { onSuccess: () => toast.success(`${p.cve} is off${svc ? ` for ${svc}` : ""}.`) }),
                              })
                            }
                          >
                            Turn off
                          </button>
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {dialog}
    </>
  );
}

function Suggestions({ d }: { d: WAFPage }) {
  const add = useAddException();
  const fb = useSetFeedback();
  const admin = can("admin");
  const [form, setForm] = useState({ threshold: String(d.feedback.threshold), window_days: String(d.feedback.window_days) });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    fb.mutate({ threshold: Number(form.threshold) || 0, window_days: Number(form.window_days) || 0 }, { onSuccess: () => toast.success("Saved.") });
  };
  return (
    <>
      <Failed error={add.error} />
      {d.suggestions.length === 0 ? (
        <p className={cn(help, "py-6 text-center")}>No suggestions yet. Mark a blocked request as a false positive on the Logs page to start collecting signal.</p>
      ) : (
        <ul>
          {d.suggestions.map((s) => (
            <li key={`${s.service}/${s.rule_id}`} className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line py-3 first:pt-0 last:border-b-0">
              <div className="min-w-0 flex-1">
                <p className="flex items-center gap-2 font-mono text-[14px] font-medium text-ink">
                  Rule {s.rule_id} {scopeTag(s.service)}
                </p>
                <p className="text-[12px] text-slate-500">
                  Marked false positive {plural(s.false_positives, "time")} · last {fmtTime(s.last_marked)}
                </p>
              </div>
              {admin && (
                <button
                  type="button"
                  disabled={add.isPending}
                  className={rowBtn}
                  onClick={() =>
                    add.mutate(
                      { rule_id: s.rule_id, service: s.service, reason: `Suggested: ${s.false_positives} false-positive marks in the last ${d.feedback.window_days} days` },
                      { onSuccess: () => toast.success(`Rule ${s.rule_id} is off ${s.service ? `for ${s.service}` : "everywhere"}.`) },
                    )
                  }
                >
                  Add exception
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={submit} className="mt-4 border-t border-line pt-4">
        <fieldset disabled={!admin} className="flex flex-wrap items-start gap-3">
          <div className="w-40">
            <FormRow label="False-positive marks" error={fieldError(fb.error, "threshold")}>
              <input type="number" min={1} max={1000} value={form.threshold} onChange={(e) => setForm((f) => ({ ...f, threshold: e.target.value }))} className={field} />
            </FormRow>
          </div>
          <div className="w-40">
            <FormRow label="Window (days)" error={fieldError(fb.error, "window_days")}>
              <input type="number" min={1} max={90} value={form.window_days} onChange={(e) => setForm((f) => ({ ...f, window_days: e.target.value }))} className={field} />
            </FormRow>
          </div>
          {admin && (
            <button type="submit" disabled={fb.isPending} className={cn(btn, "mt-[22px]")}>
              Save
            </button>
          )}
        </fieldset>
        <div className="mt-2">
          <FormError error={fb.error} fields={["threshold", "window_days"]} />
        </div>
        <p className={cn(help, "mt-2 leading-[1.6]")}>A rule is suggested after this many false-positive marks and no true-positive marks for the same service within the window. Nothing is ever disabled automatically.</p>
      </form>
    </>
  );
}

function TopRules({ d }: { d: WAFPage }) {
  const add = useAddException();
  const [dialog, ask] = useConfirm();
  if (d.top_rules.length === 0) return <p className={cn(labelMono, "py-10 text-center")}>No WAF blocks recorded yet</p>;
  return (
    <>
      <Failed error={add.error} />
      <div className="overflow-x-auto">
        <table className="w-full text-[13px]">
          <thead>
            <tr className={cn(labelMono, "border-b border-edge text-left")}>
              <th className="px-3 py-2 font-medium">Rule</th>
              <th className="px-3 py-2 text-right font-medium">Hits</th>
              <th className="px-3 py-2 font-medium">Last seen</th>
              <th className="px-3 py-2 font-medium">Status</th>
              {can("admin") && <th className="px-3 py-2" />}
            </tr>
          </thead>
          <tbody>
            {d.top_rules.map((r) => (
              <tr key={r.rule_id} className="border-b border-line last:border-b-0 hover:bg-surface">
                <td className="px-3 py-3 font-mono font-medium text-ink">{r.rule_id}</td>
                <td className="px-3 py-3 text-right font-mono tabular-nums text-ink">{r.hits.toLocaleString("en-GB")}</td>
                <td className="whitespace-nowrap px-3 py-3 text-slate-500">{fmtTime(r.last_seen)}</td>
                <td className="px-3 py-3">
                  <Status on={!r.disabled} />
                </td>
                {can("admin") && (
                  <td className="px-3 py-3 text-right">
                    {!r.disabled && (
                      <button
                        type="button"
                        className={danger}
                        onClick={() =>
                          ask({
                            title: `Disable rule ${r.rule_id}?`,
                            body: "It stops matching on every service. The WAF reloads at once.",
                            label: "Disable",
                            run: () => add.mutate({ rule_id: r.rule_id, service: "", reason: "" }, { onSuccess: () => toast.success(`Rule ${r.rule_id} is off everywhere.`) }),
                          })
                        }
                      >
                        Disable
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {dialog}
    </>
  );
}

const firstLine = (r: CustomRule) => r.note || r.rule.split("\n")[0]!;

function CustomRules({ rules, edit }: { rules: CustomRule[]; edit: (r: CustomRule) => void }) {
  const toggle = useSetCustomEnabled();
  const remove = useDeleteCustom();
  const [dialog, ask] = useConfirm();
  const admin = can("admin");
  if (rules.length === 0) return <p className={cn(labelMono, "py-10 text-center")}>No custom rules yet</p>;
  return (
    <>
      <Failed error={toggle.error ?? remove.error} />
      <ul>
        {rules.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line py-3 first:pt-0 last:border-b-0">
            {admin ? (
              <input
                type="checkbox"
                aria-label={`${firstLine(r)} on`}
                checked={r.enabled}
                onChange={() => toggle.mutate({ id: r.id, enabled: !r.enabled })}
                className="h-5 w-5 shrink-0 cursor-pointer accent-ink"
              />
            ) : (
              <Status on={r.enabled} label={r.enabled ? "On" : "Off"} />
            )}
            <div className="min-w-0 flex-1 basis-64">
              <p className={cn("truncate font-mono text-[13px] text-ink", !r.enabled && "opacity-50")} title={r.rule}>
                {r.rule}
              </p>
              <p className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-slate-500">
                {scopeTag(r.service)}
                <span>
                  {r.note || "No note"} · {fmtTime(r.created_at)}
                </span>
              </p>
            </div>
            {admin && (
              <div className="flex items-center gap-2">
                <button type="button" aria-label={`Edit ${firstLine(r)}`} onClick={() => edit(r)} className={rowBtn}>
                  Edit
                </button>
                <button
                  type="button"
                  aria-label={`Delete ${firstLine(r)}`}
                  onClick={() =>
                    ask({ title: "Delete this custom rule?", body: "It stops matching at once. The WAF reloads.", label: "Delete", run: () => remove.mutate(r.id, { onSuccess: () => toast.success("Custom rule deleted.") }) })
                  }
                  className="flex h-11 w-11 items-center justify-center rounded-sm text-slate-500 hover:bg-red-50 hover:text-red-600 sm:h-8 sm:w-8"
                >
                  <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-delete-02 text-[14px]" />
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>
      {dialog}
    </>
  );
}

function Exceptions({ d }: { d: WAFPage }) {
  const remove = useRemoveException();
  const [dialog, ask] = useConfirm();
  if (d.exceptions.length === 0) return <p className={cn(labelMono, "py-10 text-center")}>All WAF rules are active</p>;
  return (
    <>
      <Failed error={remove.error} what="turn the rule back on" />
      <ul>
        {d.exceptions.map((e) => {
          const name = `rule ${e.rule_id} ${e.service ? `for ${e.service}` : "everywhere"}`;
          return (
            <li key={`${e.service ? "s" : "g"}${e.id}`} className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line py-3 first:pt-0 last:border-b-0">
              <div className="min-w-0 flex-1">
                <p className="flex items-center gap-2 font-mono text-[14px] font-medium text-ink">
                  Rule {e.rule_id} {scopeTag(e.service)}
                </p>
                <p className="truncate text-[12px] text-slate-500">
                  {e.reason || "No reason given"} · {fmtTime(e.created_at)}
                </p>
              </div>
              {can("admin") && (
                <button
                  type="button"
                  aria-label={`Re-enable ${name}`}
                  onClick={() =>
                    ask({
                      title: `Re-enable ${name}?`,
                      body: "The rule matches again from the next request.",
                      label: "Re-enable",
                      run: () => remove.mutate(e, { onSuccess: () => toast.success(`Rule ${e.rule_id} is back on.`) }),
                    })
                  }
                  className={rowBtn}
                >
                  Re-enable
                </button>
              )}
            </li>
          );
        })}
      </ul>
      {dialog}
    </>
  );
}
