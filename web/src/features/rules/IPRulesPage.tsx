import { useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import { Card, FormRow, Page, PageHeader, labelMono } from "@/components/layout/Page";
import { can } from "@/lib/boot";
import { fmtTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useIPRules, useIPSettings, useRemove, useWrite, type Adaptive, type Autoban, type IPRule } from "./api";
import { FormError, Num, Overview, RuleBadge, RuleList, ScopeAction, SettingsCard, Toggle, btn, field, fieldError, help, primary, tag } from "./shared";

export function IPRulesPage({ page }: { page: number }) {
  const rules = useIPRules(page);
  const settings = useIPSettings();
  const remove = useRemove("ip-rules");
  const d = rules.data;
  return (
    <Page>
      <PageHeader title="IP Rules" />
      {can("admin") && <AddIPRules />}
      <div className="grid grid-cols-1 items-start gap-6 md:grid-cols-2 xl:grid-cols-3">
        {settings.isError ? (
          <p role="alert" className="border border-edge bg-card p-6 text-red-600 md:col-span-2">
            Couldn't load the banning settings. Reload to try again.
          </p>
        ) : settings.data ? (
          <>
            <AutobanCard key={JSON.stringify(settings.data.autoban)} v={settings.data.autoban} />
            <AdaptiveCard key={JSON.stringify(settings.data.adaptive)} v={settings.data.adaptive} />
            <HoneypotCard key={settings.data.honeypot_paths.join("\n")} paths={settings.data.honeypot_paths} />
          </>
        ) : (
          <p className={cn(labelMono, "py-10 text-center md:col-span-2")}>Loading…</p>
        )}
        {d && <Overview block={d.block_count} allow={d.allow_count} what="traffic" />}
      </div>
      <Card cat="Firewall" title="Active IP Rules" action={d && <span className={cn(tag, "text-slate-600")}>{d.total} rules</span>}>
        {rules.isError ? (
          <p role="alert" className="py-6 text-red-600">
            Couldn't load the IP rules. Reload to try again.
          </p>
        ) : !d ? (
          <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>
        ) : (
          <RuleList<IPRule>
            rows={d.rules}
            id={(r) => r.id}
            label={(r) => r.ip}
            empty="No IP rules yet"
            remove={remove}
            row={(r) => <IPRow r={r} />}
            footer={
              d.total_pages > 1 && (
                <nav aria-label="Pages" className="flex items-center justify-between gap-3 border-t border-line px-3 pt-3">
                  {d.page > 1 ? (
                    <Link to="/ip-rules" search={{ page: d.page > 2 ? d.page - 1 : undefined }} className={btn}>
                      ← Prev
                    </Link>
                  ) : (
                    <span />
                  )}
                  <span className={labelMono}>
                    Page {d.page} of {d.total_pages}
                  </span>
                  {d.page < d.total_pages ? (
                    <Link to="/ip-rules" search={{ page: d.page + 1 }} className={btn}>
                      Next →
                    </Link>
                  ) : (
                    <span />
                  )}
                </nav>
              )
            }
          />
        )}
      </Card>
    </Page>
  );
}

function IPRow({ r }: { r: IPRule }) {
  return (
    <>
      <i
        aria-hidden
        className={cn(
          "hgi hgi-stroke hgi-rounded flex h-10 w-10 shrink-0 items-center justify-center rounded-sm text-base",
          r.rule_type === "block" ? "hgi-cancel-circle bg-red-50 text-red-600" : "hgi-checkmark-circle-02 bg-green-50 text-green-600",
        )}
      />
      <div className="min-w-[200px] flex-1">
        <p className="truncate font-mono text-[14px] font-semibold text-ink">{r.ip}</p>
        <p className="truncate text-[12px] text-slate-500">
          {r.app_name || "Global"} · {fmtTime(r.created_at)}
          {r.note && ` · ${r.note}`}
        </p>
      </div>
      {r.auto && (
        <span className={cn(tag, "text-amber-700")}>
          <span aria-hidden className="h-2 w-2 rounded-full bg-amber-500" />
          Auto
        </span>
      )}
      <span className={cn(tag, "text-slate-600")} title="Composite threat score (0-100)">
        Score {r.score > 0 ? r.score : "—"}
      </span>
      <RuleBadge type={r.rule_type} />
    </>
  );
}

function AddIPRules() {
  const add = useWrite<{ ip: string; app_name: string; rule_type: string }>("ip-rules", "/api/ip-rules");
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    add.mutate(
      { ip: String(f.get("ip")), app_name: String(f.get("app_name")), rule_type: String(f.get("rule_type")) },
      {
        onSuccess: (res) => {
          toast.success(res.added === 1 ? "Rule added." : `${res.added} rules added.`);
          form.reset();
        },
      },
    );
  };
  const ipErr = fieldError(add.error, "ip");
  return (
    <Card title="Add IP Rules">
      <form onSubmit={submit} className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 lg:grid-cols-[1.4fr_1fr_auto_auto]">
        <FormRow label="IP addresses" help="One per line (or comma separated), up to 500. CIDR ranges work." error={ipErr}>
          <textarea name="ip" rows={2} required placeholder={"1.2.3.4\n10.0.0.0/8"} className={cn(field, "resize-y font-mono")} />
        </FormRow>
        <ScopeAction error={add.error} />
        <button type="submit" disabled={add.isPending} className={cn(primary, "lg:mt-[22px]")}>
          <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-add-circle text-sm" />
          Add
        </button>
      </form>
      <FormError error={add.error} fields={["ip", "app_name", "rule_type"]} />
      <div className={cn(help, "mt-5 grid grid-cols-1 gap-2 border-t border-line pt-4 md:grid-cols-3")}>
        <p className="flex items-center gap-2">
          <RuleBadge type="block" /> deny all requests from this IP
        </p>
        <p className="flex items-center gap-2">
          <RuleBadge type="allow" /> whitelist, bypasses other blocks
        </p>
        <p>Per-app rules take priority over global ones.</p>
      </div>
    </Card>
  );
}

const num = (f: FormData, k: string) => Number(f.get(k));
const saved = () => toast.success("Saved and applied.");

function AutobanCard({ v }: { v: Autoban }) {
  const save = useWrite<Autoban>("ip-rules-settings", "/api/ip-rules/autoban", "PUT");
  const e = save.error;
  return (
    <SettingsCard
      title="Automatic banning"
      intro="Repeat offenders and severe attacks (SQL injection, RCE, XSS classes) are banned once they cross the score below, for the ban duration (0 hours = forever). Bans appear in the list as Auto rules and can be removed like any other."
      pending={save.isPending}
      error={e}
      fields={["threshold", "window", "ban_hours", "bad_codes", "bad_points"]}
      onSubmit={(f) =>
        save.mutate(
          {
            enabled: f.has("enabled"),
            threshold: num(f, "threshold"),
            window: num(f, "window"),
            ban_hours: num(f, "ban_hours"),
            bad_status: f.has("bad_status"),
            bad_codes: String(f.get("bad_codes")),
            bad_points: num(f, "bad_points"),
          },
          { onSuccess: saved },
        )
      }
    >
      <Toggle name="enabled" label="Ban IPs automatically" on={v.enabled} />
      <div className="grid grid-cols-3 gap-3">
        <Num name="threshold" label="Ban score" value={v.threshold} min={1} max={1000} error={e} />
        <Num name="window" label="Window (min)" value={v.window} min={1} max={1440} error={e} />
        <Num name="ban_hours" label="Ban (hours)" value={v.ban_hours} min={0} max={8760} error={e} />
      </div>
      <p className={help}>
        Scoring inside the window: critical WAF hit = 5, other WAF hit = 2, rate-limited = 1, unsolved bot challenge = 1. Requests another site's page makes the browser send don't count. Private and allow-listed IPs are never banned.
      </p>
      <Toggle name="bad_status" label="Score bad backend responses" on={v.bad_status} />
      <div className="grid grid-cols-3 gap-3">
        <Num name="bad_codes" label="Status codes" value={v.bad_codes} error={e} className="col-span-2" />
        <Num name="bad_points" label="Points per hit" value={v.bad_points} min={1} max={1000} error={e} />
      </div>
      <p className={help}>Catches scanners whose probes trip no WAF rule. Missing static assets (images, scripts, fonts, source maps), crawler files, verified crawlers and trusted IPs never count.</p>
    </SettingsCard>
  );
}

function AdaptiveCard({ v }: { v: Adaptive }) {
  const save = useWrite<Adaptive>("ip-rules-settings", "/api/ip-rules/adaptive", "PUT");
  const e = save.error;
  return (
    <SettingsCard
      title="Adaptive enforcement"
      intro="Scales the global rate limit and can force a bot challenge based on each client's current threat score (shown per rule below): tighter for high-risk IPs, relaxed for low-risk ones. Every request re-checks the live score, so this never blocks anyone outright the way Automatic banning does."
      pending={save.isPending}
      error={e}
      fields={["high_threshold", "low_threshold", "high_scale", "low_scale", "force_challenge"]}
      onSubmit={(f) =>
        save.mutate(
          {
            enabled: f.has("enabled"),
            high_threshold: num(f, "high_threshold"),
            low_threshold: num(f, "low_threshold"),
            high_scale: num(f, "high_scale"),
            low_scale: num(f, "low_scale"),
            force_challenge: num(f, "force_challenge"),
          },
          { onSuccess: saved },
        )
      }
    >
      <Toggle name="enabled" label="Adjust enforcement automatically" on={v.enabled} />
      <div className="grid grid-cols-2 gap-3">
        <Num name="high_threshold" label="High-risk threshold (score ≥)" value={v.high_threshold} min={1} max={100} error={e} />
        <Num name="low_threshold" label="Low-risk threshold (score ≤)" value={v.low_threshold} min={0} max={99} error={e} />
        <Num name="high_scale" label="High-risk rate scale" value={v.high_scale} min={0.05} max={1} step={0.05} error={e} />
        <Num name="low_scale" label="Low-risk rate scale" value={v.low_scale} min={1} max={5} step={0.05} error={e} />
        <Num name="force_challenge" label="Force bot challenge (score ≥)" value={v.force_challenge} min={1} max={100} error={e} className="col-span-2" />
      </div>
      <p className={help}>
        Rate scale multiplies the global limit's rate and burst: 0.3 means 30% of normal for high-risk IPs, 1.5 means 150% of normal for low-risk ones. Requests it blocks or challenges show up in Logs tagged <span className="font-mono">:adaptive</span>.
      </p>
    </SettingsCard>
  );
}

function HoneypotCard({ paths }: { paths: string[] }) {
  const save = useWrite<{ honeypot_paths: string }>("ip-rules-settings", "/api/ip-rules/honeypots", "PUT");
  const [text, setText] = useState(paths.join("\n"));
  const err = fieldError(save.error, "honeypot_paths");
  return (
    <SettingsCard
      title="Honeypot paths"
      intro="Paths only scanners ask for. A client that requests one and gets a 404 back is banned on that first hit (when Automatic banning is on). A path your backend really serves answers something else, so it never fires."
      pending={save.isPending}
      error={save.error}
      fields={["honeypot_paths"]}
      onSubmit={() => save.mutate({ honeypot_paths: text }, { onSuccess: saved })}
    >
      <FormRow label="Honeypot paths" error={err}>
        <textarea
          name="honeypot_paths"
          rows={6}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={"/wp-login.php\n/xmlrpc.php\n/phpmyadmin/"}
          className={cn(field, "resize-y font-mono text-[12px]")}
        />
      </FormRow>
      <p className={help}>
        One path per line, case-insensitive. A path ending in <span className="font-mono">/</span> covers everything under it. Hits show up in Logs as <span className="font-mono">honeypot</span>.
      </p>
    </SettingsCard>
  );
}
