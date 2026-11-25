import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { ArtHero } from "@/components/Art";
import { Card, FormRow, Page, PageHeader, labelMono } from "@/components/layout/Page";
import { FormError, btn, field, help, primary, tag } from "@/features/rules/shared";
import { fmtTime, plural } from "@/lib/format";
import { boot, can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { ServiceDialog } from "./ServiceDialog";
import { useAddService, useCacheStats, useServices, type NewService, type Service, type ServicesPage as Data } from "./api";

// Services (issue #356): the add wizard, every configured service with its
// health and what it has turned on, and the shared cache's numbers. Each
// service's settings open in one dialog, read-only for viewers.

export function ServicesPage() {
  const q = useServices();
  const [open, setOpen] = useState<number | null>(null);
  const svc = q.data?.services.find((s) => s.id === open);
  return (
    <Page>
      <PageHeader title="Services" />
      <ArtHero art="rack" eyebrow="Protected routing" title="Every route, its backends and the checks in front.">
        <p className="max-w-[56ch] text-[14px] leading-relaxed text-slate-600">
          Match requests by host or path, send them to one or more backends, then tune health checks, TLS, caching, bot protection and limits per service.
        </p>
        {q.data && <Summary d={q.data} />}
      </ArtHero>
      {can("admin") && <AddService onAdded={(name) => toast.success(`Added ${name}. Its settings are under Edit.`)} />}
      <Card cat="Routing" title="Configured Services" action={q.data && <span className={cn(tag, "text-slate-600")}>{plural(q.data.services.length, "service")}</span>}>
        {q.isError ? (
          <p role="alert" className="py-6 text-red-600">
            Couldn't load the services. Reload to try again.
          </p>
        ) : !q.data ? (
          <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>
        ) : (
          <ServiceList services={q.data.services} onOpen={setOpen} />
        )}
      </Card>
      <CacheStatsCard />
      {q.data && svc && <ServiceDialog d={q.data} s={svc} onClose={() => setOpen(null)} />}
    </Page>
  );
}

function Summary({ d }: { d: Data }) {
  const down = d.services.filter((s) => s.known && !s.healthy).length;
  const tls = d.services.filter((s) => s.host && s.tls.mode).length;
  return (
    <p className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-[12px] uppercase tracking-[.06em] text-ink">
      <span>{plural(d.services.length, "service")}</span>
      <span>
        {tls} of {d.services.filter((s) => s.host).length} host services on TLS
      </span>
      {down > 0 && (
        <span className="flex items-center gap-2 text-red-600">
          <span className="h-2 w-2 rounded-full bg-danger" />
          {down} unreachable
        </span>
      )}
    </p>
  );
}

export const healthDot = (known: boolean, healthy: boolean) => (!known ? "bg-slate-300" : healthy ? "bg-success" : "bg-danger");
const healthTitle = (known: boolean, healthy: boolean) =>
  !known ? "No traffic seen yet, health unknown" : healthy ? "Reachable: the last real request succeeded" : "Unreachable: the last real request failed";

function ServiceList({ services, onOpen }: { services: Service[]; onOpen: (id: number) => void }) {
  if (services.length === 0) return <p className={cn(labelMono, "py-10 text-center")}>No services configured yet</p>;
  const admin = can("admin");
  return (
    <ul>
      {services.map((s) => (
        <li key={s.id} className="flex flex-col gap-3 border-b border-line py-3 last:border-b-0 sm:flex-row sm:items-center">
          <div className="relative flex h-10 w-10 shrink-0 items-center justify-center border border-edge">
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-cloud-server text-base text-ink" />
            <span role="img" aria-label={healthTitle(s.known, s.healthy)} title={healthTitle(s.known, s.healthy)} className={cn("absolute -right-px -bottom-px h-3 w-3 rounded-full border-2 border-card", healthDot(s.known, s.healthy))} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="truncate font-mono text-[14px] font-medium text-ink">{s.name}</span>
              <span className={cn(tag, "text-slate-600")}>
                <span aria-hidden className={cn("h-2 w-2 rounded-full", s.host ? "bg-info" : "bg-warning")} />
                {s.host ? "host" : "prefix"}
              </span>
              {s.docker && (
                <span className={cn(tag, "text-slate-600")} title="Created from container labels">
                  <span aria-hidden className="h-2 w-2 rounded-full bg-info" />
                  docker
                </span>
              )}
            </div>
            <p className="truncate font-mono text-[12px] text-slate-500">
              {s.host ? [s.host, ...s.hosts.aliases].join(", ") : s.prefix} → {s.backends.urls[0] ?? "no running container"}
              {s.backends.urls.length > 1 && ` +${s.backends.urls.length - 1}`}
            </p>
            {s.backends.urls.length > 1 && (
              <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
                {s.backends.health?.map((b) => (
                  <span key={b.url} className="inline-flex min-w-0 items-center gap-[5px] font-mono text-[11px] text-slate-500" title={!b.known ? "Not reached or checked yet" : b.healthy ? "In rotation" : "Down, out of rotation"}>
                    <span aria-hidden className={cn("h-2 w-2 shrink-0 rounded-full", healthDot(b.known, b.healthy))} />
                    <span className="truncate">{b.url}</span>
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2 sm:max-w-[55%] sm:justify-end">
            {badges(s).map(([label, dot]) => (
              <span key={label} className={cn(tag, "normal-case text-slate-600")}>
                <span aria-hidden className={cn("h-2 w-2 rounded-full", dot)} />
                {label}
              </span>
            ))}
            <span className="ml-1 whitespace-nowrap text-[12px] text-slate-500">{fmtTime(s.created_at)}</span>
            <button type="button" onClick={() => onOpen(s.id)} aria-label={`${admin ? "Edit" : "View"} ${s.name}`} className={btn}>
              <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded text-xs", admin ? "hgi-settings-01" : "hgi-view")} />
              {admin ? "Edit" : "View"}
            </button>
          </div>
        </li>
      ))}
    </ul>
  );
}

// badges lists what a service has turned on, as the HTMX rows did: a label
// and a dot, amber where it blocks traffic.
export function badges(s: Service): [string, string][] {
  const out: [string, string][] = [];
  const add = (on: unknown, label: string, dot = "bg-info") => on && out.push([label, dot]);
  const mode = (m: string, label: string, strict = "enforce") => add(m && m !== "off", `${label}: ${m}`, m === strict ? "bg-warning" : "bg-slate-400");
  if (s.host) {
    if (s.tls.mode === "custom") add(true, s.tls.cert_name || "Custom cert", "bg-success");
    else if (s.tls.mode === "auto") add(true, "Auto TLS (Let's Encrypt)");
    else add(true, "No TLS", "bg-slate-400");
  }
  add(s.rate_limit.rps > 0, `${s.rate_limit.rps}/s`, "bg-warning");
  add(s.bot.mode !== "inherit", `Bot: ${s.bot.mode}`, s.bot.mode === "always" ? "bg-warning" : "bg-slate-400");
  add(s.cache.enabled, "Cached");
  add(s.cache.by_session, "Cached (session)");
  add(s.tls.http3, "HTTP/3");
  add(s.compress, "Compressed");
  add(s.bot.breach_action, `Leaked passwords: ${s.bot.breach_action}`, "bg-success");
  add(Object.keys(s.bot.ai).length, "AI crawlers: custom", "bg-warning");
  add(s.bot.login_paths.length, "Login protected", "bg-success");
  add(s.uploads.large_js, "Large JS uploads", "bg-warning");
  mode(s.schema.mode, "Schema");
  mode(s.openapi_mode, "OpenAPI");
  add(s.csp.mode !== "off", `CSP: ${plural(s.csp.scripts?.length ?? 0, "script source")}${s.csp.full ? " · inventory full" : ""}`, s.csp.full ? "bg-warning" : "bg-slate-400");
  mode(s.mcp.mode, "MCP");
  mode(s.jwt.mode, "JWT");
  mode(s.responses, "Responses", "block");
  add(s.gate.maintenance, s.gate.start ? "Maintenance scheduled" : "Maintenance", "bg-warning");
  add(s.gate.waiting_room, `Waiting room: ${s.gate.max_active}`, "bg-slate-400");
  mode(s.tls.mtls.mode, "mTLS", "required");
  return out;
}

const steps = ["Name", "Match", "Backend", "Review"] as const;
const blank: NewService = { name: "", match_type: "host", match_value: "", backend: "", rate_limit_rps: 0, rate_limit_burst: 0 };

// AddService is the guided flow: name, match rule, backend (probed by the
// server before it is saved), then a review.
function AddService({ onAdded }: { onAdded: (name: string) => void }) {
  const add = useAddService();
  const [step, setStep] = useState(0);
  const [f, setF] = useState(blank);
  const [missing, setMissing] = useState(false);
  const required = [f.name, f.match_value, f.backend][step];
  const next = (e: FormEvent) => {
    e.preventDefault();
    if (step < 3) {
      if (!required?.trim()) return setMissing(true);
      setMissing(false);
      return setStep(step + 1);
    }
    add.mutate(f, {
      onSuccess: () => {
        onAdded(f.name.trim());
        setF(blank);
        setStep(0);
      },
    });
  };
  const set = <K extends keyof NewService>(k: K, v: NewService[K]) => setF((x) => ({ ...x, [k]: v }));
  const err = missing ? "This field is required." : undefined;
  return (
    <Card title="Add Service" className="border-t-4 border-t-edge">
      <ol aria-label="Steps" className="mb-5 grid grid-cols-4 gap-[6px]">
        {steps.map((s, i) => (
          <li key={s} aria-current={i === step ? "step" : undefined} className={cn("border-t-4 pt-1 font-mono text-[11px] uppercase tracking-[.04em]", i <= step ? "border-ink text-ink" : "border-line text-slate-500")}>
            {s}
          </li>
        ))}
      </ol>
      <form onSubmit={next} noValidate className="flex flex-col gap-4">
        {step === 0 && (
          <FormRow label="Service name" error={err} help="A friendly name for this backend in logs and rules.">
            <input autoFocus value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. blog, api, admin-panel" className={field} />
          </FormRow>
        )}
        {step === 1 && (
          <>
            <fieldset className="flex gap-4">
              <legend className={cn(labelMono, "mb-2")}>Match incoming requests by</legend>
              {(["host", "prefix"] as const).map((m) => (
                <label key={m} className="flex min-h-11 cursor-pointer items-center gap-2 text-[14px] text-ink">
                  <input type="radio" name="match_type" checked={f.match_type === m} onChange={() => set("match_type", m)} className="accent-ink" />
                  {m === "host" ? "Host header" : "Path prefix"}
                </label>
              ))}
            </fieldset>
            <FormRow label={f.match_type === "host" ? "Host" : "Path prefix"} error={err} help="Host matches the request's Host header exactly; prefix matches the start of the URL path.">
              <input autoFocus value={f.match_value} onChange={(e) => set("match_value", e.target.value)} placeholder={f.match_type === "host" ? "blog.example.com" : "/api"} className={cn(field, "font-mono")} />
            </FormRow>
          </>
        )}
        {step === 2 && (
          <>
            <FormRow label="Backend URL" error={err} help="Where traffic goes once it has passed inspection. It must answer before the service is saved.">
              <input autoFocus value={f.backend} onChange={(e) => set("backend", e.target.value)} placeholder="http://127.0.0.1:3000" className={cn(field, "font-mono")} />
            </FormRow>
            <div className="grid grid-cols-1 gap-3 border-t border-line pt-4 sm:grid-cols-2">
              <FormRow label="Requests / second (optional)">
                <input type="number" min={0} step={0.1} value={f.rate_limit_rps || ""} onChange={(e) => set("rate_limit_rps", Number(e.target.value))} placeholder="e.g. 10" className={field} />
              </FormRow>
              <FormRow label="Burst (optional)">
                <input type="number" min={0} value={f.rate_limit_burst || ""} onChange={(e) => set("rate_limit_burst", Number(e.target.value))} placeholder="auto (2× RPS)" className={field} />
              </FormRow>
              <p className={cn(help, "sm:col-span-2")}>Leave blank to use the global limit from Settings.</p>
            </div>
          </>
        )}
        {step === 3 && (
          <dl className="flex flex-col gap-2 bg-surface px-4 py-3 text-[13px]">
            {[
              ["Name", f.name],
              [f.match_type === "host" ? "Host" : "Prefix", f.match_value],
              ["Backend", f.backend],
              ["Rate limit", f.rate_limit_rps ? `${f.rate_limit_rps}/s, burst ${f.rate_limit_burst || "auto"}` : "Global"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-4">
                <dt className="text-slate-500">{k}</dt>
                <dd className="min-w-0 break-all text-right font-mono text-ink">{v}</dd>
              </div>
            ))}
          </dl>
        )}
        {step === 3 && <FormError error={add.error} fields={[]} />}
        <div className="flex flex-col gap-2 sm:flex-row">
          {step > 0 && (
            <button type="button" onClick={() => setStep(step - 1)} className={btn}>
              Back
            </button>
          )}
          <button type="submit" disabled={add.isPending} className={cn(primary, "sm:min-w-[160px]")}>
            {step < 3 ? (
              "Next"
            ) : (
              <>
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-add-circle text-sm" />
                {add.isPending ? "Checking the backend…" : "Create service"}
              </>
            )}
          </button>
        </div>
      </form>
    </Card>
  );
}

function CacheStatsCard() {
  const q = useCacheStats();
  const d = q.data;
  const settings = (
    <a href={`${boot.admin}/settings#settings-infrastructure`} className="text-ink underline">
      Settings
    </a>
  );
  return (
    <Card cat="Varnish" title="Cache performance" action={<span className={cn(tag, "text-slate-600")}>last 24h</span>}>
      {q.isError ? (
        <p role="alert" className="text-red-600">
          Couldn't load the cache numbers.
        </p>
      ) : !d ? (
        <p className={cn(labelMono, "py-6 text-center")}>Loading…</p>
      ) : !d.enabled ? (
        <p className="text-[13px] text-slate-500">The Varnish integration is off. Turn it on in {settings}, then turn on caching per service.</p>
      ) : (
        <div className="flex flex-col gap-4">
          {d.stats_error ? (
            <p className="text-[12px] leading-normal text-amber-700">
              Varnish counters unavailable: <span className="font-mono">{d.stats_error}</span>. The WAF's service user needs read access to varnishd's shared memory (membership in the <span className="font-mono">varnish</span> group).
            </p>
          ) : (
            d.stats && (
              <>
                <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  {(
                    [
                      ["Hit ratio", d.stats.ratio],
                      ["Objects", d.stats.objects],
                      ["Memory", `${d.stats.used} / ${d.stats.total}`],
                      ["Evicted", d.stats.evicted],
                    ] as const
                  ).map(([k, v]) => (
                    <div key={k}>
                      <dt className={labelMono}>{k}</dt>
                      <dd className={cn("font-mono text-[18px] font-medium", k === "Evicted" && d.stats!.evicted ? "text-amber-700" : "text-ink")}>{v}</dd>
                    </div>
                  ))}
                </dl>
                {d.stats.evicted > 0 && (
                  <p className={help}>
                    All cached services share one storage pool, and it has filled up: Varnish is evicting objects to make room, so a busy service can push out a quiet one's cache. Raise <span className="font-mono">-s malloc</span> in the varnish
                    systemd override if this keeps growing.
                  </p>
                )}
              </>
            )
          )}
          {d.services?.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className={cn(labelMono, "border-b border-edge text-left")}>
                    <th className="py-2 pr-2 font-medium">Service</th>
                    <th className="px-2 py-2 text-right font-medium">Hits</th>
                    <th className="px-2 py-2 text-right font-medium">Misses</th>
                    <th className="px-2 py-2 text-right font-medium" title="Not cacheable: authenticated, session, or marked uncacheable by the backend">
                      Pass
                    </th>
                    <th className="px-2 py-2 text-right font-medium" title="Varnish could not serve these, so they went straight to the backend">
                      Errors
                    </th>
                    <th className="py-2 pl-2 text-right font-medium">Hit ratio</th>
                  </tr>
                </thead>
                <tbody>
                  {d.services.map((r) => (
                    <tr key={r.app} className="border-b border-line last:border-b-0">
                      <td className="py-2 pr-2 font-semibold text-ink">{r.app}</td>
                      <td className="px-2 py-2 text-right font-mono text-slate-700">{r.hits}</td>
                      <td className="px-2 py-2 text-right font-mono text-slate-700">{r.misses}</td>
                      <td className="px-2 py-2 text-right font-mono text-slate-500">{r.passes}</td>
                      <td className="px-2 py-2 text-right font-mono">
                        {r.errors ? (
                          <a href={`${boot.admin}/logs?app=${encodeURIComponent(r.app)}&status=cache_error&mode=history`} className="text-red-600 underline">
                            {r.errors}
                          </a>
                        ) : (
                          <span className="text-slate-500">0</span>
                        )}
                      </td>
                      <td className="py-2 pl-2 text-right font-mono font-semibold text-ink">{r.ratio}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-[13px] text-slate-500">No cached traffic in the last 24 hours.</p>
          )}
        </div>
      )}
    </Card>
  );
}
