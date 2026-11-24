import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { Page, PageHeader, labelMono } from "@/components/layout/Page";
import { Flag } from "@/components/Flag";
import { boot } from "@/lib/boot";
import { fmtTime, statusDot } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useDashboard, type Dashboard } from "./api";

// The dashboard, as the HTMX page had it: counters, the live strip, 24h
// traffic, top countries, services, latest blocks, recent changes, recent
// requests, and the enforcement/threats/engine column on the right.

const card = "border border-edge bg-card";
const big = "font-mono text-[40px] leading-none text-ink tabular-nums";
const th = cn(labelMono, "px-3 py-2 text-left font-medium first:pl-4 last:pr-4");
const td = "px-3 py-2 first:pl-4 last:pr-4";

export function DashboardPage() {
  const { data, isPending, isError } = useDashboard();
  return (
    <Page>
      <PageHeader
        title="Dashboard"
        actions={
          <Link to="/logs" className="flex min-h-11 items-center gap-[7px] rounded-sm bg-ink px-4 font-mono text-[12px] uppercase tracking-[.04em] text-canvas no-underline">
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-signal-full-02 text-[14px]" />
            Live feed
          </Link>
        }
      />
      {isError && (
        <p role="alert" className={cn(card, "p-6 text-red-600")}>
          Couldn't load the dashboard. Reload to try again.
        </p>
      )}
      {isPending && <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>}
      {data && (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
          <Main d={data} />
          <Side d={data} />
        </div>
      )}
    </Page>
  );
}

const more = cn(labelMono, "no-underline hover:text-ink");

function Section({ title, action, className, children }: { title: string; action?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <section className={cn("min-w-0", className)}>
      <div className="mb-3 flex items-end justify-between gap-3">
        <h2 className="text-[15px] text-ink">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

// An HTMX page not moved to the app yet.
const Old = ({ href, children }: { href: string; children: ReactNode }) => (
  <a href={boot.admin + href} className={more}>
    {children}
  </a>
);

function Main({ d }: { d: Dashboard }) {
  const total = d.traffic.allowed.map((a, i) => a + d.traffic.blocked[i]!);
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <Section title="Overview">
        <div className={cn(card, "grid grid-cols-2 gap-px bg-edge lg:grid-cols-5")}>
          <Counter label="Requests" value={d.requests_today} sub="Today">
            <Spark values={total} fill="fill-ink" />
          </Counter>
          <Counter label="Blocked" value={d.blocked_today} sub="Today">
            <Spark values={d.traffic.blocked} fill="fill-danger" />
          </Counter>
          <Counter label="Challenged" value={d.challenged} sub="Bots today">
            <ul className="font-mono text-[12px] text-slate-600">
              <li className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-warning" />
                {d.challenged} challenged
              </li>
              <li className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-success" />
                {d.passed} passed
              </li>
            </ul>
          </Counter>
          <Counter label="Visitors" value={d.visitors} sub="Unique today">
            <p className="font-mono text-[12px] text-slate-600">
              {d.services.length} service{d.services.length === 1 ? "" : "s"} protected
            </p>
          </Counter>
          <div className="col-span-2 flex items-center gap-4 bg-card p-4 lg:col-span-1 lg:flex-col lg:items-start">
            <div>
              <p className={cn(labelMono, "mb-2")}>Block rate</p>
              <p className={big}>{d.block_rate}%</p>
              <p className={cn(labelMono, "mt-2")}>Of today's requests</p>
            </div>
            <Ring pct={d.block_rate} className="ml-auto h-16 w-16 lg:mt-auto lg:ml-0" />
          </div>
        </div>
      </Section>

      <section aria-label="Last minute" className={cn(card, "grid grid-cols-2 gap-px bg-line sm:grid-cols-4")}>
        {d.glance.map((m) => (
          <div key={m.label} className="flex items-baseline justify-between gap-2 bg-card px-4 py-3">
            <div>
              <p className={labelMono}>{m.label}</p>
              <p className="font-mono text-[20px] text-ink tabular-nums">{m.value}</p>
            </div>
            <span className="font-mono text-[11px] text-slate-500">{m.trend}</span>
          </div>
        ))}
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Section
          title="Traffic, last 24h"
          className="lg:col-span-2"
          action={
            <Link to="/logs" className={more}>
              Open logs
            </Link>
          }
        >
          <div className={cn(card, "flex h-[280px] flex-col p-4")}>
            <div className="mb-2 flex items-center gap-4 font-mono text-[11px] uppercase text-slate-600">
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 bg-ink" />
                Allowed
              </span>
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 bg-danger" />
                Blocked
              </span>
            </div>
            <TrafficChart traffic={d.traffic} />
          </div>
        </Section>
        <Section title="Top countries" action={
            <Link to="/geo-rules" className={more}>
              Geo rules
            </Link>
          }>
          <div className={cn(card, "flex h-[280px] flex-col gap-3 overflow-y-auto p-4")}>
            {d.countries.map((c) => (
              <div key={c.code}>
                <div className="mb-1 flex items-center justify-between gap-2 text-[13px]">
                  <span className="flex min-w-0 items-center gap-2">
                    <Flag code={c.code} />
                    <span className="truncate">{c.name}</span>
                  </span>
                  <span className="font-mono tabular-nums">{c.count}</span>
                </div>
                <Meter count={c.count} max={d.countries[0]!.count} />
              </div>
            ))}
            {d.countries.length === 0 && <p className={cn(labelMono, "m-auto")}>No country data yet</p>}
            <p className="mt-auto font-mono text-[10px] uppercase text-slate-500">Requests by country, last 24h</p>
          </div>
        </Section>
      </div>

      <Section title="Services" action={<Old href="/services">View all</Old>}>
        {d.services.length ? (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {d.services.slice(0, 4).map((s) => (
              <a key={s.name} href={`${boot.admin}/services`} className={cn(card, "block p-4 text-ink no-underline transition-colors hover:bg-surface")}>
                <p className="truncate font-mono text-[14px] uppercase tracking-[.04em]">{s.name}</p>
                <p className="mb-3 truncate font-mono text-[12px] text-slate-500">{s.route}</p>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[12px]">
                  <dt className="text-slate-500">Backend</dt>
                  <dd className="flex items-center gap-2">
                    <span className={cn("h-2 w-2 rounded-full", !s.known ? "bg-slate-300" : s.healthy ? "bg-success" : "bg-danger")} />
                    {!s.known ? "Unknown" : s.healthy ? "Healthy" : "Down"}
                  </dd>
                  <dt className="text-slate-500">Cache</dt>
                  <dd>{s.cache ? "Varnish" : "Off"}</dd>
                  <dt className="text-slate-500">TLS</dt>
                  <dd className="capitalize">{s.tls || "none"}</dd>
                </dl>
              </a>
            ))}
          </div>
        ) : (
          <p className={cn(card, "px-6 py-10 text-center text-slate-500")}>No services yet. Add one under Services to start proxying.</p>
        )}
      </Section>

      <div className="grid grid-cols-1 gap-6 2xl:grid-cols-3">
        <Section
          title="Latest blocked requests"
          className="2xl:col-span-2"
          action={
            <Link to="/logs" search={{ status: "blocked" }} className={more}>
              View all
            </Link>
          }
        >
          <Table head={["Time", "Source", "Service", "Path", "Action"]} empty={d.blocked.length ? "" : "Nothing blocked yet"}>
            {d.blocked.map((r) => (
              <tr key={r.ID} className="border-b border-line last:border-b-0">
                <td className={cn(td, "font-mono whitespace-nowrap text-slate-600")}>{fmtTime(r.Timestamp)}</td>
                <td className={td}>
                  <Source ip={r.RealIP} country={r.Country} />
                </td>
                <td className={td}>{r.AppName}</td>
                <td className={cn(td, "max-w-[200px] truncate font-mono text-slate-600")} title={r.Path}>
                  {r.Path}
                </td>
                <td className={cn(td, "whitespace-nowrap")}>
                  <span className="flex items-center gap-2 font-mono text-[12px]">
                    <span className="h-2 w-2 shrink-0 rounded-full bg-danger" />
                    {r.Action || "blocked"}
                    {r.RuleID ? ` · ${r.RuleID}` : ""}
                  </span>
                </td>
              </tr>
            ))}
          </Table>
        </Section>
        <Section title="Daily log" action={<Old href="/settings">Audit log</Old>}>
          <div className={cn(card, "p-4")}>
            <p className={cn(labelMono, "mb-3")}>Recent changes</p>
            <ol className="flex flex-col gap-3">
              {d.changes.map((c) => (
                <li key={c.ID} className="border-l-2 border-edge pl-3">
                  <p className="font-mono text-[11px] text-slate-500">
                    {fmtTime(c.TS)} · {c.Actor}
                  </p>
                  <p className="font-mono text-[12px] break-words text-ink">{c.Action}</p>
                </li>
              ))}
              {d.changes.length === 0 && <li className={labelMono}>No changes yet</li>}
            </ol>
          </div>
        </Section>
      </div>

      <Section
        title="Recent requests"
        action={
          <Link to="/logs" className={more}>
            Live feed
          </Link>
        }
      >
        <Table head={["Time", "Service", "Source", "Method", "Path", "Status", "Dur"]} empty={d.recent.length ? "" : "No requests yet. Send traffic through the proxy."}>
          {d.recent.map((r) => (
            <tr key={r.ID} className={cn("border-b border-line last:border-b-0", r.Blocked && "bg-red-50")}>
              <td className={cn(td, "font-mono whitespace-nowrap text-slate-600")}>{fmtTime(r.Timestamp)}</td>
              <td className={td}>{r.AppName}</td>
              <td className={td}>
                <Source ip={r.RealIP} country={r.Country} />
              </td>
              <td className={cn(td, "font-mono text-[12px]")}>{r.Method}</td>
              <td className={cn(td, "max-w-[200px] truncate font-mono text-slate-600")} title={r.Path}>
                {r.Path}
              </td>
              <td className={td}>
                <span className="flex items-center gap-2 font-mono">
                  <span className={cn("h-2 w-2 shrink-0 rounded-full", r.Blocked ? "bg-danger" : statusDot(r.Status))} />
                  {r.Status}
                  {r.Blocked && <span className="text-[11px] uppercase text-red-600">blocked</span>}
                </span>
              </td>
              <td className={cn(td, "text-right font-mono text-slate-500")}>{r.Duration}ms</td>
            </tr>
          ))}
        </Table>
      </Section>
    </div>
  );
}

function Side({ d }: { d: Dashboard }) {
  const top = Math.max(0, ...d.enforcement.map((e) => e.count));
  const threatTop = Math.max(1, ...d.threats.map((t) => t.count));
  return (
    <aside aria-label="Enforcement" className="flex flex-col gap-6">
      <Section title="Enforcement today">
        <div className={cn(card, "flex flex-col gap-4 p-4")}>
          {d.enforcement.map((e) => (
            <div key={e.label}>
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="flex min-w-0 items-center gap-2 text-[13px]">
                  <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded text-[13px] text-slate-500", e.icon)} />
                  <span className="truncate">{e.label}</span>
                </span>
                <span className="font-mono text-[13px] tabular-nums">{e.count}</span>
              </div>
              <Meter count={e.count} max={top} />
            </div>
          ))}
          <p className="font-mono text-[10px] uppercase text-slate-500">Since 00:00 UTC</p>
        </div>
      </Section>

      <Section title="Blocked by country">
        <div className={cn(card, "flex flex-col gap-2 p-4")}>
          {d.threats.map((t) => (
            <div key={t.code} className="flex items-center gap-3 font-mono text-[12px]" title={`${t.count} blocked`}>
              <span className="flex w-10 shrink-0 items-center gap-1.5">
                <Flag code={t.code} />
                {t.code}
              </span>
              <svg viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden className="h-2 flex-1">
                <rect width={Math.max(1, (t.count * 100) / threatTop)} height="4" className="fill-danger" />
              </svg>
              <span className="w-10 text-right tabular-nums">{t.count}</span>
            </div>
          ))}
          {d.threats.length === 0 && <p className={labelMono}>Nothing blocked</p>}
          <p className="mt-2 font-mono text-[10px] uppercase text-slate-500">Last 24h</p>
        </div>
      </Section>

      <Section title="Engine">
        <dl className={cn(card, "grid grid-cols-[1fr_auto] gap-y-2 p-4 font-mono text-[12px] uppercase")}>
          <dt className="text-slate-500">WAF</dt>
          <dd className="flex items-center justify-end gap-2">
            {boot.waf ? "On" : "Off"} <span className={cn("h-2 w-2 rounded-full", boot.waf ? "bg-success" : "bg-danger")} />
          </dd>
          <dt className="text-slate-500">Rule set</dt>
          <dd className="text-right">OWASP CRS</dd>
          <dt className="text-slate-500">Services</dt>
          <dd className="text-right tabular-nums">{d.services.length}</dd>
          <dt className="text-slate-500">Blocked, all time</dt>
          <dd className="text-right tabular-nums">{d.blocked_all}</dd>
        </dl>
      </Section>
    </aside>
  );
}

function Counter({ label, value, sub, children }: { label: string; value: number; sub: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2 bg-card p-4">
      <p className={labelMono}>{label}</p>
      <p className={big}>{value}</p>
      <p className={labelMono}>{sub}</p>
      <div className="mt-auto pt-2">{children}</div>
    </div>
  );
}

// Spark: one 3-unit bar per hour in a 96x32 box; an empty hour keeps a stub.
function Spark({ values, fill }: { values: number[]; fill: string }) {
  const top = Math.max(1, ...values);
  return (
    <>
      <svg viewBox="0 0 96 32" preserveAspectRatio="none" aria-hidden className="h-8 w-full">
        {values.map((v, i) => {
          const h = Math.max(1, Math.floor((v * 32) / top));
          return <rect key={i} x={i * 4} y={32 - h} width="3" height={h} className={fill} />;
        })}
      </svg>
      <p className="mt-1 font-mono text-[10px] uppercase text-slate-500">last 24h, hourly</p>
    </>
  );
}

// Meter: 12 cells filled with count/max, rounded up so any count shows one.
export function meterCells(count: number, max: number) {
  return count > 0 && max > 0 ? Math.min(12, Math.ceil((count * 12) / max)) : 0;
}

function Meter({ count, max }: { count: number; max: number }) {
  const n = meterCells(count, max);
  return (
    <div aria-hidden className="flex gap-[2px]">
      {Array.from({ length: 12 }, (_, i) => (
        <span key={i} className={cn("h-2.5 flex-1", i < n ? "bg-ink" : "bg-slate-200")} />
      ))}
    </div>
  );
}

function Ring({ pct, className }: { pct: number; className?: string }) {
  return (
    <svg viewBox="0 0 40 40" aria-hidden className={cn("-rotate-90", className)}>
      <circle cx="20" cy="20" r="16" fill="none" strokeWidth="5" className="stroke-slate-200" />
      <circle cx="20" cy="20" r="16" fill="none" strokeWidth="5" pathLength={100} strokeDasharray={`${pct} 100`} className="stroke-danger" />
    </svg>
  );
}

// TrafficChart: stacked hourly bars (allowed under blocked); hover a bar for counts.
function TrafficChart({ traffic }: { traffic: Dashboard["traffic"] }) {
  const totals = traffic.allowed.map((a, i) => a + traffic.blocked[i]!);
  const top = Math.max(1, ...totals);
  const n = totals.length;
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <p className="font-mono text-[10px] text-slate-500 tabular-nums">{top}</p>
      <svg viewBox={`0 0 ${n * 10} 100`} preserveAspectRatio="none" role="img" aria-label="Allowed and blocked requests per hour, last 24 hours" className="min-h-0 w-full flex-1 border-b border-edge">
        {totals.map((t, i) => {
          const h = (t * 100) / top;
          const hb = (traffic.blocked[i]! * 100) / top;
          return (
            <g key={i}>
              <title>{`${traffic.labels[i]} UTC: ${traffic.allowed[i]} allowed, ${traffic.blocked[i]} blocked`}</title>
              <rect x={i * 10 + 1.5} y={100 - h} width="7" height={h} className="fill-ink" />
              {hb > 0 && <rect x={i * 10 + 1.5} y={100 - h} width="7" height={hb} className="fill-danger" />}
            </g>
          );
        })}
      </svg>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-slate-500">
        {traffic.labels.filter((_, i) => i % 4 === 0).map((l) => (
          <span key={l}>{l}</span>
        ))}
      </div>
    </div>
  );
}

function Source({ ip, country }: { ip: string; country: string }) {
  return (
    <span className="flex items-center gap-2">
      <Flag code={country} />
      <span className="font-mono">{ip}</span>
    </span>
  );
}

function Table({ head, empty, children }: { head: string[]; empty: string; children: ReactNode }) {
  return (
    <div className={cn(card, "overflow-x-auto")}>
      <table className="w-full min-w-[680px] border-collapse text-[13px]">
        <thead>
          <tr className="border-b border-edge">
            {head.map((h) => (
              <th key={h} className={th}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {children}
          {empty && (
            <tr>
              <td colSpan={head.length} className={cn(labelMono, "px-4 py-10 text-center")}>
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
