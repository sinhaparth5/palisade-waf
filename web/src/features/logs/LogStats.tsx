import { useEffect, useReducer } from "react";
import { labelMono } from "@/components/layout/Page";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { StatEvent } from "./api";
import { type Panel, type Tally } from "./tally";

// Stats tab of the live Logs page. The tally counts in the background (see
// LogsPage); this repaints it at most every 400ms, not while paused, and
// every 30s anyway so the timeline slides on idle minutes.

const regions = (() => {
  try {
    return new Intl.DisplayNames(["en"], { type: "region" });
  } catch {
    return null;
  }
})();

const panelInfo: [Panel, string, string][] = [
  ["path", "Requests", "Top paths"],
  ["ip", "Visitors", "Top IPs"],
  ["why", "Security", "Block reasons"],
  ["nf", "Requests", "Not found (404)"],
  ["status", "Responses", "Status codes"],
  ["cc", "Visitors", "Countries"],
  ["app", "Routing", "Services"],
  ["br", "Clients", "Browsers"],
  ["os", "Clients", "Operating systems"],
];
const mono = new Set<Panel>(["path", "ip", "why", "nf", "status"]);

function label(p: Panel, key: string) {
  if (p !== "cc") return key;
  if (key === "??") return "Unknown";
  let name: string | undefined;
  try {
    name = regions?.of(key);
  } catch {
    // not a region code
  }
  return name && name !== key ? `${name} (${key})` : key;
}

const hhmm = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

export function LogStats({ tally, paused }: { tally: Tally; paused: boolean }) {
  const [, repaint] = useReducer((n: number) => n + 1, 0);

  useEffect(() => {
    if (tally.state !== "idle") return;
    tally.state = "seeding";
    api<{ since: number; events: StatEvent[] }>("/logs/stats")
      .then((d) => tally.seeded(d.events, d.since))
      .catch(() => tally.seedFailed())
      .finally(repaint);
  }, [tally]);

  useEffect(() => {
    if (paused) return;
    const fast = setInterval(() => {
      if (!tally.dirty) return;
      tally.dirty = false;
      repaint();
    }, 400);
    const slow = setInterval(repaint, 30_000);
    return () => {
      clearInterval(fast);
      clearInterval(slow);
    };
  }, [tally, paused]);

  const t = tally;
  const tiles: [string, string][] = [
    ["Requests", t.total.toLocaleString()],
    ["Unique visitors", t.ips.size.toLocaleString()],
    ["Blocked", t.blocked.toLocaleString()],
    ["Not found (404)", t.nf.toLocaleString()],
    ["Server errors (5xx)", t.err5.toLocaleString()],
    ["Avg response", t.total ? `${Math.round(t.msSum / t.total)} ms` : "—"],
  ];
  const minutes = t.timeline();
  const top = Math.max(1, ...minutes.map((m) => m.n));

  return (
    <div>
      <p className="mb-3 text-[12px] text-slate-500">
        {t.state !== "ready"
          ? "Loading the last hour…"
          : t.failed
            ? "Could not load the last hour — counting live requests only."
            : `Since ${hhmm(t.since)} · updates live`}
      </p>
      <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {tiles.map(([name, value], i) => (
          <div key={name} className="border border-edge bg-card p-4">
            <p className={cn(labelMono, "mb-1")}>{name}</p>
            <p className="font-mono text-[26px] leading-none text-ink tabular-nums">
              {t.state === "ready" ? value : "—"}
              {i === 2 && t.total > 0 && <span className="ml-1 text-[13px] font-semibold text-slate-500">{((t.blocked * 100) / t.total).toFixed(1)}%</span>}
            </p>
          </div>
        ))}
      </div>
      <div className="mb-3 border border-edge bg-card p-5">
        <div className="mb-3 flex items-baseline justify-between gap-4">
          <div>
            <p className={cn(labelMono, "mb-[2px]")}>Last 60 minutes</p>
            <h3 className="font-mono text-[15px] uppercase text-ink">Requests per minute</h3>
          </div>
          <p className="text-[12px] whitespace-nowrap text-slate-500">
            <span className="inline-block h-2 w-2 bg-ink" /> allowed <span className="ml-3 inline-block h-2 w-2 bg-danger" /> blocked
          </p>
        </div>
        <svg viewBox="0 0 60 40" preserveAspectRatio="none" role="img" aria-label="Requests per minute over the last 60 minutes; hover a bar for exact counts" className="h-32 w-full">
          {minutes.map((m, i) =>
            m.n ? (
              <g key={m.minute}>
                <title>{`${hhmm(m.minute * 60000)} — ${m.n} requests, ${m.b} blocked`}</title>
                <rect x={i + 0.1} y={40 - (m.n * 40) / top} width="0.8" height={(m.n * 40) / top} className="fill-ink" />
                {m.b > 0 && <rect x={i + 0.1} y={40 - (m.b * 40) / top} width="0.8" height={(m.b * 40) / top} className="fill-danger" />}
              </g>
            ) : null,
          )}
        </svg>
      </div>
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3">
        {panelInfo.map(([p, cat, title]) => {
          const rows = t.top(p);
          return (
            <section key={p} aria-label={title} className="border border-edge bg-card p-5">
              <p className={cn(labelMono, "mb-[2px]")}>{cat}</p>
              <h3 className="mb-3 font-mono text-[15px] uppercase text-ink">{title}</h3>
              <ol className="space-y-2">
                {rows.length === 0 && <li className="text-[13px] text-slate-500">No requests yet</li>}
                {rows.map((r) => (
                  <li key={r.key}>
                    <div className="flex items-center gap-3 text-[13px]">
                      <span className={cn("min-w-0 flex-1 truncate text-slate-700", mono.has(p) && "font-mono")} title={r.key}>
                        {label(p, r.key)}
                      </span>
                      <span className="font-semibold text-slate-800 tabular-nums">{r.n.toLocaleString()}</span>
                      <span className="w-12 text-right text-[12px] text-slate-500 tabular-nums">{r.pct.toFixed(1)}%</span>
                    </div>
                    <svg viewBox="0 0 100 1" preserveAspectRatio="none" aria-hidden className="mt-1 h-1 w-full">
                      <rect width="100" height="1" className="fill-slate-200" />
                      <rect width={Math.max(1, (r.n * 100) / rows[0]!.n)} height="1" className={p === "why" ? "fill-danger" : "fill-ink"} />
                    </svg>
                  </li>
                ))}
              </ol>
            </section>
          );
        })}
      </div>
    </div>
  );
}
