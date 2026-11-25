import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { Page, PageHeader, labelMono } from "@/components/layout/Page";
import { Flag } from "@/components/Flag";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { boot, can } from "@/lib/boot";
import { fmtTime, statusDot, type LogRow } from "@/lib/format";
import { cn } from "@/lib/utils";
import { eventRow, exportQuery, isLive, pageSize, useLogApps, useLogs, type LogSearch, type StatEvent } from "./api";
import { Inspector } from "./Inspector";
import { LogStats } from "./LogStats";
import { Tally } from "./tally";

// Live Logs. With no filters it is the live feed: the newest rows from the
// database, then each new request from the SSE stream, newest first, at most
// maxRows. New rows wait (a pill counts them) while paused or scrolled down,
// so they never shift what is being read. Any filter or page turns it into
// a static history page. Filters live in the URL.

const maxRows = 500;
const flushDelay = 50; // ms: a burst of requests costs one render
const followThreshold = 48; // px from the top that still counts as the top

const statuses: [string, string][] = [
  ["", "All statuses"],
  ["blocked", "Blocked only"],
  ["2xx", "2xx success"],
  ["3xx", "3xx redirect"],
  ["4xx", "4xx client error"],
  ["5xx", "5xx server error"],
  ["cache_error", "Cache errors"],
];

const btn =
  "flex min-h-11 cursor-pointer items-center gap-[6px] rounded-sm border border-edge bg-transparent px-4 py-2 font-mono text-[12px] uppercase tracking-[.04em] text-ink no-underline hover:bg-surface";
const field = "min-h-11 w-full rounded-sm border border-edge bg-card px-3 py-2 text-[13px] text-ink";

type View = "table" | "stats";
const savedView = (): View => {
  try {
    return sessionStorage.getItem("cz-logs-view") === "stats" ? "stats" : "table";
  } catch {
    return "table";
  }
};

export function LogsPage({ search }: { search: LogSearch }) {
  const live = isLive(search);
  const { data, isError, isPending } = useLogs(search, live);
  const [selected, setSelected] = useState<number | null>(null);
  // The last request shown, kept while the panel slides out after a close.
  const [shown, setShown] = useState<number | null>(null);
  if (selected !== null && selected !== shown) setShown(selected);

  // Live feed state.
  const [paused, setPaused] = useState(false);
  const [conn, setConn] = useState<"connecting" | "live" | "reconnecting">("connecting");
  const [streamed, setStreamed] = useState<LogRow[]>([]);
  const [waiting, setWaiting] = useState(0);
  const [view, setViewState] = useState<View>(savedView);
  const [tally] = useState(() => new Tally());
  const queue = useRef<LogRow[]>([]);
  const timer = useRef(0);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const wrapper = useRef<HTMLDivElement>(null);

  const atTop = () => (wrapper.current?.scrollTop ?? 0) <= followThreshold;
  const flush = useCallback(() => {
    timer.current = 0;
    const q = queue.current;
    if (!q.length) return;
    if (pausedRef.current || !atTop()) return setWaiting(q.length);
    queue.current = [];
    setStreamed((rows) => {
      const ids = new Set(rows.map((r) => r.ID));
      return [...q.reverse().filter((r) => !ids.has(r.ID)), ...rows].slice(0, maxRows);
    });
    setWaiting(0);
    if (wrapper.current) wrapper.current.scrollTop = 0;
  }, []);
  const schedule = useCallback(() => {
    if (!timer.current) timer.current = window.setTimeout(flush, flushDelay);
  }, [flush]);

  useEffect(() => {
    if (!live) return;
    const stream = new EventSource(`${boot.admin}/logs/stream`);
    stream.addEventListener("open", () => setConn("live"));
    // EventSource reconnects on its own; this only shows it.
    stream.addEventListener("error", () => setConn("reconnecting"));
    stream.addEventListener("message", (e) => {
      let ev: StatEvent;
      try {
        ev = JSON.parse((e as MessageEvent).data);
      } catch {
        return;
      }
      tally.push(ev);
      queue.current.push(eventRow(ev));
      // Past maxRows the oldest waiting rows could never be shown anyway.
      if (queue.current.length > maxRows) queue.current.splice(0, queue.current.length - maxRows);
      schedule();
    });
    return () => {
      stream.close();
      clearTimeout(timer.current);
      timer.current = 0;
    };
  }, [live, tally, schedule]);

  const togglePause = () => {
    setPaused(!paused);
    if (paused) {
      pausedRef.current = false;
      if (wrapper.current) wrapper.current.scrollTop = 0;
      schedule();
    }
  };
  const setView = (v: View) => {
    setViewState(v);
    try {
      sessionStorage.setItem("cz-logs-view", v);
    } catch {
      // storage blocked
    }
  };

  const initial = data?.logs ?? [];
  const rows = live ? merge(streamed, initial) : initial;
  const status = paused ? "paused" : conn;
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const page = search.page ?? 1;
  const showStats = live && view === "stats";

  const table = (
    <div role={live ? "tabpanel" : undefined} aria-label="Requests" className="overflow-x-auto border border-edge bg-card">
      <div className={cn(labelMono, "flex min-w-[920px] items-center gap-[22px] border-b border-edge px-6 py-3")}>
        <span className="w-[104px] shrink-0">Time</span>
        <span className="w-[94px] shrink-0">App</span>
        <span className="w-[150px] shrink-0">IP</span>
        <span className="w-[58px] shrink-0">Method</span>
        <span className="flex-1">Path</span>
        <span className="w-[50px] shrink-0 text-right">Status</span>
        <span className="w-[50px] shrink-0 text-right">Dur</span>
        <span className="w-20 shrink-0">Action</span>
      </div>
      <div
        ref={wrapper}
        onScroll={() => queue.current.length && atTop() && schedule()}
        className={cn("min-h-[360px] min-w-[920px] overflow-y-auto", live ? "h-[calc(100dvh-280px)]" : "h-[calc(100dvh-350px)]")}
      >
        {isError && (
          <p role="alert" className="p-16 text-center text-[14px] text-red-600">
            Couldn't load requests. Reload to try again.
          </p>
        )}
        {isPending && <p className={cn(labelMono, "p-16 text-center")}>Loading…</p>}
        {data && rows.length === 0 && (
          <div className="flex flex-col items-center justify-center p-16 text-center text-slate-500">
            <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded mb-[10px] block text-[40px] opacity-40", live ? "hgi-signal-full-02" : "hgi-search-02")} />
            <p className="text-[14px]">{live ? "Waiting for requests…" : "No requests match these filters."}</p>
          </div>
        )}
        {rows.map((r) => (
          <Row key={r.ID} r={r} current={r.ID === selected} onOpen={() => setSelected(r.ID)} />
        ))}
      </div>
    </div>
  );

  return (
    <Page>
      <PageHeader
        title="Live Logs"
        actions={
          <>
            {live ? (
              <button type="button" aria-pressed={paused} onClick={togglePause} className={cn(btn, "aria-pressed:bg-ink aria-pressed:text-canvas")}>
                <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded text-[13px]", paused ? "hgi-play" : "hgi-pause")} />
                <span className="min-w-[3.25rem] text-left">{paused ? "Resume" : "Pause"}</span>
              </button>
            ) : (
              <Link to="/logs" className={btn}>
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-signal-full-02 text-[13px] text-brand" />
                Back to live
              </Link>
            )}
            {can("admin") && (
              <a href={`${boot.admin}/logs/export${exportQuery(search)}`} aria-label="Export NDJSON" className={btn}>
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-download-02 text-[13px]" />
                <span className="hidden sm:inline">Export NDJSON</span>
              </a>
            )}
          </>
        }
      />
      <div className="min-w-0">
          <Filters search={search} history={!live} />

          <div className="mb-4 flex flex-wrap items-center gap-3 sm:gap-4">
            {live ? (
              <>
                <div role="status" className="flex items-center gap-2 text-[14px] font-medium">
                  <span className="relative flex h-2 w-2">
                    {status === "live" && <span className="absolute inset-0 rounded-full bg-brand opacity-75 motion-safe:animate-ping" />}
                    <span className={cn("block h-2 w-2 rounded-full", status === "live" ? "bg-brand" : status === "paused" ? "bg-slate-400" : "bg-amber-500")} />
                  </span>
                  <span className={status === "live" ? "text-green-700" : status === "paused" ? "text-slate-600" : "text-amber-700"}>
                    {{ live: "Live", paused: "Paused", connecting: "Connecting…", reconnecting: "Reconnecting…" }[status]}
                  </span>
                </div>
                <span className="hidden h-4 w-px bg-line sm:block" />
                <span className="hidden text-[12px] text-slate-500 sm:inline">Newest first · last {maxRows} rows · click a row for details</span>
                {waiting > 0 && (
                  <button
                    type="button"
                    onClick={() => {
                      if (wrapper.current) wrapper.current.scrollTop = 0;
                      if (paused) togglePause();
                      else schedule();
                    }}
                    className="flex min-h-8 items-center gap-1.5 rounded-sm bg-ink px-3 py-1 font-mono text-[11px] uppercase text-canvas hover:bg-slate-800"
                  >
                    <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-arrow-up-01 text-[12px]" />
                    {waiting >= maxRows ? `${maxRows}+` : waiting} new · show
                  </button>
                )}
                <span className="flex-1" />
                <Tabs view={view} onChange={setView} />
              </>
            ) : (
              <p className="flex items-center gap-2 text-[14px] font-medium text-slate-500">
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-database text-[13px] text-navy" />
                Showing {rows.length} of {total} matching requests
              </p>
            )}
          </div>

          {showStats ? <LogStats tally={tally} paused={paused} /> : table}

          {live && !showStats && <p className="mt-3 font-mono text-[12px] text-slate-500">Format: time · app · ip · method · path · status · duration · [action]</p>}
          {!live && (
            <nav aria-label="Pages" className="mt-4 flex items-center justify-center gap-3">
              {page > 1 && (
                <Link to="/logs" search={{ ...search, mode: "history", page: page - 1 }} className={cn(btn, "min-h-0")}>
                  ← Prev
                </Link>
              )}
              <span className={labelMono}>
                Page {page} of {pages}
              </span>
              {page < pages && (
                <Link to="/logs" search={{ ...search, mode: "history", page: page + 1 }} className={cn(btn, "min-h-0")}>
                  Next →
                </Link>
              )}
            </nav>
          )}
      </div>
      {/* The inspector slides over the right half of the table instead of
          docking beside it, so the table keeps its full width. Non-modal: rows
          stay clickable to switch requests; Escape or Close dismisses it. */}
      <Dialog modal={false} open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent
          showCloseButton={false}
          onInteractOutside={(e) => e.preventDefault()}
          className="top-14 right-0 bottom-0 left-auto z-40 h-auto w-full max-w-none translate-x-0 translate-y-0 gap-0 rounded-none border-0 border-l border-edge bg-canvas p-0 shadow-[-24px_0_48px_-28px_rgb(0_0_0/0.35)] data-[state=closed]:slide-out-to-right data-[state=closed]:zoom-out-100 data-[state=open]:slide-in-from-right data-[state=open]:zoom-in-100 sm:w-[min(560px,100vw)] sm:max-w-none xl:w-[min(44vw,700px)]"
        >
          <DialogDescription className="sr-only">Full details of one request</DialogDescription>
          <Inspector id={shown} onClose={() => setSelected(null)} heading={<DialogTitle className="text-[15px] text-ink">Request inspector</DialogTitle>} />
        </DialogContent>
      </Dialog>
    </Page>
  );
}

function merge(streamed: LogRow[], initial: LogRow[]) {
  const ids = new Set(streamed.map((r) => r.ID));
  return [...streamed, ...initial.filter((r) => !ids.has(r.ID))].slice(0, maxRows);
}

function Row({ r, current, onOpen }: { r: LogRow; current: boolean; onOpen: () => void }) {
  const onKey = (e: KeyboardEvent) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    onOpen();
  };
  return (
    <div
      role="button"
      tabIndex={0}
      aria-current={current || undefined}
      aria-label={`${r.Method} ${r.Path}, status ${r.Status}${r.Blocked ? ", blocked" : ""}. Show details`}
      onClick={onOpen}
      onKeyDown={onKey}
      className={cn(
        "flex min-w-[920px] cursor-pointer items-center gap-[22px] border-b border-line px-6 py-2.5 text-[13px] transition-colors duration-100 focus-visible:outline-offset-[-3px] aria-[current=true]:bg-side-active aria-[current=true]:shadow-[inset_3px_0_0_var(--fn-edge)]",
        r.Blocked ? "bg-red-50 hover:bg-red-100" : "hover:bg-surface",
      )}
    >
      <span className="w-[104px] shrink-0 font-mono whitespace-nowrap text-slate-600 tabular-nums">{fmtTime(r.Timestamp)}</span>
      <span className="w-[94px] shrink-0 truncate" title={r.AppName}>
        {r.AppName}
      </span>
      <span className="flex w-[150px] shrink-0 items-center gap-[7px]">
        <Flag code={r.Country} />
        <span className="truncate font-mono">{r.RealIP}</span>
      </span>
      <span className="w-[58px] shrink-0 font-mono text-[12px]">{r.Method}</span>
      <span className="flex-1 truncate font-mono text-slate-600" title={r.Path}>
        {r.Path}
      </span>
      <span className="flex w-[50px] shrink-0 items-center justify-end gap-1.5 font-mono tabular-nums">
        <span className={cn("h-2 w-2 shrink-0 rounded-full", statusDot(r.Status))} />
        {r.Status}
      </span>
      <span className="w-[50px] shrink-0 text-right font-mono text-slate-500 tabular-nums">{r.Duration}ms</span>
      <span className="w-20 shrink-0 font-mono text-[12px]">{r.Blocked && <span className="uppercase text-red-600">{r.RuleID ? `#${r.RuleID}` : "block"}</span>}</span>
    </div>
  );
}

function Tabs({ view, onChange }: { view: View; onChange: (v: View) => void }) {
  const tabs: [View, string, string][] = [
    ["table", "Table", "hgi-menu-square"],
    ["stats", "Stats", "hgi-analytics-01"],
  ];
  // Arrow keys switch tabs (WAI-ARIA tabs pattern).
  const onKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const next = view === "table" ? "stats" : "table";
    onChange(next);
    (e.currentTarget.parentElement?.querySelector(`[data-view=${next}]`) as HTMLElement | null)?.focus();
  };
  return (
    <div role="tablist" aria-label="Log view" className="inline-flex items-center border border-edge p-[3px]">
      {tabs.map(([v, name, icon]) => (
        <button
          key={v}
          type="button"
          role="tab"
          data-view={v}
          aria-selected={view === v}
          tabIndex={view === v ? 0 : -1}
          onClick={() => onChange(v)}
          onKeyDown={onKey}
          className="flex min-h-9 cursor-pointer items-center gap-[6px] rounded-md px-3 py-[6px] font-mono text-[11px] uppercase tracking-[.04em] text-slate-600 transition-colors duration-150 aria-selected:bg-ink aria-selected:text-canvas"
        >
          <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded text-[12px]", icon)} />
          {name}
        </button>
      ))}
    </div>
  );
}

function Filters({ search, history }: { search: LogSearch; history: boolean }) {
  const navigate = useNavigate();
  const { data: apps } = useLogApps();
  const submit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const pick = (k: string) => (f.get(k) as string) || undefined;
    void navigate({ to: "/logs", search: { from: pick("from"), to: pick("to"), app: pick("app"), status: pick("status"), mode: "history" } });
  };
  return (
    // Keyed on the URL so Back/Forward and "Clear filters" reset the fields.
    <form key={JSON.stringify(search)} onSubmit={submit} aria-label="Filter requests" className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:flex xl:items-end">
      <label className="min-w-0">
        <span className={cn(labelMono, "mb-[6px] block")}>From (UTC)</span>
        <input type="datetime-local" name="from" defaultValue={search.from} className={cn(field, "xl:min-w-[210px]")} />
      </label>
      <label className="min-w-0">
        <span className={cn(labelMono, "mb-[6px] block")}>To (UTC)</span>
        <input type="datetime-local" name="to" defaultValue={search.to} className={cn(field, "xl:min-w-[210px]")} />
      </label>
      <label className="min-w-0">
        <span className={cn(labelMono, "mb-[6px] block")}>App</span>
        <select name="app" defaultValue={search.app ?? ""} className={cn(field, "xl:min-w-[145px]")}>
          <option value="">All apps</option>
          {/* A filtered app no longer in the list still shows as chosen. */}
          {[...new Set([...(apps ?? []), ...(search.app ? [search.app] : [])])].map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </label>
      <label className="min-w-0">
        <span className={cn(labelMono, "mb-[6px] block")}>Status</span>
        <select name="status" defaultValue={search.status ?? ""} className={cn(field, "xl:min-w-[155px]")}>
          {statuses.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" className="flex min-h-11 items-center justify-center gap-[6px] rounded-sm bg-ink px-4 font-mono text-[12px] uppercase tracking-[.04em] text-canvas">
        <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-filter text-[13px]" />
        Filter
      </button>
      {history && (
        <Link to="/logs" className="flex min-h-11 items-center px-2 font-mono text-[12px] whitespace-nowrap uppercase text-slate-600 no-underline hover:text-ink">
          Clear filters
        </Link>
      )}
    </form>
  );
}
