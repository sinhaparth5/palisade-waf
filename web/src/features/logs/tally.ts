import type { StatEvent } from "./api";

// The Stats view's counting (GoAccess-style): the browser counts, from the
// last hour (seed) plus every streamed request. Kept outside React so the
// count goes on while the Table tab is shown.

export const panels = ["path", "ip", "why", "nf", "status", "cc", "app", "br", "os"] as const;
export type Panel = (typeof panels)[number];

const maxKeys = 5000;

export class Tally {
  total = 0;
  blocked = 0;
  nf = 0;
  err5 = 0;
  msSum = 0;
  ips = new Set<string>();
  maps = Object.fromEntries(panels.map((p) => [p, new Map<string, number>()])) as Record<Panel, Map<string, number>>;
  minutes = new Map<number, { n: number; b: number }>(); // unix minute -> requests, blocked
  // Seeding: nothing counts until the seed is asked for; events streamed
  // while it loads wait, and count only if newer than the seed.
  state: "idle" | "seeding" | "ready" = "idle";
  since = 0;
  failed = false;
  dirty = true;
  private pending: StatEvent[] = [];
  private seedMax = 0;

  push(e: StatEvent) {
    if (this.state === "seeding") this.pending.push(e);
    else if (this.state === "ready" && e.id > this.seedMax) this.count(e);
  }

  seeded(events: StatEvent[], since: number) {
    for (const e of events) {
      this.seedMax = Math.max(this.seedMax, e.id);
      this.count(e);
    }
    this.since = since;
    this.finish();
  }

  seedFailed() {
    this.failed = true;
    this.finish();
  }

  private finish() {
    for (const e of this.pending) if (e.id > this.seedMax) this.count(e);
    this.pending = [];
    this.state = "ready";
    this.dirty = true;
  }

  private bump(p: Panel, key: string) {
    if (!key) return;
    const m = this.maps[p];
    m.set(key, (m.get(key) ?? 0) + 1);
    // ponytail: drops one-hit keys once a panel tracks too many (scanners
    // hit thousands of unique paths); fine for a top-10 view.
    if (m.size > maxKeys) for (const [k, n] of m) if (n <= 1) m.delete(k);
  }

  count(e: StatEvent) {
    this.total++;
    this.msSum += e.ms || 0;
    this.ips.add(e.ip);
    if (e.blk) {
      this.blocked++;
      this.bump("why", e.why || "blocked");
    }
    if (e.s === 404) {
      this.nf++;
      this.bump("nf", e.p);
    }
    if (e.s >= 500) this.err5++;
    this.bump("path", `${e.m} ${e.p}`);
    this.bump("ip", e.ip);
    this.bump("status", String(e.s));
    this.bump("cc", e.cc || "??");
    this.bump("app", e.app);
    this.bump("br", e.br);
    this.bump("os", e.os);
    const min = Math.floor(e.t / 60000);
    const b = this.minutes.get(min) ?? { n: 0, b: 0 };
    b.n++;
    if (e.blk) b.b++;
    this.minutes.set(min, b);
    this.dirty = true;
  }

  // top returns the 10 biggest keys of a panel with their share of it.
  top(p: Panel) {
    const m = this.maps[p];
    let sum = 0;
    for (const n of m.values()) sum += n;
    return [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([key, n]) => ({ key, n, pct: (n * 100) / sum }));
  }

  // timeline returns the last 60 minutes, oldest first, dropping older ones.
  timeline(now = Date.now()) {
    const cur = Math.floor(now / 60000);
    for (const m of this.minutes.keys()) if (m <= cur - 60) this.minutes.delete(m);
    return Array.from({ length: 60 }, (_, i) => ({ minute: cur - 59 + i, ...(this.minutes.get(cur - 59 + i) ?? { n: 0, b: 0 }) }));
  }
}
