import type { StatEvent } from "./api";
import { Tally } from "./tally";

const ev = (id: number, over: Partial<StatEvent> = {}): StatEvent => ({
  id,
  t: Date.now(),
  app: "shop",
  ip: "192.0.2.1",
  cc: "NL",
  m: "GET",
  p: "/",
  s: 200,
  blk: false,
  ms: 10,
  br: "Firefox",
  os: "Linux",
  ...over,
});

describe("tally", () => {
  it("counts nothing until the seed is asked for", () => {
    const t = new Tally();
    t.push(ev(1));
    expect(t.total).toBe(0);
  });

  it("counts the seed, then what streamed meanwhile, never twice", () => {
    const t = new Tally();
    t.state = "seeding";
    t.push(ev(2)); // also in the seed
    t.push(ev(3, { s: 404, p: "/nope" }));
    t.seeded([ev(1), ev(2, { blk: true, why: "waf_blocked #942100" })], 0);
    expect(t.total).toBe(3);
    t.push(ev(4, { s: 502, ip: "192.0.2.2" }));
    expect([t.total, t.blocked, t.nf, t.err5, t.ips.size]).toEqual([4, 1, 1, 1, 2]);
    expect(t.top("why")).toEqual([{ key: "waf_blocked #942100", n: 1, pct: 100 }]);
    expect(t.top("path")[0]).toEqual({ key: "GET /", n: 3, pct: 75 });
    expect(t.top("nf")[0]!.key).toBe("/nope");
  });

  it("counts streamed requests alone when the seed fails", () => {
    const t = new Tally();
    t.state = "seeding";
    t.push(ev(5));
    t.seedFailed();
    expect([t.failed, t.total, t.state]).toEqual([true, 1, "ready"]);
  });

  it("buckets the last 60 minutes and drops older ones", () => {
    const now = 1_800_000_000_000;
    const t = new Tally();
    t.seeded([ev(1, { t: now, blk: true }), ev(2, { t: now }), ev(3, { t: now - 2 * 3600_000 })], 0);
    const line = t.timeline(now);
    expect(line).toHaveLength(60);
    expect(line[59]).toMatchObject({ n: 2, b: 1 });
    expect(t.minutes.size).toBe(1);
  });

  it("forgets one-hit keys once a panel tracks too many, and skips empty ones", () => {
    const t = new Tally();
    t.seedFailed();
    t.push(ev(1, { p: "/hot", blk: true, why: "", ms: 0, br: "", cc: "" }));
    t.push(ev(2, { p: "/hot" }));
    for (let i = 0; i < 5001; i++) t.push(ev(i + 3, { p: `/scan${i}` }));
    expect(t.top("nf")).toEqual([]);
    expect(t.top("br").map((r) => r.key)).toEqual(["Firefox"]);
    expect(t.top("why").map((r) => r.key)).toEqual(["blocked"]);
    expect(t.top("cc").map((r) => r.key)).toContain("??");
    // The 5000th one-hit path tipped it over: only /hot (2 hits) and the next one remain.
    expect(t.top("path").map((r) => r.key)).toEqual(["GET /hot", "GET /scan5000"]);
  });
});
