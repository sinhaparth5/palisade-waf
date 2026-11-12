# Benchmarks

Two ways to measure the request pipeline: Go benchmarks for per-request cost
(repeatable, no server needed), and a load test against a running binary for
throughput and tail latency.

## Go benchmarks

`internal/proxy/bench_test.go` drives `proxy.Handler.Handle` with every stage
active (IP blocklist, geo, bot challenge, rate limit, Coraza + CRS, reverse
proxy) against a local test backend:

| Benchmark | Request |
|---|---|
| `Handle/clean` | browser-like GET, unique query each time, so CRS runs in full |
| `Handle/clean_cached` | the same GET repeated, answered by the WAF verdict cache |
| `Handle/waf_blocked` | SQL injection in the query, 403 from CRS |
| `Handle/large_body` | 58 KiB JSON POST of 960 values, inspected by CRS |
| `HandleParallel` | `clean` from every core at once; wall time per request, so 1/x is throughput |
| `OpenAPICheck` (`internal/security/waf`) | the per-service OpenAPI check alone: a 200-route spec, path and query parameters validated |
| `CheckResponse` (`internal/security/waf`) | response inspection alone: CRS outbound rules over a clean 32 KiB HTML page |

```bash
make bench                       # 6 runs of each -> bench.txt
```

To check a change, run `make bench` on `main` and on your branch (same
machine, nothing else busy), then compare:

```bash
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e main.txt branch.txt
```

benchstat marks differences it considers significant; `~` means noise.

### Baseline

2026-10-15, commit 983c97e, Go 1.27.2, Intel i5-8400H (6 cores, 8 threads), WSL2.
Median of 6 runs.

| Benchmark | Time/op | Memory/op | Allocs/op |
|---|---|---|---|
| `Handle/clean` | 1.16 ms | 217 KiB | 3,179 |
| `Handle/clean_cached` | 242 µs | 50 KiB | 178 |
| `Handle/waf_blocked` | 1.39 ms | 178 KiB | 3,244 |
| `Handle/large_body` (2026-11-12, see below) | 447 ms | 100 MiB | 126,000 |
| `HandleParallel` | 388 µs (≈2,600 req/s) | 214 KiB | 3,202 |
| `OpenAPICheck` (2026-10-27) | 2.4 µs | 1.4 KiB | 35 |
| `CheckResponse` (2026-11-12) | 4.0 ms | 632 KiB | 1,760 |

Most of a clean request is CRS evaluation: the verdict cache, which skips the
Coraza transaction, cuts it by about 80%. The 64 KiB JSON body is the outlier
at roughly 450 ms per request: CRS runs every rule over every JSON value (see
[Large JSON bodies](#large-json-bodies)). An OpenAPI spec adds about 0.2% to a
clean request.

Response inspection (off by default) costs about 0.13 ms per KiB inspected
since the regex prefilter (#292); before it, 0.55 ms per KiB, almost all of
it CRS's outbound regexes. Per 32 KiB, measured before the prefilter, web shells (955) take
about 6.5 ms, IIS (954) 3.4 ms, PHP (953) 2.6 ms, generic leakage (950) and
Java (952) about 1.7 ms each, SQL (951) and Ruby (956) next to nothing. That
is why it stops at 64 KiB. With it off, the request path is unchanged: the
`Handle` benchmarks and allocations match `main`.

## Large JSON bodies

Issue #292, 2026-11-12, same machine. The `large_body` request (58 KiB, 960
JSON values of about 300 characters) timed with one CRS family removed at a
time; the difference from the full run is roughly what that family costs:

| Family | Cost per request |
|---|---|
| 941 XSS | ~150 ms |
| 942 SQLi | ~150 ms |
| 932 RCE | ~130 ms |
| 933 PHP, 934 generic | ~75 ms each |
| 921 protocol, 930 LFI | ~35 ms each |
| everything else | under 30 ms together |
| all CRS rules removed | 2 ms in total |

The cost grows with bytes inspected times rules, not with the JSON shape:
65% of CPU is Go's regexp in `@rx`, 15% transformations, the rest Coraza's
per-rule copy of the ARGS collection and GC. None of the families is
irrelevant to JSON values, so none is skipped.

Two changes came out of it:

- **Argument limit.** Coraza collects at most 1000 arguments per collection
  (`SecArgumentsLimit`) and silently drops the rest, so the old benchmark body
  (6,000 values) only ever had its first 1000 inspected, and a payload placed
  after 1000 harmless values was never inspected at all. Rule 2100000 now
  answers 400 instead. That also caps the work per request: at most 1000
  values within the 128 KiB JSON limit.
- **`SecRxPreFilter On`.** Coraza skips a regex when the value lacks a literal
  the pattern requires or is too short to match. benchstat over 6 alternating
  runs against `main`: `Handle/large_body` -34% (679 → 447 ms),
  `Handle/waf_blocked` -13%, `CheckResponse` -80% (20 → 4 ms), others within
  noise. `TestRxPreFilterSameMatches` checks that CRS matches the same rules
  with and without it.

Not done: a lower JSON limit per service (the 1000-argument cap and the
inspection slots from #261 already bound the worst case), and an alternative
regex engine (a new dependency; the prefilter got most of the way).

## Dashboard queries

`BenchmarkDashboardQueries` (`internal/storage`) times the dashboard's
queries over a request log spread across 30 days, 10% of it blocked. SQLite
only.

```bash
BENCH_ROWS=1000000 go test ./internal/storage/ -run '^$' -bench DashboardQueries -benchtime 5x
```

2026-11-11, 1M rows, same machine as above. Before and after #288:

| Query | Before | After |
|---|---|---|
| `Stats` | 543 ms | 27 ms |
| `AtAGlance` | 2,646 ms | 215 ms |
| `HourlyTraffic` | 55 ms | 37 ms |
| `TopFiringRules` | 154 ms | unchanged |
| `RuleHitCounts` | 143 ms | unchanged |
| `TopCountries` | 37 ms | unchanged |

`Stats` and `AtAGlance` used to aggregate the whole table; they now read
only today's and yesterday's rows through the `ts` index, plus two all-time
counts answered from an index. The two rule queries still visit every
blocked row, because the all-time hit counts they show need them.

## Load test

Throughput and p50/p95/p99 latency against a real binary. Run everything on
one machine and close other busy programs.

1. Start a backend that answers quickly, e.g. `python3 -m http.server 9000`
   in a directory with an `index.html`.
2. Build and start Palisade on a throwaway database:

   ```bash
   make build
   ./palisade --db /tmp/bench.db
   ```

   Sign in to `/admin`, add a service with Prefix `/` and backend
   `http://127.0.0.1:9000`. Keep bot protection off, or the load generator
   gets challenged instead of proxied.
3. Run the load. With [wrk](https://github.com/wg/wrk):

   ```bash
   wrk -t4 -c64 -d30s --latency http://127.0.0.1:8080/
   ```

   wrk reports p50/p75/p90/p99. For p95, use [k6](https://k6.io):

   ```bash
   k6 run --vus 64 --duration 30s --summary-trend-stats 'avg,p(50),p(95),p(99)' - <<'EOF'
   import http from 'k6/http';
   export default function () { http.get(`http://127.0.0.1:8080/?n=${__VU}-${__ITER}`); }
   EOF
   ```

   The `?n=` query makes every request unique so CRS runs in full. wrk sends
   the same URL every time, so it measures the verdict-cache path.

Record results here with the date, commit, machine and command used.
