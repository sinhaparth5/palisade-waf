# REVIEW.md

How to review a change in this repo. Don't ask "what's wrong with this code?". Ask **"what can break because of it?"** For every change, picture it running in production under bad input, heavy load, partial failure and an upgrade from an older version, then trace what happens.

## What can break

Walk the diff with these questions. Flag anything you can't answer from the code.

**Inputs**
- What happens with empty, huge, malformed, duplicate or hostile input? Is any client-controlled value (header, path, query, body, cookie, hostname) trusted without validation?
- Can a client-controlled string reach SQL text, a Varnish ban expression, a log line, an HTML template or a shell? (Values go through `?` placeholders, the `safe*` charset checks, `\xHH` escaping and `textContent` respectively.)
- Is the client IP taken from `proxy.ClientIP`? Per-client counters keyed through `ratelimit.ClientKey`?

**Hot path**
- Does anything new on the request path block: DB queries, network calls, unbounded loops, lock contention? Slow work belongs on a goroutine or the log queue.
- Is every new map, cache or slice bounded (TTL, cap, janitor)? An attacker with unique IPs or fingerprints will grow it.
- Can a panic in a goroutine take the whole process down?

**Concurrency**
- Shared state read and written without the mutex? A swap (`Reload*`) that leaves old goroutines, tickers or limiters running?
- Does `go test -race` pass for the touched package?

**Failure paths**
- What happens when the DB, a backend, Varnish, ClickHouse, SMTP or a webhook endpoint is down or slow? A dependency outage must degrade the feature, never 502 traffic or stall the log worker.
- Are errors returned/logged, not swallowed? Does a failure fail **closed** for security checks (auth, 2FA, WAF, CSRF) and **open** only where that's the documented intent (Varnish bypass, health fallback)?
- Is a partial write possible (half-saved config, rule added but blocklist not reloaded)?

**Security**
- New admin route: behind `sessionAuth` + CSRF? Mutating and audited? Sensitive response on a POST, not a GET?
- New secret: in `secretMetaKeys`, accessed via `getSecretMeta`/`setSecretMeta`, never echoed back to the UI, excluded from audit summaries and the warehouse?
- Does the change widen a bypass (open paths, challenge exemptions, trusted crawlers, verdict cache key)?

**Data and upgrades**
- Does the query work on SQLite, MySQL **and** Postgres? (`Rebind`, reserved words, no SQLite date functions, `time.Time` scans.)
- Does an existing database upgrade cleanly? Can a rolled-back binary still read it?
- Does a new action string break exact-match consumers (autoban, webhooks, stats, toasts)? Use prefix matches.

**Config and UI**
- New Tailwind class: was `make css` run and the output committed?
- New JS: edited in `static/js/src/`, built with `make build`, script tag has `?v={{.Asset}}`?
- Does a changed VCL match the `install.sh` heredoc?

## Clean code

- The smallest diff that fixes the root cause. Fix the shared function, not each caller.
- No dead code, unused parameters, speculative abstractions, or interfaces with one implementation.
- Reuse what exists (storage helpers, template partials, `Reload` patterns) before writing new code.
- Names say what a thing is; no `data2`, `tmp`, `handleStuff`.
- `gofmt` and `make lint` clean. `//nolint` only with a same-line reason.
- Tests: table-driven cases next to the existing ones, covering the failure path rather than just the happy path. UI handlers go through `newAdminEnv`.

## Comments

Keep them few and useful:
- A short doc comment on exported functions and the main entry point of a feature.
- A comment where the code would surprise a reader: a non-obvious ordering, a library quirk, a security reason, a deliberate trade-off.
- No comments that restate the code, narrate history ("used to…", "now…"), or reference the review/issue discussion. History belongs in the commit message.

## Verdict

Every finding needs a concrete scenario: **input/state → what breaks**. If you can't describe how it breaks, it's a style nit — mark it as one or drop it.
