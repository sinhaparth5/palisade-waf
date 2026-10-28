# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Palisade** is a single-binary Go WAF + reverse proxy: embedded Coraza v3 (OWASP CRS), Echo for HTTP/routing, a pluggable SQL store (SQLite via pure-Go modernc by default; MySQL/MariaDB and Postgres/CockroachDB/Neon via `--db-driver`), and an HTMX + Tailwind admin UI served from the same binary.

Naming: module/binary/service/user are `palisade`; data `/var/lib/palisade`, key `/etc/palisade`, logs `/var/log/palisade`, metrics `palisade_*`, `Server`/`X-WAF-Engine` headers say `Palisade`. The repo was renamed from `coraza-waf-mod` to `palisade-waf` after v2.5.0; release assets are `palisade-waf-linux-*` (`ASSET` in Makefile, `PACKAGE_NAME` in `ci.yml`, `ASSET_NAME` in `install.sh`). `install.sh` pins with `PALISADE_VERSION`, supports v2.5.1+ only. Pre-rename GHCR images stay at `ghcr.io/sinhaparth5/coraza-waf-mod`. Only the Coraza *engine* keeps the Coraza name.

## Commands

Requires **Go 1.27+**.

```bash
make build       # go generate (minifies JS) + go build -> ./palisade
make generate    # regenerate minified JS only
make css         # recompile Tailwind (standalone CLI into .cache/, no Node) — output is committed
make test        # go test ./...
make bench       # proxy pipeline benchmarks -> bench.txt (see BENCHMARKS.md)
make lint        # golangci-lint run ./... (.golangci.yml, version pinned in LINT_VERSION)
make dist        # cross-compile linux/amd64, linux/arm64, windows/amd64 (CGO_ENABLED=0)
make tag VERSION=v1.0.0  # roll CHANGELOG, commit, tag, push -> release workflow
```

- Single test: `go test ./internal/proxy/ -run TestName -v`.
- **Never bare `go build` after editing JS** — `go:generate` (the `tools/minify` minifier) only runs via `make build`/`make dist`/`make generate`.
- `make build`/`make test` set `core.hooksPath .githooks` (pre-commit runs lint). `git commit --no-verify` skips it once.
- **Do not start the server** (`go run .`, `make run`) unless the user asks each time; verify with throwaway `go test` files and delete them after.
- Run `gofmt` and `make lint` on changed Go files. Tests are table-driven; add cases next to existing ones.
- Lint suppressions the presets don't cover get a same-line `//nolint` with a short reason (see `internal/storage/db.go`).
- Admin UI handler tests use `newAdminEnv` (`internal/ui/harness_test.go`): real handler + session + CSRF over temp SQLite. Use `env.do(method, path, form(...))`, don't call handlers directly.
- Storage tests get their DB from `openTestDB(t)`: temp SQLite by default; set `TEST_DB_DRIVER` + `TEST_DB_DSN` (admin DSN that can CREATE/DROP DATABASE) to run against a real server. `docker compose -f docker-compose.test.yml up -d` gives mysql:8 on `:3307` and postgres:16 on `:5433`; MySQL needs ~20–25s before it's really ready (early `mysqladmin ping` lies).
- CI (`ci.yml`): `lint`, `test` (`-coverpkg=./...`, Codecov), and a `test-external-db` matrix all gate `release` and `docker`. `codeql.yml` and `govulncheck.yml` run separately.
- Run `go test -race` on packages where you touched shared state or a `Reload*` swap.
- Reviews follow `REVIEW.md` (every finding needs a concrete input/state → breakage scenario).

**CLI flags** — there is no config file; every bootstrap setting is a flag (`main.go`), every runtime knob lives in the DB and is edited in the admin UI. Comments mentioning "config.yaml" are historical.

```
--listen :8080   --listen-tls   --listen-h3 (needs --listen-tls)   --trusted-proxies ip,cidr
--trusted-crawlers ua=cidr[,cidr];ua2=ip   --db waf.db (DSN for mysql/postgres)   --db-driver sqlite|mysql|postgres
--certs ./certs   --waf-rules dir   --geo-db path (empty = bundled)   --retention 30 (0 = forever)
--prune-interval 0 (Docker passes 24h)   --tls-cert/--tls-key   --access-log path (+ -max-size-mb, -max-backups)
--db-key-file path (encrypt secrets at rest)   --warehouse-url (ClickHouse HTTP endpoint)
```

**Subcommands**: `prune [--retention d] [--vacuum]`, `setup --admin-email ...` (password on stdin, idempotent), `build-dsn --driver ...` (password on stdin; correctly escapes DSNs), `gencert --hosts ...`, `healthcheck [--url]` (scratch image has no curl), `--version`.

## Request pipeline

`internal/proxy/handler.go` `Handle`, in order: IP blocklist → geo blocklist → bot challenge gate → global rate limit → per-service rate limit → maintenance / waiting room → Coraza WAF → reverse proxy.

- **Maintenance and waiting room** (issue #198, `proxy/gate.go`, `security/waitroom`, table `service_gate`, on `Service.Gate`): skipped for open paths and trusted IPs. Maintenance is a 503 with `Retry-After`; `?palisade_bypass=<token>` sets `cz_bypass` and redirects with the token stripped. Waiting room tickets ride in `cz_wait_<id>`, HMAC'd with the challenge secret over service + ticket + `ratelimit.ClientKey`. Rooms live in `Handler.gates`, outside the registry, so `Reload` doesn't empty the queue. Queue state is bounded (`MaxQueue`, `MaxPerKey`, `QueueTTL`). Both log unblocked (`logChallenged`), so queue polls never touch autoban or JA4 reputation.

- IP/geo run **before** the challenge so a banned IP gets 403, not an endless challenge redirect.
- WAF runs **after** the challenge on purpose: autoban needs unsolved-challenge points to ban a new attacker before any WAF verdict exists.
- `openPaths` (`/robots.txt`, `/sitemap.xml`, `/sitemap_index.xml`, `/llms.txt`; bodiless, query-less GET/HEAD) skip everything but the WAF, even for banned IPs.
- `canonicalRedirect` 301/308s host aliases to the canonical host before any other stage.
- Unknown `/_cz/*` requests (e.g. `HEAD /_cz/challenge` — Echo doesn't route HEAD to GET) are 404'd, never challenged or proxied.
- Logging is fire-and-forget: `DB.QueueRequest` → buffered `logQueue` (10000) → one `runLogWorker` goroutine, which also fans out to broadcast, webhook, autoban, threat score, access log and warehouse hooks. Hooks run on that goroutine, so keep them in-memory; spawn goroutines for slow work.
- `Server: Palisade` is forced in both `handler.go` and `services/registry.go`'s `ModifyResponse`.
- `proxy.responseWriter` must explicitly implement `Hijack` and `Flush` or WebSockets break.
- Client IP: always `proxy.ClientIP` (CF header only from Cloudflare peers, XFF only from `--trusted-proxies`, walked from the right), **never** echo's `c.RealIP()`.
- Backends get `X-Forwarded-For`/`X-Real-IP`/`CF-Connecting-IP` rewritten from that resolved IP (`forwardClientIP`, applied to a clone so `captureHeaders` still logs what the client sent). The stock Director keeps client copies, so never forward `r` directly.
- Trusted IPs (Settings, `services.Registry.Trusted`) skip IP/geo/challenge/rate-limit **and the WAF** on every path, and never trip honeypots.
- IPv6 clients are keyed by /64 via `ratelimit.ClientKey` for rate limits, autoban, bans and threat-score cache. New per-client counters must use it; logs and manual rules keep the exact address.

## Services and routing

- Services live in the DB only (`/admin/services`); `services.Registry` holds them plus one load-balancing `pool` per service, rebuilt wholesale by `Reload(db)` on every change.
- `Match(host, path)`: prefix matches first (longest wins, prefix stripped before proxying), then host. Returns nil when nothing matches — no fallback to the first service; unmatched traffic is logged as app `VPS`. A default backend is an explicit Prefix `/` service.
- Every host lookup goes through `Registry.hosts` (host + `HostAliases` → service), never `Service.Host`. `services.ValidateHosts` is the single hostname check.
- `services.Validate` blocks cloud metadata endpoints by host and resolved IP; private backends are allowed on purpose.
- Multiple backends: `Backend` + newline-separated `ExtraBackends`, `round_robin`/`least_conn`. Passive health by default (10s cooldown); with `health_path`, active checks gate re-entry. All backends must share a base path. Readiness (`/_cz/readyz`) ignores backend health.
- **Varnish** (per-service "Cache"): client → WAF → varnishd `127.0.0.1:6081` → WAF cache-return listener `127.0.0.1:6082` → backend. The VCL has one backend and never changes per service; per-service settings travel as `X-Cache-*` headers. Everything is loopback-only by design. `install.sh` embeds the VCL in a heredoc — edit `deploy/varnish/default.vcl` and the heredoc together (`TestInstallVCLMatchesDefault` enforces byte equality). Purge ban expressions are guarded only by `safeServiceNameForBan`/`safePurgePath` (Varnish ban grammar has no escaping).
- Varnish failures fail open: a dial error, or a 503 the VCL's `vcl_backend_error` marks with `X-Cache-Fetch-Error`, is served from the backend by a `stripPath` pool (the Director already joined the base path) and logged as cache status `ERROR` (Logs "Cache errors" filter). install.sh raises varnishd's 8 KiB header limits; an oversized backend header was the static asset 503 in issue #212.
- Per-service path rules (`cache_rules`, `services/cacherules.go`, issue #212): `cache /p` or `bypass /p`, longest prefix wins, matched on the service path before the base-path join. Bypass skips Varnish in the Director; cache sends `X-Cache-Rule: cache`, which the VCL treats like a static asset (cookies and Set-Cookie dropped, Authorization still passes).
- **HTTP/3**: `--listen-h3` + per-service opt-in, both gated by `Registry.HTTP3Host` (Host-matched services only). `Allow0RTT` must stay explicitly `false` (quic-go enables it when `QUICConfig` is nil).
- TLS certs by SNI: per-service custom cert → autocert (if in `HostPolicy()`) → global fallback. Uploaded keys live under `certs/services/<name>/`, not the DB. The base `tls.Config` must list `h2` in `NextProtos` or `http.Server` silently serves HTTP/1.1 only.
- **mTLS** (`services/mtls.go`, table `service_mtls`, CA at `certs/services/<name>/client-ca.pem`): `GetConfigForClient` only *requests* a cert (`RequestClientCert`, tickets off) for SNI names with a policy; `CheckClientCert` verifies per request against the **Host**'s policy, so SNI/Host mismatch can't bypass it. Required + no valid cert → 403 `mtls_required`, before the IP blocklist, trusted IPs included. `X-Client-Cert-*` are stripped and re-set on `r` itself, so the request log shows the fingerprint. No CRL/OCSP.
- `hostGuard` sends admin-path requests on a service host to the proxy, so the admin UI never appears on customer domains.

## WAF

- `@coraza.conf-recommended` sets `SecRuleEngine DetectionOnly`; any `SecRuleEngine On` must come **after** the CRS includes or nothing is blocked.
- Body inspection is gated by Content-Type (`inspectionFor` in `waf/engine.go`). Without the gate, CRS 901340 makes Coraza parse binary bodies as URL-encoded forms (a 3.5 MiB PUT took 52s / 4.4 GiB). Multipart limit 12.5 MiB; everything else 128 KiB, enforced in `Check` because **Coraza ignores `SecRequestBodyNoFilesLimit`**. Uninspected bodies stream unread.
- Rule exceptions and service-scoped custom rules are compiled in, so each affected service gets its own full CRS engine. `buildWAFAll` in `main.go` builds the default + per-service engines lazily, re-run on SIGHUP and UI saves; `ReloadWAF` swaps them atomically. `AllowLargeJSUploads` is a packaged exception (skip JS bodies, except 911100/920420).
- Virtual patches (`waf/vpatch/*.conf`, embedded): one rule id each in 2000000–2099999, loaded **before** CRS so they deny under their own id and `SecRuleRemoveById` can still remove them. Turning one off is an ordinary rule exception. Autoban counts them as critical. How to add one: CONTRIBUTING.md.
- Custom rules (`waf_custom_rules`): `waf.ValidateCustomRule` — only `SecRule`/`SecAction`, ids in 1000000–1999999, standalone compile, unique ids. `buildWAFAll` skips invalid rows rather than failing startup.
- Verdict cache (`verdictcache.go`): 5s TTL, 4096 entries, per engine. Fingerprint covers IP, method, host, raw path/query, all headers and body. Requests with `Cookie`/`Authorization` are never cached.
- Per-service request JSON Schema (`SetRequestSchema`, `off`/`log`/`enforce`): only on a fully buffered JSON-typed body; enforce → 400 `schema_violation`, log mode → action `schema_violation:log` (no stdout line per request).
- Per-service OpenAPI 3.x spec (`waf/openapi.go`, `SetOpenAPI`, table `service_openapi`, `MEDIUMTEXT` on MySQL): compiled into a route trie per engine build. Matched against `CheckOptions.Path` (service prefix stripped); `servers[].url` base paths are optional. Enforce → 404 route / 405 method / 400 params or body / 415 media type, action `openapi_violation`; log → `openapi_violation:log`. Declared operations skip the plain request schema. Undeclared `OPTIONS` passes (CORS) and `HEAD` falls back to `GET`.
- Response inspection (`waf/response.go`, per service `response_inspect` ""/`log`/`block`): `CheckResponse` runs a fresh transaction (phase 1 replayed for CRS setup, then phases 3–4) from the proxy's `ModifyResponse` via `services.WithResponseHook`, never through the verdict cache. Only identity-encoded HTML/text/JSON/XML up to 64 KiB (~0.55 ms/KiB); the hook strips `Accept-Encoding` toward the backend (Go's Transport then gunzips transparently) and compression re-negotiates from the client's original. A match is a 950000–958999 rule **with a msg** (CRS flow/PL-gate rules match without one). `block` returns `services.ErrResponseBlocked` → 502, which the error handlers must not log, retry or count against backend health. Actions `response_leak:log`/`response_leak:block`.
- A failed body read returns `waf.ErrBodyRead` (client abort/malformed body) → 400 in the handler, never a 500 "waf error".
- No paranoia-level tiering: it would need one CRS engine per level per service.

## Storage

- Queries in `db.go` use `?` and go through `DB.exec/query/queryRow`, which `Rebind`. Hand-rolled `*sqlx.Tx` code must call `Rebind` itself (Postgres rejects `?`).
- `dialect` generates only what Rebind can't: DDL types, idempotent index/ALTER clauses, MySQL TEXT index prefixes, quoted identifiers (`meta.key` is reserved in MySQL), upserts. `schema.go` emits one statement per Exec (pgx rejects multi-statement strings).
- Verify dialect-touching changes against real mysql:8/postgres:16, not docs.
- SQLite PRAGMAs go in the DSN (`_pragma=...`), not an `Exec` — only DSN params reach every pooled connection.
- **Never use SQLite `date()`/`strftime()` on `requests.ts`** — modernc stores Go's `.String()` format and they return NULL. Bucket times in Go with `>=`/`<=` (see `GetHourlyTraffic`). Always scan/insert timestamps as `time.Time`.
- Bolt-on features get new tables (`CREATE TABLE IF NOT EXISTS`) rather than `ALTER TABLE`, e.g. `waf_service_rule_exceptions`, `ip_threat_scores`, `ja4_reputation`.
- The live DB connection always comes from CLI flags; the Settings "Database connection" card only prefills, tests and copies config tables (`MigrateConfigTo`). `BackupTo` (`VACUUM INTO`) is SQLite-only.
- `DB.Close` is idempotent and `QueueRequest` after it is a silent drop (a handler can outlive a timed-out shutdown); keep that guard if you touch the log queue.
- Pruning is not automatic unless `--prune-interval` is set; `PruneOldRequests` deletes in batches of 2000. `VACUUM` lives only in the one-shot `prune --vacuum`, never in the running server.
- **Secrets at rest** (`secretenc.go`, `--db-key-file`): AES-256-GCM with an `enc:v1:` prefix. A new secret meta key must go in `secretMetaKeys` and use only `getSecretMeta`/`setSecretMeta`. A sealed value read with a missing/wrong key must error loudly; `GetOrCreateChallengeSecret` must never regenerate on that error.

## Admin UI

- Session-cookie auth (bcrypt), optional TOTP/backup/email-code 2FA, passkeys, all per user in `admin_users` (`storage/users.go`; the old `meta` account is migrated in as owner on startup). One live session **per user**: `CreateSession` revokes that user's others (`revoked_at`, not delete). `sessionAuth` puts the user in the context (`currentUser`). Login is throttled per IP and per account (`loginlimit.go`); failed 2FA codes count too and are not reset by a correct password.
- **Roles** (`owner`/`admin`/`viewer`, issue #196): every mutating admin route is registered inside an `as(role, ...)` block in `Register`; `requireRole` enforces it and `TestRouteRoles` fails on an undeclared one. Owner = users, DB connection, secrets (webhook/email/TypeSafe), API keys, backup. The last enabled owner can't be demoted, disabled or deleted (`ErrLastOwner`, in storage).
- **OIDC SSO** (issue #197, `ui/sso.go`, `storage/sso.go`): invite-only. State, nonce and PKCE verifier ride in the `cz_sso` cookie, not server memory. The first login spends an `admin_sso_invites` row (needs `email_verified` true) and binds a new password-less user to `iss`+`sub` in `admin_sso_identities`; later logins match on that pair, never on email. Email/groups missing from the ID token are filled from userinfo (Authelia's default). SSO logins skip Palisade 2FA and write an `SSO login` audit row with `amr`. Password login can't be turned off (break-glass). Tests use a fake IdP in `ui/sso_test.go`.
- **CSRF**: all non-GET admin routes. HTMX gets it from `hx-headers` on `<body>`. Plain `method="POST"` forms need `<input type="hidden" name="_csrf" value="{{.CSRF}}">`; raw `fetch` sends `X-CSRF-Token: document.body.dataset.csrf`. Anything returning sensitive data must be POST.
- **Audit log**: the `auditLog` middleware records every successful non-GET. A handler that returns 200 with an inline error must signal failure via a non-empty `...Err`/`...Error` template field or an `HX-Retarget` header. Summaries copy only the `auditFields` allowlist; never switch it to a denylist.
- **REST API** (`internal/ui/api.go`, `{admin}/api/v1/*`): bearer `cwaf_` keys stored as SHA-256 (not bcrypt — they're high-entropy), no session/CSRF. Metrics are at `{admin}/metrics` (session) and `{admin}/api/v1/metrics` (bearer; use this for Prometheus).
- `h.render` sets `data["Page"]` to the template name, so pagination uses `CurPage`.
- Go templates: content outside `{{define}}` never renders — modals go inside `{{define "content"}}`.
- Hidden-step wizards use `novalidate` + manual JS checks; `required` in a hidden step silently blocks submission in Chrome.
- Form controls use the `.field`, `.field-label`, `.btn-ghost` and `.tag` classes from `tailwind.css`, not long utility strings.
- Reuse partials in `templates/components/` (`card_header`, `panel_header`, `management_hero`, `empty_state`, `confirm_modal`, `toggle_switch`, `remove_btn`, `rule_type_badge`, `rule_ring_row`, `ring`, `section_head`, `pager`).
- Management pages (IP Rules, Geo Rules, Services, Certificates, WAF Rules, Threat Intel): `management-hero`, then one full-width `card border-t-4 border-t-edge p-5` primary-action card, supporting panels in a grid **below** it. Inline submit for single-row forms, button below for multi-row.
- Icon names (`hgi-*`) are not validated; a wrong one renders blank. Check against `curl -s https://cdn.hugeicons.com/font/hgi-stroke-rounded.css | grep -oE '\.hgi-[a-z0-9-]+'`.

**JS/CSS**
- JS source in `static/js/src/`, minified to `static/js/dist/` (embedded). No Node/npm in this repo.
- Every page script tag carries `?v={{.Asset}}` (embedded assets have no cache headers; the stamp is a hash of the CSS).
- Tailwind v4, CSS-first config in `static/css/tailwind.css`, compiled to committed `static/css/dist/tailwind.min.css`. **Re-run `make css` and commit when adding a class** anywhere under `internal/ui/` (templates and Go) or `static/js/src/`; classes elsewhere won't exist. After `make css`, a running browser may hold the old stylesheet.
- v3 "ledger" theme (issue #215): colors come only from the `--fn-*` variables in `tailwind.css`. `@theme` resets the palette (`--color-*: initial`), so only slate/red/green/amber/purple/violet/blue/sky/cyan plus the named tokens (`edge`, `side-*`, `success`/`warning`/`info`/`danger`) exist; any other family (rose, teal, …) compiles to nothing. Status colors: `-500` = bright (dots, badges), `-600`+ = text-safe ink shade. Text must pass WCAG AA on cream: `text-slate-500`+ and `text-<status>-600`+ only; `slate-300/400` and status `-400/-500` are for borders, dots, fills and placeholders.
- Use v4 names (`rounded-sm`, `shadow-xs`, `outline-hidden`, `bg-linear-to-*`), never v3 (`rounded`, `shadow`, `outline-none`, `bg-gradient-to-*`). Prefer `starting:` over JS animation.
- No `style="..."` or `<style>` for anything Tailwind can express. JS toggles `classList`, never `element.style`; keep a permanent `flex`/`block` next to a toggled `hidden`.

## Security subsystems

- **Bot** (`security/bot`, `challenge`): header scoring; trusted crawlers must verify by FCrDNS, ASN or pinned CIDR — UA alone is `unverified_crawler`. Operator pins come only from `--trusted-crawlers`; never hardcode IPs. JS PoW challenge + FingerprintJS (vendored, `/_cz/fp.js`) + automation detection; optional Turnstile/hCaptcha fallback. `challenge.Exempt` skips the gate for web manifests (path-based, never header-based). Per-service `bot_mode`: `inherit`/`always`/`off`. **AI crawler policy** (`bot/ai.go`, `services/aicrawler.go`): per category `allow`/`challenge`/`block`, service override over the global default in `meta`; block hits any UA naming the category, allow needs a verified crawler (vendors without rDNS/ASN must be pinned via `--trusted-crawlers`, which merges into the existing entry). AI crawlers are never `IsTrustedCrawler`.
- **TLS fingerprints**: JA4 primary, JA3 deprecated (don't build on it). Cloudflare `Cf-Ja4`/`Cf-Ja3-Fp` win only from Cloudflare peers. Per-connection geo/ASN caches store the client IP and discard on mismatch (pooled proxies multiplex clients).
- **Autoban** (`security/autoban`): scores events per IP in a window; `ip_blocked*`/`geo_blocked*` never score; cross-site subresource requests never score. Bans are `Auto-banned — ` notes on global block rules; existing admin rules always win; private IPs never banned.
- **TypeSafe ASN classification** (`threatscore/typesafeclassify.go`, Settings "AI classification", off by default; key is the `typesafe_api_key` secret): judges unknown ASN orgs in a background goroutine, never on the log worker. Successes are cached per ASN until the config is reloaded; failures back off `typesafeRetryAfter` (10m) per ASN; a 401/403 (`errTypeSafeAuth`) pauses classification until the settings are saved again. Every call is a `typesafe_calls` row (capped at `typesafeCallsKeep`).
- **Threat score** (`security/threatscore`) feeds **adaptive enforcement** (`security/adaptive`, off by default). Adaptive actions log as `...:adaptive`, so anything matching actions must use prefix matches (`LIKE 'bot_challenge%'`, `strings.HasPrefix`), as must `ip_blocked`/`geo_blocked`/`rate_limited`.
- **Login protection** (`services/login.go`) and **honeypots** (`services/honeypot.go`, fire only on 404 responses).
- **Leaked password check** (`security/breach`, per service, login paths only): after the WAF, HIBP range API with only the 5-char SHA-1 prefix sent, 300ms timeout, **fails open**. `log` adds `X-Palisade-Leaked-Password: 1` to the backend request (client copies stripped); `block` → 403. Both score in autoban. The password must never reach a `RequestLog`.
- Rate limiter: in-process token bucket, persisted every 10s. Redis support was removed; `migrate()` deletes leftover keys and the `redis_mode` column is unused.
- Hot reload: `ReloadWAF`, `ReloadBotProtection`, `ReloadRateLimit` swap under RWMutex; SIGHUP rebuilds the WAF; SIGINT/SIGTERM shut down gracefully (10s) and drain the log queue. `main`/`startTLS` must block on the channel `shutdownOnSignal` returns: `Serve` returns as soon as `Shutdown` starts, and the deferred `db.Close` would otherwise run under in-flight requests.
- In TLS mode the `:80` ACME/redirect listener is bound before serving, so a taken port fails startup rather than silently breaking cert renewal.

## Outbound

- Webhooks (`notify/webhook`): `generic`/`slack`/`discord` payloads; `generic` must stay byte-identical. Category logic is shared by `shouldSend` and formatting.
- Daily email (`notify/mailer`): Cloudflare Email Service only (endpoint and sender hardcoded); the token is never echoed back by the UI.
- Access log (`notify/accesslog`): nginx combined, in-house rotation. Close it after the DB drains (defer order in `main.go`).
- ClickHouse warehouse (`notify/warehouse`): mirror only, the operational DB stays the source of truth. Dimension tables are an **allowlist** in `snapshot()`; never ship secret-bearing tables or `headers_json`. Schema is created by the sink at startup, not an initdb script.

## Layout

Everything under `internal/`: `config/`, `storage/`, `proxy/`, `services/`, `ui/`, `security/*` (pipeline signals and mitigations), `notify/*` (outbound reporting). `main.go`/`assets.go` stay at the root because `//go:embed` can't reach `static/` otherwise. `tools/minify` is build-time only. GeoLite2 country and DB-IP ASN databases are bundled via `//go:embed`. User docs live in a separate repo.

## Release and distribution

- `CHANGELOG.md` holds exactly `[Unreleased]` + the latest version. Add entries under `[Unreleased]` as one line: `- (#137) <issue title as on GitHub>` — no description, never a hand-written version heading. `make tag` rolls it (`scripts/roll-changelog.sh`) before tagging because CI reads release notes from the tagged commit.
- Docker: multi-stage → `scratch`; needs the copied CA bundle and `TMPDIR=/data` (Coraza writes a temp file; scratch has no `/tmp`). Pushed to GHCR and Docker Hub on `v*` tags; tags are computed in shell, not `docker/metadata-action`.
- `deploy/install.sh` (`curl | sudo bash`): writes systemd units via heredoc and regenerates the main unit every run; extra flags go in `/etc/palisade/palisade.env` (`$PALISADE_FLAGS`), which is never overwritten. It generates `/etc/palisade/db.key` once.

Never commit credentials, TLS private keys, GeoIP databases or a production `waf.db`.
