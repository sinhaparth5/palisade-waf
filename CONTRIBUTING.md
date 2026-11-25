# Contributing to Palisade

Thanks for your interest in improving Palisade — a single-binary Go WAF +
reverse proxy with an embedded React admin dashboard. This guide covers
how to build, test, and submit changes.

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE), and to abide by the project's
[Code of Conduct](CODE_OF_CONDUCT.md).

## Prerequisites

- **Go 1.27+** (the module targets `go 1.27`).
- **[Bun](https://bun.sh)** (version: `BUN_VERSION` in `.github/workflows/ci.yml`)
  to build the React admin app in `web/`. It's build-time only: the built
  files are embedded in the binary, which needs no Node or Bun to run.
- Every Go dependency is pure Go — the SQLite driver is `modernc.org/sqlite`
  (no CGO) — and `make css` downloads the standalone Tailwind CLI into
  `.cache/`.

## Getting started

```bash
git clone https://github.com/sinhaparth5/palisade-waf.git
cd palisade-waf
make build      # make web (React app -> static/app/dist) + go build -> ./palisade
make test       # go test ./...
make lint       # golangci-lint run ./... (config: .golangci.yml)
```

`make lint` requires [golangci-lint](https://golangci-lint.run/welcome/install/)
(pin: see `LINT_VERSION` in the `Makefile`, matching the `version:` pinned in
`.github/workflows/ci.yml`'s lint job). The first `make build` or `make test`
you run in a fresh clone also points git at the versioned
`.githooks/pre-commit` script (`git config core.hooksPath .githooks` — `hooks`
is a prerequisite of both targets, idempotent and silent once already set),
so `golangci-lint run ./...` runs before every `git commit` from then on,
catching lint failures locally instead of first in CI. There's no way to ship
that config in a commit — git never version-controls `.git/hooks/` itself —
so if you never run `make build`/`make test` locally (e.g. editing only docs)
the hook stays off; enable it explicitly with `make hooks`. Skip a single
commit with `git commit --no-verify`.

Run a single package's tests while iterating:

```bash
go test ./internal/proxy/ -run TestName -v
```

Tests are organised by scope, not file type:

- **Go unit tests** sit next to the code as `*_test.go` in the same package,
  so they reach unexported names. Fixture files go in that package's
  `testdata/` (e.g. `internal/storage/testdata/`), fuzz crashers in
  `testdata/fuzz/`. Tests that wire several packages together (servers on
  port 0, subcommands) live in `internal/app`.
- **Frontend unit and component tests** sit next to their file in `web/src`
  (`ServiceForm.tsx` -> `ServiceForm.test.tsx`); a test that spans several
  components goes at the top of `web/src` (`csp.test.tsx`). `web/src/test/`
  holds only shared setup and helpers.
- **Browser end-to-end tests** live in `web/e2e/` (Playwright, `make e2e`).

No `__tests__/` folders and no mirrored test trees. Every implementation
package lives under `internal/`, grouped by concern (`internal/security/` for
signal/mitigation packages, `internal/notify/` for outbound reporting) — see
[`CLAUDE.md`](CLAUDE.md)'s "Layout" section.

## Build rules that will bite you

- **After editing anything under `web/`, run `make web` (or `make build`)
  before `go build`.** The binary embeds `static/app/dist`, which only the web
  build writes; without one the admin pages answer 404.
- `make web-check` is what CI runs on `web/` (types, unit tests, build, smoke).
  `make e2e` runs the role sweep in a real browser: as a viewer and an admin
  it presses every control on every page and fails on any 403 (Playwright,
  `web/e2e`; first run `cd web && bunx playwright install chromium`). Run it
  when you add a page or a write control. Frontend layout and test helpers:
  [`web/README.md`](web/README.md).
- Don't start the server as part of routine work. Verify behaviour with
  `go test` (throwaway tests are fine — delete them once they pass) rather than
  running `make run` / `go run .`.

## Coding conventions

- Run **`gofmt`** on every changed Go file, and **`make lint`**
  (golangci-lint) before committing — the same check runs in CI and, once
  the pre-commit hook is enabled (automatic after your first `make build` or
  `make test`), locally on every `git commit`. Keep package names short,
  lowercase, and role-based; export only what crosses a package boundary.
- Prefer **table-driven tests** (e.g. `TestRegistryMatchPrefixPriority`), and add
  cases next to the package you changed.
- **Frontend:** styling is Tailwind v4 with a CSS-first config in
  `static/css/tailwind.css`, compiled to the committed
  `static/css/dist/tailwind.min.css`. **Run `make css` and commit the output
  whenever you add a class** under `internal/ui/` (the Pro page),
  otherwise it won't exist. The React app in `web/` compiles its own
  Tailwind at build time. Use v4 names (`rounded-sm`, `shadow-xs`,
  `outline-hidden`, `bg-linear-to-*`) and `class="..."` utilities
  (including arbitrary-value syntax like `w-[34px]`); do **not** add
  `style="..."` attributes or `<style>` blocks for anything Tailwind can
  express, and toggle visibility with `classList`, not `element.style.*`.
- **Config direction:** there is no config file. Bootstrap settings (listen
  addresses, TLS binding, WAF rules dir, DB path, retention) are CLI flags —
  see `palisade --help` (defined in `serve`, `internal/app/serve.go`). All
  runtime knobs (bot protection, ACME email, per-service overrides,
  etc.) are stored in the SQLite database (`meta` table / per-service
  columns) and managed from the admin UI.

See [`CLAUDE.md`](CLAUDE.md) for the architecture rules (request pipeline,
hot-reload pattern, storage and date/time gotchas, Varnish cache,
etc.) before making non-trivial changes, and [`REVIEW.md`](REVIEW.md) for what
reviewers check.

## Adding a virtual patch

Virtual patches block an actively exploited CVE until the app behind
Palisade is updated. Each one is a file in `internal/security/waf/vpatch/`,
named after the CVE (`CVE-2024-4577.conf`), embedded in the binary and loaded
into every engine ahead of CRS.

1. Start the file with these header lines; the WAF Rules page shows them:
   ```
   # CVE: CVE-2024-4577
   # Product: <product and affected versions>
   # Reference: https://nvd.nist.gov/vuln/detail/CVE-2024-4577
   # Added: <YYYY-MM-DD>
   ```
   Follow them with a comment explaining what the exploit looks like.
2. Write exactly **one** `SecRule` (a chain is fine) with the next free id in
   2000000–2099999, `deny,status:403,log,severity:'CRITICAL'`, a `msg` naming
   the CVE and `tag:'vpatch/<CVE>'`. Use phase 1 unless you need body
   arguments. One id per patch is what lets an operator turn it off with a
   normal rule exception.
3. Match the exploit itself, not the product: real traffic to the same app
   must pass.
4. Add a case to `vpatchCases` in `internal/security/waf/vpatch_test.go`:
   one request carrying the exploit (must be blocked by *your* rule id) and one
   normal request to the same product (must pass with full CRS loaded).
   `TestVPatchPack` fails until both exist.

## Security & secret hygiene

Never commit any of the following:

- Real admin credentials, TLS private keys, or Cloudflare/API tokens.
- A production `waf.db`, or bundled GeoIP/ASN databases beyond what the repo
  already ships.

Admin credentials are seeded via `palisade setup` (password read from
stdin, never a flag or file — see `--help`). When adding a new configurable
secret, follow the existing pattern: store it in the `meta` table, enter it
from the Settings page, add its key to `secretMetaKeys` and read/write it only
through `getSecretMeta`/`setSecretMeta` (so `--db-key-file` encrypts it at
rest), and never echo it back to the UI or ship it in the binary/installer.

Found a security vulnerability? Please **do not** open a public issue — report it
privately as described in [`SECURITY.md`](SECURITY.md).

## Submitting changes

This project is hosted on **GitHub**; changes are proposed as **pull requests**.

1. Branch off `main` (e.g. `git checkout -b 42-fix-threat-intel-delete`).
2. Make focused commits with short, imperative or descriptive summaries — match
   the existing history (e.g. `feat(web): move the sign-in page to react`). Mention the affected area when useful.
3. Run `make test`, `gofmt` and `make lint` before pushing.
4. Open a pull request that includes:
   - a brief description of the change and its motivation;
   - test results, plus any config or migration notes;
   - screenshots for dashboard/UI changes;
   - an explicit call-out for anything affecting routing, TLS, storage, or
     blocking decisions.
5. Add one line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) for
   anything user-visible: `- (#137) <issue title as on GitHub>`, no
   description.

Preserve unrelated changes in the working tree, and keep each PR scoped to one
logical change.

## Releases

Releases are cut by the maintainer with `make tag VERSION=vX.Y.Z`, which pushes
an annotated tag and triggers the GitHub Actions release workflow. The project follows
[Semantic Versioning](https://semver.org/). `make tag` rolls the
`## [Unreleased]` entries into a version section (`scripts/roll-changelog.sh`)
and commits it before tagging; the workflow uses that section as the GitHub
Release description and appends install/checksum instructions automatically.
`CHANGELOG.md` only ever holds `[Unreleased]` plus the latest version. Contributors
don't need to tag — just land your `Unreleased` changelog entry and it will roll
into the next release.
