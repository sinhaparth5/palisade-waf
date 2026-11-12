BINARY  := palisade
# Release asset name: unchanged from the pre-Palisade releases so the installer
# and every already-published download link keep working.
ASSET   := palisade-waf
DIST    := dist

# Version is the nearest git tag; falls back to the commit hash if no tag exists.
# Override with: make dist VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -s -w -X main.version=$(VERSION)

# Keep in sync with .github/workflows/ci.yml's golangci-lint-action `version:`
# input, so a clean local `make lint` and CI never disagree on results.
LINT_VERSION := v2.14.0

.PHONY: build generate css icons run test bench fuzz lint hooks clean dist checksums tag

build: hooks generate
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

generate:
	go generate ./...

# Recompile the admin UI stylesheet (static/css/tailwind.css ->
# static/css/dist/tailwind.min.css) with the standalone Tailwind CLI — a
# single native binary, no Node/npm. The output is committed and //go:embed-ed
# (assets.go), so build/dist/CI never need this tool; run it (and commit the
# result) whenever templates, static/js/src, or internal/ui Go handlers
# add/remove a utility class. Missing CLI is auto-downloaded to a git-ignored
# local cache (no sudo, arch/OS-aware); TAILWIND_BIN points at an existing
# binary instead.
TAILWIND_BIN  ?= .cache/tailwindcss
TAILWIND_OS   := $(shell uname -s | sed -e 's/Linux/linux/' -e 's/Darwin/macos/')
TAILWIND_ARCH := $(shell uname -m | sed -e 's/x86_64/x64/' -e 's/aarch64/arm64/')
css:
	@if [ ! -x "$(TAILWIND_BIN)" ] && ! command -v "$(TAILWIND_BIN)" >/dev/null 2>&1; then \
		echo "==> Downloading standalone Tailwind CLI ($(TAILWIND_OS)-$(TAILWIND_ARCH)) to $(TAILWIND_BIN)"; \
		mkdir -p $(dir $(TAILWIND_BIN)); \
		curl -fsSLo "$(TAILWIND_BIN)" https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-$(TAILWIND_OS)-$(TAILWIND_ARCH); \
		chmod +x "$(TAILWIND_BIN)"; \
	fi
	"$(TAILWIND_BIN)" -i static/css/tailwind.css -o static/css/dist/tailwind.min.css --minify

# Subset the hugeicons font and stylesheet to the hgi-* names the admin UI
# uses (issue #284). The full set (byte-identical to what was vendored) is
# downloaded to .cache/ once; fonttools runs through uvx, so nothing is
# installed. Run it (and commit the result) after adding or removing an icon;
# TestIconsInSubset fails until you do.
ICONS_DIR := internal/ui/vendor/hugeicons
icons:
	@mkdir -p .cache/hugeicons
	@[ -f .cache/hugeicons/full.css ] || curl -fsSLo .cache/hugeicons/full.css https://cdn.hugeicons.com/font/hgi-stroke-rounded.css
	@[ -f .cache/hugeicons/full.woff2 ] || curl -fsSLo .cache/hugeicons/full.woff2 https://cdn.hugeicons.com/font/hgi-stroke-rounded.woff2
	codes=$$(python3 scripts/subset-icons.py .cache/hugeicons/full.css $(ICONS_DIR)/hgi-stroke-rounded.css) && \
	uvx --from 'fonttools[woff]==4.55.3' pyftsubset .cache/hugeicons/full.woff2 --unicodes="$$codes" \
		--flavor=woff2 --layout-features='' --no-hinting --desubroutinize --output-file=$(ICONS_DIR)/hgi-stroke-rounded.woff2

run: build
	./$(BINARY)

test: hooks
	go test ./...

# Request-pipeline and OpenAPI-check benchmarks. Writes bench.txt;
# compare two runs with benchstat — see BENCHMARKS.md.
BENCH_COUNT ?= 6
bench:
	go test -run '^$$' -bench . -benchmem -count $(BENCH_COUNT) ./internal/proxy/ ./internal/security/waf/ | tee bench.txt

# Runs every Fuzz* target for FUZZTIME each (issue #265). A failure leaves
# its input under the package's testdata/fuzz/<Target>/; commit it so the
# case runs in plain `go test` from then on.
FUZZTIME ?= 30s
fuzz:
	@set -e; for f in $$(grep -rl --include='*_test.go' '^func Fuzz' internal); do \
		for t in $$(sed -n 's/^func \(Fuzz[A-Za-z0-9_]*\)(.*/\1/p' $$f); do \
			echo "== $$t ($$(dirname $$f))"; \
			go test ./$$(dirname $$f) -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME); \
		done; \
	done

# Requires golangci-lint $(LINT_VERSION) — https://golangci-lint.run/welcome/install/
# Config lives in .golangci.yml. Same command CI and the pre-commit hook run.
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found. Install $(LINT_VERSION):"; \
		echo "  https://golangci-lint.run/welcome/install/"; \
		exit 1; \
	}
	golangci-lint run ./...

# Points git at the versioned hooks in .githooks/ instead of the untracked,
# per-clone .git/hooks/ directory — there's no way to ship that config in a
# commit, git deliberately never version-controls .git/hooks/. A prerequisite
# of build/test so it's enabled the first time anyone runs either, without
# needing to know this target exists; idempotent and silent once already set,
# so it doesn't nag on every subsequent build.
hooks:
	@if [ "$$(git config --get core.hooksPath 2>/dev/null)" != ".githooks" ]; then \
		git config core.hooksPath .githooks; \
		echo "==> git hooks enabled (.githooks) — golangci-lint runs before every commit"; \
	fi

clean:
	rm -f $(BINARY)
	rm -f static/js/dist/*.min.js
	rm -rf $(DIST)

# Cross-compiled, stripped release binaries (no CGO, so this works without
# any target toolchain installed). -s -w drop debug symbols/DWARF — smaller
# download, and end users never need to attach a debugger to this binary.
# -trimpath keeps build-machine paths out of the binary (reproducible builds).
dist: generate
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(ASSET)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(ASSET)-linux-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(ASSET)-windows-amd64.exe .

# Run after `make dist`. Produces dist/checksums.txt for users to verify
# their download with `sha256sum --check checksums.txt`.
checksums:
	cd $(DIST) && sha256sum $(ASSET)-linux-amd64 $(ASSET)-linux-arm64 $(ASSET)-windows-amd64.exe > checksums.txt

# Cut a release: promote CHANGELOG.md's [Unreleased] section into a version
# section, commit that, tag it, and push — which triggers the CI release
# pipeline. Usage: make tag VERSION=v1.0.0
#
# The changelog roll happens *before* the tag on purpose: the release
# workflow reads its notes out of CHANGELOG.md at the tagged commit, so that
# commit has to be the one where [Unreleased] has become [X.Y.Z]. It also
# keeps the file to two sections (see scripts/roll-changelog.sh) instead of
# letting it grow a section per release forever.
tag:
	@test -n "$(VERSION)" || (echo "Usage: make tag VERSION=v1.0.0" && exit 1)
	@git diff --quiet && git diff --cached --quiet || { \
		echo "Working tree is dirty — commit or stash first, so the release"; \
		echo "commit contains only the changelog roll."; \
		exit 1; \
	}
	sh scripts/roll-changelog.sh $(VERSION)
	git add CHANGELOG.md
	git commit -m "release: prepare $(VERSION)"
	@echo "==> Tagging $(VERSION)"
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin HEAD
	git push origin $(VERSION)
	@echo "==> GitHub Actions release workflow started — watch it at:"
	@echo "    https://github.com/sinhaparth5/palisade-waf/actions"
