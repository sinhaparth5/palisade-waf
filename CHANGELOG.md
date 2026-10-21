# Changelog

All notable changes to **Palisade** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file deliberately keeps only two sections: **[Unreleased]**, where changes
accumulate, and the **most recently published version**, kept so the current
release is readable without leaving the repo. `make tag VERSION=vX.Y.Z` promotes
Unreleased into a new version section, drops the previous one, and opens a fresh
Unreleased — older entries stay available in their git tags and GitHub releases
rather than growing this file forever.

## [Unreleased]

### Security

- Every HTTP server now sets a 10s header-read timeout, a 120s idle timeout and a 1 MiB header cap, so a client trickling headers (Slowloris) can no longer hold connections open indefinitely. Uploads, SSE and WebSockets are unaffected, since no read or write timeout is set (#127).

## [2.8.4] - 2026-10-20

### Changed

- The `dev-portal-uptime` user agent is now a trusted crawler, so the uptime monitor skips the bot challenge. The WAF still inspects every request it makes.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.4...main
[2.8.4]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.3...v2.8.4
