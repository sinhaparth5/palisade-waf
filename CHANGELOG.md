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

### Fixed

- WebSocket connections to a service with caching on failed (the backend saw a plain `GET` and answered 404): every `GET` was routed through Varnish, which drops the `Upgrade` header. Requests carrying `Upgrade` now skip the cache and go straight to the backend.

## [2.8.1] - 2026-10-19

### Added

- The 2FA step of admin login now submits by itself once a 6-digit code is typed, pasted or autofilled. Backup codes still need the Verify button.

### Changed

- AhrefsBot and AhrefsSiteAudit are now trusted crawlers, so they skip the bot challenge. The WAF still inspects every request they make.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.1...main
[2.8.1]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.0...v2.8.1
