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

### Added

- (#193) Autoban on repeated 4xx responses (scanner detection)
- (#194) Threat intel: CIDR ranges in feeds and CrowdSec LAPI source
- (#195) Strict Content-Security-Policy for the admin UI
- (#196) Multiple admin users with roles
- (#197) OIDC single sign-on for the admin UI
- (#198) Maintenance mode and waiting room per service

## [2.10.5] - 2026-10-27

### Added

- (#187) AI crawler policy per service: allow, challenge or block by crawler category
- (#188) Check login passwords against known breaches (HIBP k-anonymity)
- (#189) Virtual patching: curated rule pack for actively exploited CVEs
- (#190) OpenAPI positive security model per service
- (#191) Client certificate (mTLS) authentication per service
- (#192) Opt-in response inspection to catch error leaks and data leakage

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.5...main
[2.10.5]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.4...v2.10.5
