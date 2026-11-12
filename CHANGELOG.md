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

- (#266) Remove JA3 fingerprinting

## [3.2.5] - 2026-11-12

- (#265) Run fuzz tests in CI and cover the request parsers
- (#264) Split handlers.go and db.go into per-feature files
- (#263) Export and import configuration as a file
- (#262) REST API write endpoints for geo rules, rule exceptions and virtual patches
- (#280) Per-path rate limits per service

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.5...main
[3.2.5]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.4...v3.2.5
