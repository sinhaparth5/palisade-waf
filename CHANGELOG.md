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

- (#187) AI crawler policy per service: allow, challenge or block by crawler category
- (#188) Check login passwords against known breaches (HIBP k-anonymity)

## [2.10.4] - 2026-10-26

### Fixed

- (#186) Review: forwarded IP headers, shutdown drain, ACME listener, TypeSafe retries

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.4...main
[2.10.4]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.3...v2.10.4
