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

- Open crawler files (robots.txt, sitemap, llms.txt) to every client

## [2.9.5] - 2026-10-21

### Added

- (#133) Turnstile / hCaptcha as challenge fallback
- (#134) UI: manual dark-mode toggle
- (#136) Fuzz tests for parsers
- (#137) Release supply chain: SBOM and signed binaries

### Changed

- (#135) UI: finish the field-notes theme (hatch, tape, badge colours)

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.9.5...main
[2.9.5]: https://github.com/sinhaparth5/palisade-waf/compare/v2.9.0...v2.9.5
