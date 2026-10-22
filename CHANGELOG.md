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

- (#182) --trusted-proxies rejects single IP addresses

## [2.10.1] - 2026-10-22

### Fixed

- (#178) Settings page audit log grows without limit and layout breaks on mobile
- (#179) IP that can't be blocked

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.1...main
[2.10.1]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.0...v2.10.1
