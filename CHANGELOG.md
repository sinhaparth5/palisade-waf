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

### Removed

- (#184) Remove Redis support

## [2.10.2] - 2026-10-22

### Fixed

- (#182) --trusted-proxies rejects single IP addresses

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.2...main
[2.10.2]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.1...v2.10.2
