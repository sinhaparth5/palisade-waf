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

- (#255) Compress and cache admin UI static assets

## [3.2.0] - 2026-11-02

- (#243) Read-only REST API endpoints for the CLI
- (#244) Palisade CLI: skeleton, config and services view
- (#245) Palisade CLI: logs view and live tail
- (#246) Palisade CLI: stats dashboard, rules and bans views
- (#253) Install the CLI from install.sh and version it with the WAF

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.0...main
[3.2.0]: https://github.com/sinhaparth5/palisade-waf/compare/v3.1.0...v3.2.0
