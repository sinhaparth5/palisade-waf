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

- (#212) Feature Request: Add Path-Based Varnish Cache Rules and Fix Static Asset Loading Issues

## [2.11.0] - 2026-10-27

### Added

- (#193) Autoban on repeated 4xx responses (scanner detection)
- (#194) Threat intel: CIDR ranges in feeds and CrowdSec LAPI source
- (#195) Strict Content-Security-Policy for the admin UI
- (#196) Multiple admin users with roles
- (#197) OIDC single sign-on for the admin UI
- (#198) Maintenance mode and waiting room per service

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.11.0...main
[2.11.0]: https://github.com/sinhaparth5/palisade-waf/compare/v2.10.5...v2.11.0
