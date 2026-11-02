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

- (#243) Read-only REST API endpoints for the CLI
- (#244) Palisade CLI: skeleton, config and services view
- (#245) Palisade CLI: logs view and live tail
- (#246) Palisade CLI: stats dashboard, rules and bans views

## [3.1.0] - 2026-11-01

- (#232) CRS: vendor 4.25.2 LTS to pick up the October 2026 bypass fixes
- (#233) Bot: verify Web Bot Auth (RFC 9421) signed agents
- (#234) WAF: MCP endpoint guard (Origin check, JSON-RPC method allowlist)
- (#235) CSP report-only and third-party script inventory
- (#236) Virtual patches for 2026 CISA KEV web CVEs

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.1.0...main
[3.1.0]: https://github.com/sinhaparth5/palisade-waf/compare/v3.0.5...v3.1.0
