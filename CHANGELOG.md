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

## [3.2.9] - 2026-11-12

- (#304) Fuzz client IP resolution
- (#305) Fuzz edge JWT verification
- (#306) Fuzz signed cookie parsing for challenge, waiting room and SSO
- (#307) Fuzz request body and header extractors
- (#308) Fuzz admin rule parsers and config import
- (#309) Read-only MCP server for AI assistants
- (#310) Path-based checks can be bypassed with non-canonical paths
- (#311) CSP inventory can be filled with fake reports to silence new-script alerts
- (#312) Bot challenge pass cookie is not bound to the client
- (#313) Allow service that uses self signed certificate

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.9...main
[3.2.9]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.8...v3.2.9
