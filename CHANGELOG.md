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

- (#310) Path-based checks can be bypassed with non-canonical paths
- (#311) CSP inventory can be filled with fake reports to silence new-script alerts
- (#312) Bot challenge pass cookie is not bound to the client

## [3.2.8] - 2026-11-12

- (#291) Let the WAF verdict cache serve requests that carry cookies
- (#292) Cut the cost of inspecting large JSON bodies
- (#301) Remove leftover ja3_hash and redis_mode references
- (#297) Drop the Windows release build
- (#298) Remove the ClickHouse warehouse mirror
- (#299) Remove TypeSafe ASN classification
- (#300) Drop MySQL and Postgres backends, SQLite only
- (#303) Rename docker-compose.yml to compose.yml
- (#302) Verify the feature removals leave a clean upgrade and no residue
- (#296) Allow the login of existing users via SSO

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.8...main
[3.2.8]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.7...v3.2.8
