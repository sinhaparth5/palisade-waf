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

- (#285) Remove Redis leftovers and historical comments

## [3.2.6] - 2026-11-12

- (#284) Shrink the embedded icon and flag assets
- (#283) Enforce mode for the script inventory CSP
- (#282) Per-service request policy: methods, content types and body size
- (#281) Harden backend cookies and response headers per service
- (#267) Owner-only pprof endpoint
- (#266) Remove JA3 fingerprinting

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.6...main
[3.2.6]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.5...v3.2.6
