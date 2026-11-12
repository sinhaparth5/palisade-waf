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

- (#291) Let the WAF verdict cache serve requests that carry cookies
- (#292) Cut the cost of inspecting large JSON bodies
- (#301) Remove leftover ja3_hash and redis_mode references
- (#297) Drop the Windows release build

## [3.2.7] - 2026-11-12

- (#285) Remove Redis leftovers and historical comments
- (#286) Raise test coverage on the least-covered files
- (#287) Make main.go testable and stop ignoring it in Codecov

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.7...main
[3.2.7]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.6...v3.2.7
