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

- (#315) Admin setup accepts a non-email login, says it configured an account it skipped, and has no password reset

## [3.3.0] - 2026-11-12

- (#314) Return a JSON challenge_required to API calls instead of redirecting them to the challenge page

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.3.0...main
[3.3.0]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.9...v3.3.0
