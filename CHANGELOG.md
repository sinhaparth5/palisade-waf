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

- (#274) Run the Docker image as a non-root user
- (#275) Tighten the systemd sandbox in install.sh
- (#276) Pin GitHub Actions to commit SHAs
- (#277) Move to Echo v5
- (#278) Enable gosec and stricter linters
- (#279) Verify JWTs at the edge per service

## [3.2.3] - 2026-11-12

- (#270) Block cloud metadata addresses at connect time for every outbound request
- (#271) Restrict the admin UI by source IP or a separate listener
- (#272) Bound slow request bodies and per-client connections
- (#273) Reject weak and breached admin passwords

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.3...main
[3.2.3]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.2...v3.2.3
