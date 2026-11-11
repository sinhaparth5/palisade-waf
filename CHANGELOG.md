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
- (#270) Block cloud metadata addresses at connect time for every outbound request
- (#271) Restrict the admin UI by source IP or a separate listener

## [3.2.2] - 2026-11-11

- (#259) Keep autoban and threat scoring running when the request log falls behind
- (#289) Reuse reverse proxy copy buffers
- (#288) Stop dashboard queries from scanning the whole request log
- (#260) Apply automatic bans in memory before persisting them
- (#261) Limit concurrent WAF body inspections
- (#269) Store admin session tokens hashed

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.2...main
[3.2.2]: https://github.com/sinhaparth5/palisade-waf/compare/v3.2.1...v3.2.2
