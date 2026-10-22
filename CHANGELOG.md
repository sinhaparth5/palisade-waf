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

### Fixed

- (#161) Data race on the pending 2FA login entry
- (#160) Cloudflare fingerprint headers trusted from any peer
- (#159) Login path protection matches exact paths only
- (#158) Backend migration drops the API key read-only flag
- (#170) Registered devices lists the same browser twice after re-login
- (#157) Crawler open paths skip WAF header inspection
- (#156) Autoban bans are permanent and can be triggered by cross-site subresource requests
- (#155) Cache Director forwards client-supplied X-Cache-* headers to Varnish
- (#153) Request logs keep credential headers
- (#154) Client IP taken from the leftmost X-Forwarded-For entry
- (#163) Installer upgrade overwrites custom flags in the systemd unit
- (#152) WAF verdict cache key does not cover request headers

## [2.9.51] - 2026-10-22

### Added

- Open crawler files (robots.txt, sitemap, llms.txt) to every client

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.9.51...main
[2.9.51]: https://github.com/sinhaparth5/palisade-waf/compare/v2.9.5...v2.9.51
