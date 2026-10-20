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

- Admin UI and login page were unreadable (cream text on white panels, dark inputs) for anyone whose OS is set to dark mode: the new dark palette followed `prefers-color-scheme`, but several surfaces (e.g. `lg:bg-white`) are not remapped. The UI is now always light; the dark palette is opt-in via `data-theme="dark"` and off by default (#126).

## [2.8.2] - 2026-10-20

### Fixed

- WebSocket connections to a service with caching on failed (the backend saw a plain `GET` and answered 404): every `GET` was routed through Varnish, which drops the `Upgrade` header. Requests carrying `Upgrade` now skip the cache and go straight to the backend.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.2...main
[2.8.2]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.1...v2.8.2
