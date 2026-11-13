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

- (#319) Make the multipart request body limit configurable

## [3.3.2] - 2026-11-13

- (#318) Read the admin audit log from the shell (setup --audit)
- (#317) Reset an admin's 2FA from the shell (setup --reset-2fa)
- (#316) List admin users from the shell (setup --list-users)

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v3.3.2...main
[3.3.2]: https://github.com/sinhaparth5/palisade-waf/compare/v3.3.1...v3.3.2
