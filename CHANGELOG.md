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

### Added

- Admin audit log: every change made from the admin dashboard or the REST API is recorded with time, who made it (the admin session or the named API key), source IP, the action and its target. It's shown read-only on the Settings page and kept for at least a year (or your `--retention`, if longer) by the existing `prune`. Rejected requests aren't logged, and secret values never are: only an allowlist of identifying fields such as names, IPs and rule IDs is copied (#129).
- Honeypot paths: list paths only scanners ask for (e.g. `/wp-login.php` on a site that isn't WordPress, `/xmlrpc.php`, `/phpmyadmin/`) in the new card on the IP Rules page. A client that requests one and gets a 404 is banned by Automatic banning on that first hit, and the request is logged with the `honeypot` action. A path your backend really serves never answers 404, so it can't fire for real visitors. `/.env` and `/.git/` don't need listing: the OWASP rules already block them (#130).

### Security

- IPv6 clients are now rate limited, scored by Automatic banning and given a threat score per /64 network instead of per address, so rotating through the addresses of one /64 no longer resets the limit or dodges a ban. An automatic ban on an IPv6 client blocks its whole /64. IPv4 is unchanged, and logs and manual IP rules still use exact addresses (#131).
- Trusted crawlers are now verified by where they connect from, not just their user agent, so sending `User-Agent: Googlebot` no longer skips the bot challenge. Search-engine and SEO crawlers are checked by forward-confirmed reverse DNS, link-preview bots (Meta, X, LinkedIn, Telegram) and the Internet Archive by ASN, and a failed check falls back to normal scoring. Slackbot, Discordbot and DuckDuckBot publish no way to verify them and are no longer trusted. `dev-portal-uptime` is no longer trusted by default either; trust your own monitors with the new `--trusted-crawlers` flag, e.g. `--trusted-crawlers "my-monitor=203.0.113.5"` (#128).
- Every HTTP server now sets a 10s header-read timeout, a 120s idle timeout and a 1 MiB header cap, so a client trickling headers (Slowloris) can no longer hold connections open indefinitely. Uploads, SSE and WebSockets are unaffected, since no read or write timeout is set (#127).

## [2.8.4] - 2026-10-20

### Changed

- The `dev-portal-uptime` user agent is now a trusted crawler, so the uptime monitor skips the bot challenge. The WAF still inspects every request it makes.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.4...main
[2.8.4]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.3...v2.8.4
