# Third-Party Notices

## MaxMind GeoLite2

This product includes GeoLite Data created by MaxMind, available from
[https://www.maxmind.com](https://www.maxmind.com).

The bundled `internal/security/geo/GeoLite2-Country.mmdb` database is distributed under the
MaxMind GeoLite End User License Agreement. Keep bundled release data current
and replace or remove old GeoLite database versions within the period required
by the agreement.

## DB-IP ASN Lite

This product includes the IP to ASN Lite database by DB-IP
([https://db-ip.com](https://db-ip.com)), bundled as `internal/security/asn/dbip-asn-lite.mmdb`
and licensed under Creative Commons Attribution 4.0 International
(CC BY 4.0).

## go-qrcode

This product includes the go-qrcode library
([https://github.com/skip2/go-qrcode](https://github.com/skip2/go-qrcode)),
Copyright (c) 2014 Tom Harwood, licensed under the MIT License. It renders
the QR code shown once during two-factor authentication enrollment on the
admin Settings page.

## FingerprintJS

This product includes FingerprintJS
([https://github.com/fingerprintjs/fingerprintjs](https://github.com/fingerprintjs/fingerprintjs)),
Copyright (c) FingerprintJS, Inc, vendored as `internal/security/challenge/fp.min.js` and
licensed under the MIT License (the full license text is retained in the
file's header comment). It is served to visitors at `/_cz/fp.js` by the bot
challenge page to compute a browser visitor identifier.


## Admin UI assets

Served from the binary under `{admin}/static/vendor/` (vendored in
`internal/ui/vendor/`) so the admin UI's Content-Security-Policy allows no
external origin:

- **htmx** 1.9.12 ([https://htmx.org](https://htmx.org)), Copyright (c) Big Sky Software, Zero-Clause BSD License.
- **Chart.js** 4.4.4 ([https://www.chartjs.org](https://www.chartjs.org)), Copyright (c) Chart.js Contributors, MIT License.
- **flag-icons** 7.5.0 ([https://github.com/lipis/flag-icons](https://github.com/lipis/flag-icons)), Copyright (c) 2013 Panayiotis Lipiridis, MIT License (`internal/ui/vendor/flag-icons/LICENSE`). Only the 4x3 flags are included.
- **Hugeicons** free stroke-rounded icon font ([https://hugeicons.com](https://hugeicons.com)), MIT License.
- **Calistoga, DM Sans, JetBrains Mono, Caveat** from Google Fonts, SIL Open Font License 1.1, latin and latin-ext subsets.
