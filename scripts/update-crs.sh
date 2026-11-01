#!/usr/bin/env bash
# Vendor an OWASP CRS release into internal/security/waf/crs (embedded by
# crs.go). Usage: scripts/update-crs.sh v4.25.2
# @coraza.conf-recommended is ours and is left untouched.
set -euo pipefail

tag=${1:?usage: $0 <crs tag, e.g. v4.25.2>}
dst="$(cd "$(dirname "$0")/.." && pwd)/internal/security/waf/crs"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${tag}.tar.gz" | tar -xz -C "$tmp"
src="$tmp/coreruleset-${tag#v}"

rm -rf "$dst/@owasp_crs"
mkdir -p "$dst/@owasp_crs"
cp "$src"/rules/*.conf "$src"/rules/*.data "$dst/@owasp_crs/"
cp "$src/crs-setup.conf.example" "$dst/@crs-setup.conf.example"
cp "$src/LICENSE" "$dst/LICENSE"
echo "$tag" > "$dst/VERSION"
echo "CRS $tag vendored into $dst"
