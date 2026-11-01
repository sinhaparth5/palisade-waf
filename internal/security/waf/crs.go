package waf

import (
	"embed"
	"io/fs"
)

// CRS is vendored (scripts/update-crs.sh) rather than taken from
// coraza-coreruleset, which stopped at v4.25.0 and missed the 4.25.2 LTS
// bypass fixes (issue #232). crs/VERSION holds the tag.
//
//go:embed crs
var crsEmbed embed.FS

var crsFS, _ = fs.Sub(crsEmbed, "crs")
