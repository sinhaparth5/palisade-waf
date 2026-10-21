package accesslog

import (
	"strconv"
	"strings"
	"testing"
)

// FuzzEscape checks that escape output is printable ASCII with no bare quote,
// so a client-controlled field can never end its quoted field early or split
// the line, and that it decodes back to the input byte for byte.
func FuzzEscape(f *testing.F) {
	for _, s := range []string{"", "GET", `/a"b\c`, "Mozilla/5.0 (X11)", "\r\n\x00\x7f", "héllo"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := escape(s)
		var dec strings.Builder
		for i := 0; i < len(out); i++ {
			c := out[i]
			if c < 0x20 || c > 0x7e || c == '"' {
				t.Fatalf("escape(%q) = %q: raw byte %#x", s, out, c)
			}
			if c != '\\' {
				dec.WriteByte(c)
				continue
			}
			if i+4 > len(out) || out[i+1] != 'x' {
				t.Fatalf("escape(%q) = %q: truncated escape", s, out)
			}
			b, err := strconv.ParseUint(out[i+2:i+4], 16, 8)
			if err != nil {
				t.Fatalf("escape(%q) = %q: bad escape: %v", s, out, err)
			}
			dec.WriteByte(byte(b))
			i += 3
		}
		if dec.String() != s {
			t.Fatalf("escape(%q) = %q decodes to %q", s, out, dec.String())
		}
	})
}
