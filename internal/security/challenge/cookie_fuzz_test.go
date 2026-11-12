package challenge

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
)

// FuzzChallengeCookie (issue #306): only the exact cookie issued to a
// client passes, and only for that client (IPv6 /64). Without the secret
// the fuzzer can't forge a MAC, so any other accepted value is a parser bug.
func FuzzChallengeCookie(f *testing.F) {
	c := New("fuzz-secret", 3600, 3)
	const ip = "2001:db8::1"
	valid := c.buildCookieValue(4102444800, ip, "visitor-1") // fixed (2100), so saved inputs replay
	f.Add(valid, ip, uint(0), byte('x'))
	f.Add(valid, "2001:db8::2", uint(3), byte('0'))
	f.Add(valid, "2001:dB8::", uint(3), byte(0x7f))
	f.Add(valid, "198.51.100.7", uint(len(valid)-1), byte('A'))
	f.Add("+"+valid, ip, uint(0), byte('+'))
	f.Add("0"+valid, ip, uint(5), byte('.'))
	f.Add("1.x.", ip, uint(1), byte(0))
	if _, ok := c.parseCookie(valid, ip); !ok {
		f.Fatal("issued cookie refused")
	}

	f.Fuzz(func(t *testing.T, value, clientIP string, pos uint, b byte) {
		a, err := netip.ParseAddr(clientIP)
		same := err == nil && client64.Contains(a) // the cookie is bound to the /64
		if vid, ok := c.parseCookie(value, clientIP); ok && (value != valid || !same || vid != "visitor-1") {
			t.Fatalf("accepted %q for %q (visitor %q)", value, clientIP, vid)
		}
		// One changed byte of the real cookie is always refused.
		if i := int(pos % uint(len(valid))); valid[i] != b {
			mut := valid[:i] + string(b) + valid[i+1:]
			if _, ok := c.parseCookie(mut, ip); ok {
				t.Fatalf("accepted mutated cookie %q", mut)
			}
		}
	})
}

var client64 = netip.MustParsePrefix("2001:db8::/64")

// FuzzVerifyPoW: a solution passes only when SHA-256(nonce || decimal)
// really starts with a zero byte.
func FuzzVerifyPoW(f *testing.F) {
	f.Add("abc", uint64(0))
	f.Add("", uint64(1<<63))
	f.Add("nonce-1", uint64(208)) // a real solution or not, the oracle decides
	f.Fuzz(func(t *testing.T, nonce string, solution uint64) {
		h := sha256.Sum256(fmt.Appendf(nil, "%s%d", nonce, solution))
		if got, want := verifyPoW(nonce, solution), h[0] == 0; got != want {
			t.Fatalf("verifyPoW(%q, %d) = %v, want %v", nonce, solution, got, want)
		}
	})
}
