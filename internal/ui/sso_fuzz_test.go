package ui

import (
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// FuzzSSOCookie (issue #306): a callback reaches the token exchange only
// when its state equals a well-formed cz_sso cookie's, and the nonce and
// verifier handed on are that cookie's.
func FuzzSSOCookie(f *testing.F) {
	state, nonce, verifier := randHex(16), randHex(16), oauth2.GenerateVerifier()
	valid := state + "." + nonce + "." + verifier
	f.Add(valid, state)
	f.Add(valid, "")
	f.Add("..", "")
	f.Add(".x.y", "")
	f.Add(valid+".", state)
	f.Add(strings.ToUpper(valid), state)
	if n, v, ok := parseSSOCookie(valid, state); !ok || n != nonce || v != verifier {
		f.Fatal("real cookie refused")
	}

	f.Fuzz(func(t *testing.T, value, st string) {
		n, v, ok := parseSSOCookie(value, st)
		if !ok {
			return
		}
		if len(st) != 32 || len(n) != 32 || v == "" || value != st+"."+n+"."+v {
			t.Fatalf("accepted cookie %q with state %q (nonce %q, verifier %q)", value, st, n, v)
		}
	})
}
