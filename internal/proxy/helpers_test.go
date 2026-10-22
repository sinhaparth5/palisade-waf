package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTLSInfo(t *testing.T) {
	if v, c, s := tlsInfo(httptest.NewRequest("GET", "/", nil)); v+c+s != "" {
		t.Errorf("plain HTTP = %q %q %q", v, c, s)
	}
	for ver, want := range map[uint16]string{
		tls.VersionTLS13: "TLS 1.3", tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS11: "TLS 1.1", tls.VersionTLS10: "TLS 1.0", 0x7f00: "0x7f00",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.TLS = &tls.ConnectionState{Version: ver, CipherSuite: tls.TLS_AES_128_GCM_SHA256, ServerName: "a.test"}
		v, c, s := tlsInfo(r)
		if v != want || c != "TLS_AES_128_GCM_SHA256" || s != "a.test" {
			t.Errorf("tlsInfo(%#x) = %q %q %q", ver, v, c, s)
		}
	}
}

func TestIPHelpers(t *testing.T) {
	if got := ParseTrustedProxyCIDRs([]string{" 10.0.0.0/8 ", "", "bogus", "::1/128"}); len(got) != 2 {
		t.Errorf("trusted CIDRs = %v", got)
	}
	for in, want := range map[string]string{"1.2.3.4:80": "1.2.3.4", "no-port": "no-port", "[::1]:80": "::1"} {
		if got := socketPeerIP(in); got != want {
			t.Errorf("socketPeerIP(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"::ffff:127.0.0.1": "127.0.0.1", "::1": "::1", "garbage": "garbage"} {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q) = %q", in, got)
		}
	}
	if inNets("not-an-ip", ParseTrustedProxyCIDRs([]string{"0.0.0.0/0"})) {
		t.Error("unparseable peer trusted")
	}
}

// TestClientIP pins issue #154: forwarded addresses come from the right end
// of the chain, which only trusted proxies wrote, and must be real IPs.
func TestClientIP(t *testing.T) {
	trusted := ParseTrustedProxyCIDRs([]string{"192.0.2.0/24"})
	cases := []struct {
		name, peer string
		hdr        map[string][]string
		want       string
	}{
		{"untrusted peer ignores headers", "203.0.113.7:1", map[string][]string{"X-Forwarded-For": {"10.0.0.1"}, "X-Real-Ip": {"10.0.0.2"}}, "203.0.113.7"},
		{"single hop", "192.0.2.10:1", map[string][]string{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7"},
		{"client-sent entry left of real one", "192.0.2.10:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1, 203.0.113.7"}}, "203.0.113.7"},
		{"trusted hops skipped", "192.0.2.10:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1, 203.0.113.7, 192.0.2.20"}}, "203.0.113.7"},
		{"split across header lines", "192.0.2.10:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1", "203.0.113.7"}}, "203.0.113.7"},
		{"all hops trusted", "192.0.2.10:1", map[string][]string{"X-Forwarded-For": {"192.0.2.30, 192.0.2.20"}}, "192.0.2.30"},
		{"garbage stops the walk", "192.0.2.10:1", map[string][]string{"X-Forwarded-For": {"evil"}}, "192.0.2.10"},
		{"garbage X-Real-IP ignored", "192.0.2.10:1", map[string][]string{"X-Real-Ip": {"evil"}}, "192.0.2.10"},
		{"X-Real-IP from trusted peer", "192.0.2.10:1", map[string][]string{"X-Real-Ip": {"203.0.113.7"}}, "203.0.113.7"},
		{"mapped IPv4 normalized", "192.0.2.10:1", map[string][]string{"X-Forwarded-For": {"::ffff:203.0.113.7"}}, "203.0.113.7"},
		{"CF header from Cloudflare", "173.245.48.1:1", map[string][]string{"Cf-Connecting-Ip": {"203.0.113.7"}}, "203.0.113.7"},
		{"CF header from elsewhere", "203.0.113.9:1", map[string][]string{"Cf-Connecting-Ip": {"1.1.1.1"}}, "203.0.113.9"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		for k, v := range tc.hdr {
			r.Header[k] = v
		}
		if got := ClientIP(r, trusted); got != tc.want {
			t.Errorf("%s: ClientIP = %q, want %q", tc.name, got, tc.want)
		}
	}
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	hijacked, flushed bool
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}
func (h *hijackRecorder) Flush() { h.flushed = true }

// TestResponseWriterPassthrough pins the reason responseWriter exists:
// WebSocket upgrades need Hijack and SSE needs Flush to reach the real writer.
func TestResponseWriterPassthrough(t *testing.T) {
	inner := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	rw := &responseWriter{ResponseWriter: inner}
	if _, _, err := rw.Hijack(); err != nil || !inner.hijacked {
		t.Errorf("Hijack not delegated: %v", err)
	}
	rw.Flush()
	if !inner.flushed {
		t.Error("Flush not delegated")
	}
	rw.WriteHeader(http.StatusTeapot)
	if rw.status != http.StatusTeapot || inner.Code != http.StatusTeapot {
		t.Errorf("status = %d / %d", rw.status, inner.Code)
	}

	plain := &responseWriter{ResponseWriter: struct{ http.ResponseWriter }{httptest.NewRecorder()}}
	if _, _, err := plain.Hijack(); err == nil {
		t.Error("Hijack should fail when the inner writer can't")
	}
	plain.Flush() // no-op, must not panic
}
