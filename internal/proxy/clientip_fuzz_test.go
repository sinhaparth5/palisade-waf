package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// FuzzClientIP checks the address every block, ban and rate limit keys on
// (issue #304): it is always an IP from the input, an untrusted peer can't
// pick it with headers, and from X-Forwarded-For only a hop with nothing
// but trusted proxies to its right counts.
func FuzzClientIP(f *testing.F) {
	f.Add("203.0.113.9", "1.2.3.4", "", "", uint8(0))
	f.Add("10.0.0.1", "1.2.3.4, 10.0.0.2", "", "", uint8(1))
	f.Add("10.0.0.1", "evil, 1.2.3.4", "5.6.7.8", "", uint8(1))
	f.Add("::ffff:10.0.0.1", " 2001:db8::1 ,::ffff:1.2.3.4", "", "", uint8(2))
	f.Add("173.245.48.1", "", "", "198.51.100.7", uint8(0)) // Cloudflare peer
	f.Add("fe80::1%eth0", "", "", "", uint8(2))
	trustSets := [][]*net.IPNet{
		nil,
		ParseTrustedProxyCIDRs([]string{"10.0.0.0/8", "2001:db8::/32"}),
		ParseTrustedProxyCIDRs([]string{"0.0.0.0/0", "::/0"}),
	}
	f.Fuzz(func(t *testing.T, remote, xff, xri, cf string, sel uint8) {
		// net/http's RemoteAddr is an address and port; a zone is an
		// interface name, so it never breaks the host:port split.
		addr := net.JoinHostPort(remote, "1234")
		if _, err := netip.ParseAddr(remote); err != nil {
			t.Skip()
		}
		if h, _, err := net.SplitHostPort(addr); err != nil || h != remote {
			t.Skip()
		}
		trusted := trustSets[int(sel)%len(trustSets)]
		r := &http.Request{RemoteAddr: addr, Header: http.Header{}}
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Real-IP", xri)
		r.Header.Set("CF-Connecting-IP", cf)

		got := ClientIP(r, trusted)
		if net.ParseIP(got) == nil {
			t.Fatalf("ClientIP = %q, not an IP", got)
		}
		peer := normalizeIP(socketPeerIP(addr))
		cfPeer, trustedPeer := isCloudflareIP(peer), inNets(peer, trusted)
		if !cfPeer && !trustedPeer && got != peer {
			t.Fatalf("untrusted peer %q resolved to %q", remote, got)
		}
		if got == peer || (cfPeer && got == validIP(cf)) {
			return
		}
		if !trustedPeer {
			t.Fatalf("%q came from a header of an untrusted peer %q", got, remote)
		}
		hops := strings.Split(xff, ",")
		ok := slices.ContainsFunc(hops, func(h string) bool { return validIP(h) == got })
		if !ok {
			if got != validIP(xri) {
				t.Fatalf("%q is in no input", got)
			}
			return
		}
		// Some occurrence of got must have only valid, trusted hops after it.
		for i := len(hops) - 1; i >= 0; i-- {
			ip := validIP(hops[i])
			if ip == got {
				return
			}
			if ip == "" || !inNets(ip, trusted) {
				break
			}
		}
		if got != validIP(xri) {
			t.Fatalf("%q picked from XFF %q past an untrusted hop", got, xff)
		}
	})
}
