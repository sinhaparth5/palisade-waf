package ratelimit

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzClientKey checks the per-client key behind rate limits, autoban and
// bans (issue #304): IPv4 keys are the address, and an IPv6 key is its /64,
// shared by every address in it and by no address outside it.
func FuzzClientKey(f *testing.F) {
	f.Add("203.0.113.9", uint64(0), uint64(0))
	f.Add("::ffff:1.2.3.4", uint64(1), uint64(0))
	f.Add("2001:db8:1:2::1", uint64(0xffff), uint64(1))
	f.Add("fe80::1%eth0", uint64(7), uint64(1<<63))
	f.Fuzz(func(t *testing.T, ip string, low, high uint64) {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			t.Skip()
		}
		key := ClientKey(ip)
		if key != ClientKey(ip) {
			t.Fatal("key not stable")
		}
		if a.Is4() || a.Is4In6() {
			if key != ip {
				t.Fatalf("IPv4 %q keyed as %q", ip, key)
			}
			return
		}
		p, err := netip.ParsePrefix(key)
		if err != nil || p.Bits() != 64 || !p.Contains(a.WithZone("")) {
			t.Fatalf("IPv6 %q keyed as %q, want its /64", ip, key)
		}
		b := a.As16()
		binary.BigEndian.PutUint64(b[8:], low)
		if same := netip.AddrFrom16(b).String(); ClientKey(same) != key {
			t.Fatalf("%q and %q share a /64 but key %q vs %q", ip, same, key, ClientKey(same))
		}
		if high != 0 {
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(b[:8])^high)
			if other := netip.AddrFrom16(b); !other.Is4In6() && ClientKey(other.String()) == key {
				t.Fatalf("%q and %q are in different /64s but share key %q", ip, other, key)
			}
		}
	})
}
