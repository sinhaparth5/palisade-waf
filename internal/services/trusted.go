package services

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseTrustedIPs turns IPs and CIDRs into prefixes for SetTrustedIPs. Every
// valid entry is returned; err names the first one that isn't.
func ParseTrustedIPs(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	var err error
	for _, e := range entries {
		p, perr := netip.ParsePrefix(e)
		if !strings.Contains(e, "/") {
			var a netip.Addr
			if a, perr = netip.ParseAddr(e); perr == nil {
				a = a.Unmap()
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if perr != nil {
			if err == nil {
				err = fmt.Errorf("%q is not an IP address or CIDR range", e)
			}
			continue
		}
		out = append(out, p.Masked())
	}
	return out, err
}

// SetTrustedIPs swaps in the trusted IP list (issue #179). Reload calls it
// from the DB; the Settings page calls it directly after saving.
func (r *Registry) SetTrustedIPs(nets []netip.Prefix) {
	r.mu.Lock()
	r.trusted = nets
	r.mu.Unlock()
}

// Trusted reports whether ip is on the trusted list, whose requests skip
// every blocking stage of the proxy pipeline. Nil-receiver safe.
func (r *Registry) Trusted(ip string) bool {
	if r == nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
