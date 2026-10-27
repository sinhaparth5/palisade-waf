package blocklist

import (
	"net"
	"net/netip"
	"slices"
	"sync"

	"palisade/internal/storage"
)

type cidrRule struct {
	network  *net.IPNet
	ruleType string
}

// IPBlocklist holds IP allow/block rules in memory for fast per-request lookup.
// Supports both plain IPs (O(1) exact match) and CIDR ranges (O(n) linear scan,
// but the CIDR list stays small in practice). Per-app rules take priority over
// global rules at each level. "allow" wins over "block" at the same scope.
// Threat-intel blocks have the lowest priority — any user rule (allow or block)
// at any scope takes precedence.
type IPBlocklist struct {
	mu          sync.RWMutex
	exact       map[string]string     // "appName:ip" or ":ip" → "block"|"allow"
	appCIDRs    map[string][]cidrRule // appName → per-app CIDR rules
	globalCIDRs []cidrRule
	// threat-intel blocks (lowest priority — user rules always win). A
	// sorted range set, not a CIDR scan: feeds and CrowdSec can hold 100k+
	// ranges (issue #194).
	intel rangeSet
}

func NewIPBlocklist(db *storage.DB) (*IPBlocklist, error) {
	bl := &IPBlocklist{}
	if err := bl.Reload(db); err != nil {
		return nil, err
	}
	if err := bl.ReloadIntel(db); err != nil {
		return nil, err
	}
	return bl, nil
}

// Reload re-reads all rules from the DB. Call after adding/removing rules via
// the UI.
func (bl *IPBlocklist) Reload(db *storage.DB) error {
	rows, err := db.ListIPRules()
	if err != nil {
		return err
	}

	exact := make(map[string]string, len(rows))
	appCIDRs := make(map[string][]cidrRule)
	var globalCIDRs []cidrRule

	for _, r := range rows {
		if _, network, err := net.ParseCIDR(r.IP); err == nil {
			rule := cidrRule{network: network, ruleType: r.RuleType}
			if r.AppName == "" {
				globalCIDRs = append(globalCIDRs, rule)
			} else {
				appCIDRs[r.AppName] = append(appCIDRs[r.AppName], rule)
			}
		} else {
			exact[r.AppName+":"+r.IP] = r.RuleType
		}
	}

	bl.mu.Lock()
	bl.exact = exact
	bl.appCIDRs = appCIDRs
	bl.globalCIDRs = globalCIDRs
	bl.mu.Unlock()
	return nil
}

// ReloadIntel re-reads all threat-intel IPs from the DB and swaps the
// in-memory intel block set. Called by the threatintel.Worker after each
// sync.
func (bl *IPBlocklist) ReloadIntel(db *storage.DB) error {
	feed, err := db.ListThreatIntelIPs()
	if err != nil {
		return err
	}
	crowdsec, err := db.ListCrowdSecIPs()
	if err != nil {
		return err
	}
	rs := make([]ipRange, 0, len(feed)+len(crowdsec))
	rs = appendRanges(rs, feed, "ip_blocked_intel")
	rs = appendRanges(rs, crowdsec, "ip_blocked:crowdsec")
	intel := buildRangeSet(rs)
	bl.mu.Lock()
	bl.intel = intel
	bl.mu.Unlock()
	return nil
}

// Check returns (blocked, reason). An empty reason means the request is allowed.
// Priority order: per-app exact → per-app CIDR → global exact → global CIDR →
// threat-intel (user allow rules always win over intel blocks).
func (bl *IPBlocklist) Check(ip, appName string) (blocked bool, reason string) {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	parsedIP := net.ParseIP(ip)

	// Per-app exact match.
	if rt, ok := bl.exact[appName+":"+ip]; ok {
		return rt == "block", ifBlock(rt, "ip_blocked")
	}

	// Per-app CIDR match.
	if parsedIP != nil {
		for _, r := range bl.appCIDRs[appName] {
			if r.network.Contains(parsedIP) {
				return r.ruleType == "block", ifBlock(r.ruleType, "ip_blocked")
			}
		}
	}

	// Global exact match.
	if rt, ok := bl.exact[":"+ip]; ok {
		return rt == "block", ifBlock(rt, "ip_blocked_global")
	}

	// Global CIDR match.
	if parsedIP != nil {
		for _, r := range bl.globalCIDRs {
			if r.network.Contains(parsedIP) {
				return r.ruleType == "block", ifBlock(r.ruleType, "ip_blocked_global")
			}
		}
	}

	// Threat-intel block (lowest priority — user allow rules already returned above).
	if addr, err := netip.ParseAddr(ip); err == nil {
		if reason := bl.intel.lookup(addr.Unmap()); reason != "" {
			return true, reason
		}
	}

	return false, ""
}

// ipRange is an inclusive address range with the block reason it logs.
type ipRange struct {
	from, to netip.Addr
	reason   string
}

// rangeSet is sorted by from with no overlaps, so lookup is a binary search.
type rangeSet []ipRange

// appendRanges parses IPs and CIDRs into ranges, skipping anything invalid.
func appendRanges(rs []ipRange, entries []string, reason string) []ipRange {
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			p = p.Masked()
			rs = append(rs, ipRange{p.Addr().Unmap(), lastAddr(p).Unmap(), reason})
		} else if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			rs = append(rs, ipRange{a, a, reason})
		}
	}
	return rs
}

// buildRangeSet sorts rs and merges overlapping ranges; a merged range keeps
// the reason of the one that starts first. IPv4 sorts before IPv6 and the
// two never merge (netip.Addr.Compare orders by family first).
func buildRangeSet(rs []ipRange) rangeSet {
	slices.SortFunc(rs, func(a, b ipRange) int { return a.from.Compare(b.from) })
	out := rs[:0]
	for _, r := range rs {
		if n := len(out); n > 0 && out[n-1].to.BitLen() == r.from.BitLen() && r.from.Compare(out[n-1].to) <= 0 {
			if r.to.Compare(out[n-1].to) > 0 {
				out[n-1].to = r.to
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// lookup returns the reason of the range holding a, or "".
func (s rangeSet) lookup(a netip.Addr) string {
	i, found := slices.BinarySearchFunc(s, a, func(r ipRange, a netip.Addr) int { return r.from.Compare(a) })
	if !found {
		i-- // the last range starting before a
	}
	if i >= 0 && a.BitLen() == s[i].to.BitLen() && a.Compare(s[i].to) <= 0 {
		return s[i].reason
	}
	return ""
}

// lastAddr returns the highest address in the masked prefix p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func ifBlock(ruleType, reason string) string {
	if ruleType == "block" {
		return reason
	}
	return ""
}
