package bot

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// crawler is a legitimate bot that skips the challenge gate, but only when
// its request comes from where the operator says it does: a UA substring
// alone is trivially spoofable (issue #128). A crawler verifies by any one of
// forward-confirmed reverse DNS, ASN or a pinned CIDR; one with none of them
// set never verifies and is scored like any other client.
type crawler struct {
	ua    []string       // lower-case User-Agent substrings
	rdns  []string       // PTR suffixes, forward-confirmed (e.g. "googlebot.com")
	asns  []uint         // origin ASNs from the bundled ASN database
	cidrs []netip.Prefix // pinned source ranges
}

// Slack, Discord and DuckDuckGo publish no reverse DNS or dedicated ASN for
// their fetchers, so they're deliberately absent: a UA-only entry would put
// the spoofing hole straight back.
var trustedCrawlers = []crawler{
	{ua: []string{"googlebot", "google-inspectiontool", "googleother", "adsbot-google", "google-read-aloud", "mediapartners-google"},
		rdns: []string{"googlebot.com", "google.com"}},
	{ua: []string{"bingbot", "bingpreview", "msnbot", "adidxbot"}, rdns: []string{"search.msn.com"}},
	{ua: []string{"applebot"}, rdns: []string{"applebot.apple.com"}},
	{ua: []string{"slurp"}, rdns: []string{"crawl.yahoo.net"}},
	{ua: []string{"yandexbot", "yandexmobilebot"}, rdns: []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{ua: []string{"baiduspider"}, rdns: []string{"baidu.com", "baidu.jp"}},
	{ua: []string{"pinterest/"}, rdns: []string{"pinterest.com"}},
	{ua: []string{"ahrefsbot", "ahrefssiteaudit"}, rdns: []string{"ahrefs.com", "ahrefs.net"}},
	// Meta: Facebook and WhatsApp link previews.
	{ua: []string{"facebookexternalhit", "facebot", "whatsapp/"}, asns: []uint{32934}},
	{ua: []string{"twitterbot"}, asns: []uint{13414}},
	{ua: []string{"linkedinbot"}, asns: []uint{14413}},
	{ua: []string{"telegrambot"}, asns: []uint{62041}},
	{ua: []string{"ia_archiver", "archive.org_bot"}, asns: []uint{7941}},
}

// AddPinnedCrawlers trusts extra crawlers by source range, from the
// --trusted-crawlers flag: "ua=cidr[,cidr];ua2=ip". Operator-specific, so it
// stays out of the source (a self-hosted monitor's IP is the server's own).
// Must run before serving: trustedCrawlers is read without a lock.
func AddPinnedCrawlers(spec string) error {
	for entry := range strings.SplitSeq(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		ua, ranges, ok := strings.Cut(entry, "=")
		ua = strings.ToLower(strings.TrimSpace(ua))
		if !ok || ua == "" {
			return fmt.Errorf("trusted crawler %q: want ua=cidr[,cidr]", entry)
		}
		c := crawler{ua: []string{ua}}
		for r := range strings.SplitSeq(ranges, ",") {
			p, err := parsePrefix(strings.TrimSpace(r))
			if err != nil {
				return fmt.Errorf("trusted crawler %q: %w", ua, err)
			}
			c.cidrs = append(c.cidrs, p)
		}
		trustedCrawlers = append(trustedCrawlers, c)
	}
	return nil
}

// parsePrefix accepts a CIDR or a bare IP (a single-address range).
func parsePrefix(s string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err
}

func matchCrawler(uaLow string) *crawler {
	for i := range trustedCrawlers {
		for _, s := range trustedCrawlers[i].ua {
			if strings.Contains(uaLow, s) {
				return &trustedCrawlers[i]
			}
		}
	}
	return nil
}

func verifyCrawler(c *crawler, ip string, asnNum uint) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range c.cidrs {
		if p.Contains(addr) {
			return true
		}
	}
	if asnNum != 0 && slices.Contains(c.asns, asnNum) {
		return true
	}
	return len(c.rdns) > 0 && rdnsVerified(addr, c.rdns)
}

// Swappable for tests.
var (
	lookupAddr = net.DefaultResolver.LookupAddr
	lookupHost = net.DefaultResolver.LookupHost
)

const (
	rdnsTimeout  = 2 * time.Second
	rdnsOKTTL    = time.Hour
	rdnsFailTTL  = 10 * time.Minute
	rdnsCacheCap = 10000
)

type rdnsResult struct {
	ok  bool
	exp time.Time
}

var (
	rdnsMu    sync.Mutex
	rdnsCache = map[string]rdnsResult{}
)

// rdnsVerified reports whether addr's PTR name ends in one of suffixes and
// that name resolves back to addr. The verdict is cached per IP and crawler,
// so a crawler (or a spoofer) pays the DNS round-trip once per TTL.
func rdnsVerified(addr netip.Addr, suffixes []string) bool {
	key := addr.String() + "|" + suffixes[0]
	now := time.Now()
	rdnsMu.Lock()
	r, hit := rdnsCache[key]
	rdnsMu.Unlock()
	if hit && now.Before(r.exp) {
		return r.ok
	}

	ok := forwardConfirmed(addr, suffixes)
	ttl := rdnsFailTTL
	if ok {
		ttl = rdnsOKTTL
	}
	rdnsMu.Lock()
	// ponytail: drops the whole cache when full; an LRU if verified
	// crawlers ever get re-checked often enough to matter.
	if len(rdnsCache) >= rdnsCacheCap {
		clear(rdnsCache)
	}
	rdnsCache[key] = rdnsResult{ok: ok, exp: now.Add(ttl)}
	rdnsMu.Unlock()
	return ok
}

func forwardConfirmed(addr netip.Addr, suffixes []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), rdnsTimeout)
	defer cancel()
	names, err := lookupAddr(ctx, addr.String())
	if err != nil {
		return false
	}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if !hasDomainSuffix(name, suffixes) {
			continue
		}
		ips, err := lookupHost(ctx, name)
		if err != nil {
			continue
		}
		for _, s := range ips {
			if a, err := netip.ParseAddr(s); err == nil && a.Unmap() == addr {
				return true
			}
		}
	}
	return false
}

// hasDomainSuffix matches whole labels, so "evilgooglebot.com" is not
// "googlebot.com".
func hasDomainSuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}
