package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"palisade/internal/security/egress"
)

// Google's own services (Tag Manager, PageSpeed Insights, Site Verification,
// Translate, ...) fetch pages from Google IPs, often with a plain Chrome UA
// that names no crawler, and can't run the challenge. Google publishes every
// range it owns (goog.json) and the ones it rents to Google Cloud customers
// (cloud.json); only goog minus cloud is Google itself, since anyone can
// rent a Cloud VM. Opt-in with --google-fetchers.
const (
	googURL         = "https://www.gstatic.com/ipranges/goog.json"
	googCloudURL    = "https://www.gstatic.com/ipranges/cloud.json"
	googleRefresh   = 24 * time.Hour
	googleRetry     = 10 * time.Minute
	googleMaxBody   = 1 << 20
	googleMinRanges = 10 // a near-empty list is a broken fetch, not Google shrinking
)

type googleSet struct{ goog, cloud []netip.Prefix }

var googleRanges atomic.Pointer[googleSet]

// googleService reports whether ip is a Google-owned, non-Cloud address.
// Nil (feature off or not fetched yet) is false.
// ponytail: linear scan of ~150 + ~1150 prefixes, only for bodiless GETs from
// unverified clients; a prefix trie if it ever shows in a profile.
func googleService(ip string) bool {
	s := googleRanges.Load()
	if s == nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return containsAddr(s.goog, addr) && !containsAddr(s.cloud, addr)
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// RunGoogleRanges fetches Google's ranges now and every day until ctx ends,
// retrying sooner after a failure. A failed refresh keeps the last good set.
func RunGoogleRanges(ctx context.Context) {
	client := egress.Client(30 * time.Second)
	for {
		wait := googleRefresh
		if err := refreshGoogleRanges(ctx, client); err != nil {
			log.Printf("google ranges: %v", err)
			wait = googleRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func refreshGoogleRanges(ctx context.Context, client *http.Client) error {
	goog, err := fetchGoogleRanges(ctx, client, googURL)
	if err != nil {
		return err
	}
	cloud, err := fetchGoogleRanges(ctx, client, googCloudURL)
	if err != nil {
		return err
	}
	googleRanges.Store(&googleSet{goog: goog, cloud: cloud})
	return nil
}

func fetchGoogleRanges(ctx context.Context, client *http.Client, url string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, googleMaxBody))
	if err != nil {
		return nil, err
	}
	ps, err := parseGoogleRanges(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return ps, nil
}

// parseGoogleRanges reads the {"prefixes":[{"ipv4Prefix"|"ipv6Prefix":...}]}
// format of goog.json and cloud.json.
func parseGoogleRanges(body []byte) ([]netip.Prefix, error) {
	var doc struct {
		Prefixes []struct {
			V4 string `json:"ipv4Prefix"`
			V6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	ps := make([]netip.Prefix, 0, len(doc.Prefixes))
	for _, e := range doc.Prefixes {
		s := e.V4
		if s == "" {
			s = e.V6
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("bad prefix %q", s)
		}
		ps = append(ps, p.Masked())
	}
	if len(ps) < googleMinRanges {
		return nil, fmt.Errorf("only %d prefixes", len(ps))
	}
	return ps, nil
}
