// Package autoban turns repeat offenders and severe attackers into IP block
// rules that expire after the configured ban duration (issue #156). It watches the stream of logged requests (fed from the
// storage log worker via DB.SetAutobanFn), scores each blocked event per
// client IP over a sliding window, and when the configured threshold is
// crossed it writes a global block rule (visible on the IP Rules page),
// hot-reloads the in-memory blocklist, and emails the admin the reason.
//
// Scoring per event:
//
//	critical WAF rule (SQLi/RCE/XSS/LFI class)  5 points
//	any other WAF rule block                    2 points
//	rate limited                                1 point
//	bot-challenge redirect (never solved)       1 point
//	honeypot path hit (issue #130)              the whole threshold
//	bad backend status, opt-in (issue #193)     configured, default 1
//
// Challenge redirects are logged with Blocked=false (a challenge is not a
// deny), but a client that keeps hitting the challenge wall without ever
// solving it is a scanner — without scoring those, a bot stuck at the
// challenge gate probes forever and is never banned. Clients that solve the
// challenge stop producing bot_challenge rows, so they accumulate nothing.
//
// Already-blocked traffic (ip_blocked*, geo_blocked*) never scores — banned
// IPs keep producing blocked log rows forever and must not re-trigger bans or
// emails. Private, loopback, and link-local addresses are never banned, and
// an existing admin rule for the IP (allow or block) always wins.
//
// Cross-site subresource requests (Sec-Fetch-Site: cross-site on anything
// but a top-level navigation) never score either: a third-party page can
// make a visitor's browser fetch payload URLs from a protected site through
// <img>/<iframe>/fetch, and that must not get the visitor banned.
//
// Bad-status scoring catches scanners whose probes trip no rule: a run of
// 404s/403s from the backend. Trusted IPs, open paths and verified crawlers
// (RequestLog.Exempt) and missing static assets never score.
//
// IPv6 clients are scored and banned by /64 (ratelimit.ClientKey, issue
// #131): the ban rule is the /64 CIDR, so rotating addresses inside it
// neither resets the score nor escapes the ban.
package autoban

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"palisade/internal/security/ratelimit"
	"palisade/internal/security/waf"
	"palisade/internal/storage"
)

// Points per event class. The default threshold (10) means ~2 critical WAF
// hits, 4 generic WAF hits, 5 breached-password logins, or 10 rate-limited or
// challenged requests inside the window.
const (
	ptsCritical    = 5
	ptsWAF         = 2
	ptsRateLimited = 1
	ptsChallenged  = 1
	ptsLeaked      = 2
)

// store is the slice of *storage.DB the banner needs; an interface so tests
// can run without a real database.
type store interface {
	GetAutobanConfig() (storage.AutobanConfig, error)
	GetIPRuleType(appName, ip string) (string, error)
	AddIPRuleWithNote(appName, ip, ruleType, note string) error
	ExpireAutobans(cutoff time.Time) (int64, error)
}

type event struct {
	t   time.Time
	pts int
	// event class for the ban-reason breakdown
	critical, waf, rl, chal, hp, leaked bool
	status                              int // bad backend status, 0 otherwise
}

// Banner accumulates blocked-event scores per IP and issues bans.
type Banner struct {
	db     store
	reload func()                  // swaps the in-memory blocklist after a ban
	notify func(ip, reason string) // emails the ban alert (may be slow — runs async)

	mu     sync.Mutex
	cfg    storage.AutobanConfig
	hist   map[string][]event
	banned map[string]time.Time // recently banned here — suppress duplicates

	stop  chan struct{}
	once  sync.Once
	now   func() time.Time // injectable for tests
	spawn func(func())     // go func() in production; synchronous in tests
}

// New reads the current config from the DB and starts the janitor goroutine
// that keeps the per-IP history bounded. reload is called after every ban;
// notify is called asynchronously with the banned IP and the reason.
func New(db *storage.DB, reload func(), notify func(ip, reason string)) *Banner {
	b := &Banner{
		db:     db,
		reload: reload,
		notify: notify,
		hist:   make(map[string][]event),
		banned: make(map[string]time.Time),
		stop:   make(chan struct{}),
		now:    time.Now,
		spawn:  func(fn func()) { go fn() },
	}
	b.ReloadConfig()
	go b.janitor()
	return b
}

// Stop shuts down the janitor goroutine.
func (b *Banner) Stop() { b.once.Do(func() { close(b.stop) }) }

// ReloadConfig re-reads the autoban settings from the DB. Called by the UI
// save handler so changes apply without a restart.
func (b *Banner) ReloadConfig() {
	cfg, err := b.db.GetAutobanConfig()
	if err != nil {
		log.Printf("autoban: read config: %v", err)
		return
	}
	b.mu.Lock()
	b.cfg = cfg
	b.mu.Unlock()
}

// Score returns ip's current unexpired point total (0 if it has none),
// without mutating history — safe to call concurrently from other
// subsystems (e.g. the threatscore package folds this into a composite
// per-IP score). Deliberately does not reuse pruneEvents: that helper
// compacts its slice in place via evs[:0], which would corrupt b.hist[ip]'s
// backing array if called here without reassigning the result back.
func (b *Banner) Score(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-time.Duration(b.cfg.WindowMinutes) * time.Minute)
	score := 0
	for _, ev := range b.hist[ratelimit.ClientKey(ip)] {
		if ev.t.After(cutoff) {
			score += ev.pts
		}
	}
	return score
}

// Record scores one logged request. It runs on the storage log worker
// goroutine, so the fast path is in-memory only; the ban itself (DB write,
// blocklist reload, email) happens on a spawned goroutine.
func (b *Banner) Record(e storage.RequestLog) {
	if e.RealIP == "" {
		return
	}
	// Challenge redirects are Blocked=false by design but still score: a
	// client repeatedly bounced to the challenge without ever solving it is
	// a scanner, not a browser. Prefix match — issue #16's adaptive
	// enforcement can also trigger a challenge, logged as
	// "bot_challenge:adaptive", which must score exactly the same way.
	challenged := !e.Blocked && strings.HasPrefix(e.Action, "bot_challenge")
	// A honeypot hit is logged unblocked too (the backend answered 404),
	// and nothing legitimate asks for those paths, so it bans outright.
	honeypot := e.Action == "honeypot"
	// A breached password on a login path (issue #188) scores whether it was
	// blocked or only logged: repeated hits from one client are a stuffing run.
	leaked := strings.HasPrefix(e.Action, "leaked_password")
	// A backend error status on a request Palisade let through (issue #193);
	// whether the code counts is decided under the lock from the config.
	badStatus := !e.Blocked && !e.Exempt && e.Action == "" && e.Status >= 400 && !staticAsset(e.Path)
	if !e.Blocked && !challenged && !honeypot && !leaked && !badStatus {
		return
	}
	// Never score traffic that is already blocked by an IP rule or geo rule:
	// re-banning adds nothing, and banned IPs log blocked rows forever.
	if strings.HasPrefix(e.Action, "ip_blocked") || strings.HasPrefix(e.Action, "geo_blocked") {
		return
	}
	if crossSiteSubresource(e.HeadersJSON) {
		return
	}

	ev := event{t: e.Timestamp}
	switch {
	case honeypot:
		ev.hp = true // pts set to the threshold below, under the lock
	case challenged:
		ev.pts, ev.chal = ptsChallenged, true
	case leaked:
		ev.pts, ev.leaked = ptsLeaked, true
	case e.RuleID > 0 && criticalRule(e.RuleID):
		ev.pts, ev.critical = ptsCritical, true
	case e.RuleID > 0:
		ev.pts, ev.waf = ptsWAF, true
	case strings.HasPrefix(e.Action, "rate_limited"):
		ev.pts, ev.rl = ptsRateLimited, true
	case badStatus:
		ev.status = e.Status // pts set from the config below, under the lock
	default:
		return
	}
	if ev.t.IsZero() {
		ev.t = b.now()
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.cfg.Enabled {
		return
	}
	if ev.hp {
		ev.pts = b.cfg.Threshold
	}
	if ev.status != 0 {
		if !b.cfg.BadStatusEnabled || !slices.Contains(b.cfg.BadStatusCodes, ev.status) {
			return
		}
		ev.pts = b.cfg.BadStatusPoints
	}
	if !bannable(e.RealIP) {
		return
	}
	key := ratelimit.ClientKey(e.RealIP)
	if _, dup := b.banned[key]; dup {
		return
	}

	window := time.Duration(b.cfg.WindowMinutes) * time.Minute
	cutoff := b.now().Add(-window)
	recent := append(pruneEvents(b.hist[key], cutoff), ev)
	b.hist[key] = recent

	score := 0
	for _, r := range recent {
		score += r.pts
	}
	if score < b.cfg.Threshold {
		return
	}

	// Threshold crossed: mark synchronously so queued events for the same IP
	// can't trigger a second ban, then do the slow work off this goroutine.
	b.banned[key] = b.now()
	delete(b.hist, key)
	reason := banReason(recent, b.cfg.WindowMinutes)
	b.spawn(func() { b.ban(key, reason) })
}

// ban writes the block rule, reloads the blocklist, and sends the alert.
func (b *Banner) ban(ip, reason string) {
	// An existing rule for this IP — an admin allow (or an earlier ban that
	// survived a restart) — always wins over the automatic ban.
	if rt, err := b.db.GetIPRuleType("", ip); err != nil {
		log.Printf("autoban: rule lookup for %s: %v", ip, err)
		return
	} else if rt != "" {
		return
	}

	note := "Auto-banned — " + reason
	if err := b.db.AddIPRuleWithNote("", ip, "block", note); err != nil {
		log.Printf("autoban: ban %s: %v", ip, err)
		return
	}
	if b.reload != nil {
		b.reload()
	}
	log.Printf("autoban: banned %s (%s)", ip, reason)
	if b.notify != nil {
		b.notify(ip, reason)
	}
}

// janitor prunes stale history and old dedupe markers once a minute so the
// maps stay bounded regardless of how many IPs send blocked traffic.
func (b *Banner) janitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.sweep()
			b.expire()
		case <-b.stop:
			return
		}
	}
}

// sweep drops history outside the scoring window and stale dedupe markers.
func (b *Banner) sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-time.Duration(b.cfg.WindowMinutes) * time.Minute)
	for ip, evs := range b.hist {
		if evs = pruneEvents(evs, cutoff); len(evs) == 0 {
			delete(b.hist, ip)
		} else {
			b.hist[ip] = evs
		}
	}
	// Dedupe markers only bridge the gap until the blocklist reload
	// makes the IP log as ip_blocked; an hour is more than enough.
	for ip, t := range b.banned {
		if b.now().Sub(t) > time.Hour {
			delete(b.banned, ip)
		}
	}
}

// expire removes bans older than the configured duration and reloads the
// blocklist when any went. The DB call runs outside the lock.
func (b *Banner) expire() {
	b.mu.Lock()
	hours := b.cfg.BanHours
	b.mu.Unlock()
	if hours <= 0 {
		return
	}
	n, err := b.db.ExpireAutobans(b.now().Add(-time.Duration(hours) * time.Hour))
	if err != nil {
		log.Printf("autoban: expire bans: %v", err)
		return
	}
	if n > 0 {
		log.Printf("autoban: %d ban(s) expired", n)
		if b.reload != nil {
			b.reload()
		}
	}
}

// crossSiteSubresource reports whether a logged request was made by a
// browser on behalf of another site's page rather than as a top-level
// navigation. Sec-Fetch-* are forbidden header names a page script cannot
// set, so a browser's values are honest.
// ponytail: a non-browser client can send the same headers to avoid scoring;
// it still gets blocked per request, it just isn't banned.
func crossSiteSubresource(headersJSON string) bool {
	if !strings.Contains(headersJSON, "Sec-Fetch-Site") {
		return false
	}
	var h map[string]string
	if json.Unmarshal([]byte(headersJSON), &h) != nil {
		return false
	}
	return h["Sec-Fetch-Site"] == "cross-site" &&
		(h["Sec-Fetch-Mode"] != "navigate" || h["Sec-Fetch-Dest"] != "document")
}

func pruneEvents(evs []event, cutoff time.Time) []event {
	kept := evs[:0]
	for _, ev := range evs {
		if ev.t.After(cutoff) {
			kept = append(kept, ev)
		}
	}
	return kept
}

// criticalRule reports whether a CRS rule ID belongs to an attack-detection
// class severe enough to fast-track a ban: 930–934 (LFI/RFI/RCE/PHP/Node
// injection) and 941–944 (XSS, SQLi, session fixation, Java injection), plus
// virtual patches (issue #189): an exploit for a known CVE is never a typo.
func criticalRule(id int) bool {
	return (id >= 930000 && id < 935000) || (id >= 941000 && id < 945000) ||
		(id >= waf.VPatchIDMin && id <= waf.VPatchIDMax)
}

// staticExts are asset types whose 404s are broken pages, not probes: a
// missing favicon or source map must never get a visitor banned.
var staticExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true, ".ico": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".webp": true, ".avif": true, ".woff": true, ".woff2": true, ".ttf": true,
}

func staticAsset(p string) bool {
	return staticExts[strings.ToLower(path.Ext(p))]
}

// bannable rejects addresses that must never be auto-banned: unparseable,
// loopback, RFC1918/ULA private, link-local, and unspecified addresses —
// banning those could lock out the LAN, health checks, or the admin.
func bannable(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !parsed.IsLoopback() && !parsed.IsPrivate() && !parsed.IsLinkLocalUnicast() &&
		!parsed.IsLinkLocalMulticast() && !parsed.IsUnspecified()
}

// banReason summarises what earned the ban, e.g.
// "12 flagged requests in 10 min (2 critical WAF hits, 1 WAF hit, 3 rate-limited)".
func banReason(evs []event, windowMin int) string {
	var hp, crit, waf, rl, chal, leaked, bad int
	var codes []int
	for _, ev := range evs {
		switch {
		case ev.hp:
			hp++
		case ev.critical:
			crit++
		case ev.waf:
			waf++
		case ev.rl:
			rl++
		case ev.chal:
			chal++
		case ev.leaked:
			leaked++
		case ev.status != 0:
			bad++
			if !slices.Contains(codes, ev.status) {
				codes = append(codes, ev.status)
			}
		}
	}
	var parts []string
	if hp > 0 {
		parts = append(parts, fmt.Sprintf("%d honeypot %s", hp, plural(hp, "hit")))
	}
	if crit > 0 {
		parts = append(parts, fmt.Sprintf("%d critical WAF %s", crit, plural(crit, "hit")))
	}
	if waf > 0 {
		parts = append(parts, fmt.Sprintf("%d WAF %s", waf, plural(waf, "hit")))
	}
	if leaked > 0 {
		parts = append(parts, fmt.Sprintf("%d breached %s", leaked, plural(leaked, "password")))
	}
	if rl > 0 {
		parts = append(parts, fmt.Sprintf("%d rate-limited", rl))
	}
	if chal > 0 {
		parts = append(parts, fmt.Sprintf("%d unsolved bot %s", chal, plural(chal, "challenge")))
	}
	if bad > 0 {
		parts = append(parts, fmt.Sprintf("%d bad %s (%s)", bad, plural(bad, "response"), storage.FormatStatusCodes(codes)))
	}
	return fmt.Sprintf("%d flagged requests in %d min (%s)",
		len(evs), windowMin, strings.Join(parts, ", "))
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
