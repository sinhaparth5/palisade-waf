package ui

import (
	"net/http"
	"sync"
	"time"

	"palisade/internal/proxy"

	"github.com/labstack/echo/v4"
)

const (
	// maxLoginFailures consecutive failures within loginWindow lock the IP out.
	maxLoginFailures = 5
	loginWindow      = 15 * time.Minute
	loginLockout     = 15 * time.Minute
	// loginLimiterCap bounds the tracking map so an attacker cycling source
	// IPs can't grow it without limit; stale entries are swept past this size.
	loginLimiterCap = 4096
)

// loginLimiter throttles credential guessing per client IP. In-process state
// is enough here: there is a single admin account and a single WAF process,
// and bcrypt already caps the verify rate. This exists to turn "slow" into
// "stopped" and to give lockouts a clear audit trail.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempts
	now     func() time.Time // injectable for tests
}

type loginAttempts struct {
	failures    int
	firstFail   time.Time
	lockedUntil time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginAttempts), now: time.Now}
}

// blocked reports whether ip is currently locked out and for how much longer.
func (l *loginLimiter) blocked(ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		return 0, false
	}
	if wait := e.lockedUntil.Sub(l.now()); wait > 0 {
		return wait, true
	}
	return 0, false
}

// fail records a failed attempt and returns true when it triggers a lockout.
func (l *loginLimiter) fail(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	if len(l.entries) >= loginLimiterCap {
		l.sweep(now)
	}

	e, ok := l.entries[ip]
	if !ok || now.Sub(e.firstFail) > loginWindow {
		l.entries[ip] = &loginAttempts{failures: 1, firstFail: now}
		return false
	}
	e.failures++
	if e.failures >= maxLoginFailures {
		e.lockedUntil = now.Add(loginLockout)
		return true
	}
	return false
}

// success clears the failure history for ip after a valid login.
func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// sweep drops entries whose window and lockout have both expired.
// Caller must hold l.mu.
func (l *loginLimiter) sweep(now time.Time) {
	for ip, e := range l.entries {
		if now.Sub(e.firstFail) > loginWindow && now.After(e.lockedUntil) {
			delete(l.entries, ip)
		}
	}
}

// clientIP resolves the real client IP for login throttling, through the
// same proxy.ClientIP the request pipeline uses: forwarding headers count
// only from a configured trusted proxy (issue #154). Echo's c.RealIP()
// trusts X-Forwarded-For unconditionally, which would let an attacker rotate
// fake IPs to dodge the lockout.
func (h *Handler) clientIP(r *http.Request) string {
	return proxy.ClientIP(r, h.trustedNets)
}

// secureCookie reports whether session cookies should carry the Secure flag.
// True when the request arrived over TLS directly or, behind a TLS-terminating
// proxy, via X-Forwarded-Proto (spoofing that header can only *add* the flag,
// which locks the spoofer out of plain HTTP, never the reverse).
func secureCookie(c echo.Context) bool {
	return c.Scheme() == "https"
}
