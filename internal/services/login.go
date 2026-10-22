package services

import (
	"path"
	"strings"

	"palisade/internal/security/ratelimit"
	"palisade/internal/storage"
)

// Login protection preset (issue #132): submissions to a service's login
// paths are limited to LoginBurst at once, then one every 12s, per client
// (IPv6 per /64). Fixed rather than configurable: the point of a preset.
const (
	LoginRate  = 5.0 / 60 // tokens per second
	LoginBurst = 5

	// loginLimiterSuffix keys a service's login limiter in Registry.limiters,
	// so Reload's existing swap-and-stop covers it.
	loginLimiterSuffix = "\x00login"
)

// IsLoginPath reports whether p (the client-facing path) is covered by one of
// s's login paths (issue #159). Paths are compared cleaned, case-insensitively,
// ignoring a trailing slash and ";param" path parameters, so "/Login/",
// "//login" or "/login;jsessionid=x" can't step around "/login". A login path
// also covers what a backend may route to the same handler on a segment
// boundary: sub-paths ("/login/submit") and the path mounted deeper
// ("/api/login"), but never "/login2" or "/mylogin".
func IsLoginPath(s *storage.Service, p string) bool {
	if s == nil || len(s.LoginPaths) == 0 {
		return false
	}
	p = strings.ToLower(path.Clean("/" + stripPathParams(p)))
	for _, l := range s.LoginPaths {
		l = strings.ToLower(path.Clean("/" + l))
		if l == "/" {
			if p == "/" {
				return true
			}
			continue
		}
		if p == l || strings.HasPrefix(p, l+"/") || strings.HasSuffix(p, l) {
			return true
		}
	}
	return false
}

// stripPathParams drops the ";param" part of every segment, which servlet
// containers and some frameworks ignore when routing.
func stripPathParams(p string) string {
	if !strings.Contains(p, ";") {
		return p
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i], _, _ = strings.Cut(seg, ";")
	}
	return strings.Join(segs, "/")
}

// AllowLogin checks the service's login limiter. Allowed when the service
// has no login paths.
func (r *Registry) AllowLogin(name, key string) ratelimit.Result {
	return r.AllowService(name+loginLimiterSuffix, key)
}
