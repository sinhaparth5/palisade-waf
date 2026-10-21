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

// IsLoginPath reports whether p (the client-facing path) is one of s's login
// paths: compared cleaned, case-insensitively and ignoring a trailing slash,
// so "/Login/" or "//login" can't step around "/login".
func IsLoginPath(s *storage.Service, p string) bool {
	if s == nil || len(s.LoginPaths) == 0 {
		return false
	}
	p = path.Clean("/" + p)
	for _, l := range s.LoginPaths {
		if strings.EqualFold(p, path.Clean(l)) {
			return true
		}
	}
	return false
}

// AllowLogin checks the service's login limiter. Allowed when the service
// has no login paths.
func (r *Registry) AllowLogin(name, key string) ratelimit.Result {
	return r.AllowService(name+loginLimiterSuffix, key)
}
