package services

import (
	"path"
	"strings"
)

// SetHoneypots swaps in a new honeypot path list (issue #130). Reload calls
// it from the DB; the admin UI calls it directly after saving the list so a
// change doesn't rebuild every proxy.
func (r *Registry) SetHoneypots(paths []string) {
	lower := make([]string, len(paths))
	for i, p := range paths {
		lower[i] = strings.ToLower(p)
	}
	r.mu.Lock()
	r.honeypots = lower
	r.mu.Unlock()
}

// Honeypot reports whether p is a honeypot path: equal to an entry, or under
// one ending in "/" ("/.git/" covers "/.git/config"). Case-insensitive, and
// p is cleaned first so "//.env" or "/x/../.env" can't step around "/.env".
// Nil-receiver safe, like IsServiceHost.
func (r *Registry) Honeypot(p string) bool {
	if r == nil {
		return false
	}
	p = strings.ToLower(path.Clean("/" + p))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.honeypots {
		if p == e || (strings.HasSuffix(e, "/") && (strings.HasPrefix(p, e) || p+"/" == e)) {
			return true
		}
	}
	return false
}
