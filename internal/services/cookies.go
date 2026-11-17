package services

import (
	"net/http"
	"slices"
	"strings"
)

// hardenCookies adds HttpOnly, SameSite=Lax and (over HTTPS) Secure
// to the backend's Set-Cookie headers that lack them (issue #281). Cookies
// named in exempt are left alone, e.g. one the page's JavaScript must read.
func hardenCookies(resp *http.Response, exempt []string) {
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	// Behind a TLS-terminating Ingress the connection is plain HTTP and the
	// Ingress says https in X-Forwarded-Proto; a spoofed header only adds
	// Secure, which can't weaken anything.
	tls := resp.Request != nil && (resp.Request.TLS != nil ||
		strings.EqualFold(resp.Request.Header.Get("X-Forwarded-Proto"), "https"))
	out := make([]string, len(cookies))
	for i, c := range cookies {
		out[i] = hardenCookie(c, exempt, tls)
	}
	resp.Header["Set-Cookie"] = out
}

func hardenCookie(c string, exempt []string, tls bool) string {
	parts := strings.Split(c, ";")
	name, _, _ := strings.Cut(parts[0], "=")
	if slices.Contains(exempt, strings.TrimSpace(name)) {
		return c
	}
	var secure, httpOnly, sameSite bool
	for _, p := range parts[1:] {
		attr, _, _ := strings.Cut(p, "=")
		switch strings.ToLower(strings.TrimSpace(attr)) {
		case "secure":
			secure = true
		case "httponly":
			httpOnly = true
		case "samesite":
			sameSite = true
		}
	}
	c = strings.TrimRight(c, "; ")
	if tls && !secure {
		c += "; Secure"
	}
	if !httpOnly {
		c += "; HttpOnly"
	}
	if !sameSite {
		c += "; SameSite=Lax"
	}
	return c
}
