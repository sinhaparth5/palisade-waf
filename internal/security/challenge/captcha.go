package challenge

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// CAPTCHA fallback (issue #133): when the PoW can't run — crypto.subtle is
// missing outside a secure context (plain HTTP), or a locked-down browser
// blocks it — the challenge page offers a Turnstile or hCaptcha widget
// instead, and ServeVerify checks its token with the provider before issuing
// the same bypass cookie. Both providers share the render/siteverify shape,
// so they differ only in these URLs.

// captchaVerifyURLs are the providers' server-side token checks. A var so
// tests can point them at an httptest server.
var captchaVerifyURLs = map[string]string{
	"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	"hcaptcha":  "https://api.hcaptcha.com/siteverify",
}

// captchaScripts are the widget loaders. The page adds onload/render params,
// and the global each defines is named after the provider (window.turnstile,
// window.hcaptcha).
var captchaScripts = map[string]string{
	"turnstile": "https://challenges.cloudflare.com/turnstile/v0/api.js",
	"hcaptcha":  "https://js.hcaptcha.com/1/api.js",
}

var captchaClient = &http.Client{Timeout: 5 * time.Second}

// ValidCaptchaProvider reports whether p names a supported provider.
func ValidCaptchaProvider(p string) bool {
	_, ok := captchaVerifyURLs[p]
	return ok
}

// WithCaptcha enables the CAPTCHA fallback and returns c. An unknown provider
// or a missing key leaves it off. Call before the Challenger is shared.
func (c *Challenger) WithCaptcha(provider, siteKey, secret string) *Challenger {
	if c != nil && ValidCaptchaProvider(provider) && siteKey != "" && secret != "" {
		c.captchaProvider, c.captchaSiteKey, c.captchaSecret = provider, siteKey, secret
	}
	return c
}

// verifyCaptcha asks the provider whether token is a fresh, valid solve.
// Providers redeem a token once, so a replay fails here too.
func (c *Challenger) verifyCaptcha(token string) bool {
	resp, err := captchaClient.PostForm(captchaVerifyURLs[c.captchaProvider],
		url.Values{"secret": {c.captchaSecret}, "response": {token}})
	if err != nil {
		log.Printf("challenge: %s siteverify: %v", c.captchaProvider, err)
		return false
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		log.Printf("challenge: %s siteverify: %v", c.captchaProvider, err)
		return false
	}
	return out.Success
}
