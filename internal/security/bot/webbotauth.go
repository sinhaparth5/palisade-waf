package bot

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Web Bot Auth (issue #233, draft-ietf-webbotauth-httpsig-protocol): the
// agent signs the request (RFC 9421, Ed25519) and names its key directory in
// Signature-Agent (the member the signature covers). That header is client-controlled, so a directory is only
// fetched when its origin is listed on the crawler the UA claims (sigAgents);
// any other origin is unverified, never fetched. Keys are fetched in the
// background: a request whose directory isn't cached yet is unverified.

const (
	wbaTag        = "web-bot-auth"
	wbaDirPath    = "/.well-known/http-message-signatures-directory"
	wbaOKTTL      = time.Hour
	wbaFailTTL    = 5 * time.Minute // draft Appendix C.5 caps negative caching at 5m
	wbaSkew       = time.Minute
	wbaMaxDirSize = 64 << 10
	wbaMaxKeys    = 32
)

// wbaClient never follows redirects (the draft forbids it) and gives up fast.
var wbaClient = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type wbaDir struct {
	keys     map[string]ed25519.PublicKey // by JWK thumbprint (keyid)
	exp      time.Time
	fetching bool
}

var (
	wbaMu    sync.Mutex
	wbaCache = map[string]*wbaDir{} // by origin; bounded by the sigAgents allowlist
)

// parseSigAgent validates an operator-supplied signature agent origin.
func parseSigAgent(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("signature agent %q: want https://host", s)
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// webBotAuthVerified reports whether r carries a valid web-bot-auth signature
// from one of c's signature agents with a key that is already cached.
func webBotAuthVerified(r *http.Request, c *crawler) bool {
	if len(c.sigAgents) == 0 || r.Header.Get("Signature") == "" {
		return false
	}
	inputs, err := parseSFDict(strings.Join(r.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return false
	}
	sigs, err := parseSFDict(strings.Join(r.Header.Values("Signature"), ", "))
	if err != nil {
		return false
	}
	agents := parseSigAgentHeader(strings.Join(r.Header.Values("Signature-Agent"), ", "))
	now := time.Now()
	for label, in := range inputs {
		if in.items == nil || in.params["tag"] != wbaTag {
			continue
		}
		created, err1 := strconv.ParseInt(in.params["created"], 10, 64)
		expires, err2 := strconv.ParseInt(in.params["expires"], 10, 64)
		if err1 != nil || err2 != nil || now.Add(wbaSkew).Before(time.Unix(created, 0)) || !now.Before(time.Unix(expires, 0)) {
			continue
		}
		if a := in.params["alg"]; a != "" && a != "ed25519" {
			continue
		}
		sig, ok := sigs[label]
		if !ok || sig.items != nil || !sig.bytes {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(sig.value)
		if err != nil {
			continue
		}
		base, agentKey, ok := signatureBase(r, in, agents)
		if !ok {
			continue
		}
		agent := agents[agentKey]
		if agent.items != nil || (agent.params["type"] != "" && agent.params["type"] != "directory") {
			continue
		}
		origin, err := parseSigAgent(agent.value)
		if err != nil || !slices.Contains(c.sigAgents, origin) {
			continue
		}
		key := wbaKey(origin, in.params["keyid"])
		if key != nil && ed25519.Verify(key, []byte(base), raw) {
			return true
		}
	}
	return false
}

// signatureBase builds the RFC 9421 §2.5 signature base and returns the
// Signature-Agent member the signature covers, which names its directory.
// It requires @authority or @target-uri and exactly one signature-agent
// member to be covered (draft §4.2); any component it can't reproduce fails.
func signatureBase(r *http.Request, in sfMember, agents map[string]sfMember) (string, string, bool) {
	var b strings.Builder
	authority, agentKey, agentCount := false, "", 0
	for _, it := range in.items {
		var v string
		switch it.value {
		case "@authority":
			authority = true
			v = strings.TrimSuffix(strings.ToLower(r.Host), ":443")
		case "@target-uri":
			authority = true
			scheme := "https"
			if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "http" {
				scheme = "http"
			}
			v = scheme + "://" + strings.ToLower(r.Host) + r.URL.RequestURI()
		case "@method":
			v = r.Method
		case "@path":
			v = r.URL.EscapedPath()
			if v == "" {
				v = "/"
			}
		case "@query":
			v = "?" + r.URL.RawQuery
		case "signature-agent":
			k := it.params["key"] // "" is the legacy bare-string header
			m, ok := agents[k]
			if !ok {
				return "", "", false
			}
			agentKey, agentCount = k, agentCount+1
			v = m.raw
		default:
			if strings.HasPrefix(it.value, "@") || len(it.params) > 0 {
				return "", "", false
			}
			vals := r.Header.Values(it.value)
			if len(vals) == 0 {
				return "", "", false
			}
			for i := range vals {
				vals[i] = strings.TrimSpace(vals[i])
			}
			v = strings.Join(vals, ", ")
		}
		b.WriteString(it.raw + ": " + v + "\n")
	}
	if !authority || agentCount != 1 {
		return "", "", false
	}
	b.WriteString(`"@signature-params": ` + in.raw)
	return b.String(), agentKey, true
}

// wbaKey returns the cached key for origin+keyid, or nil. A missing or
// stale directory is fetched in the background, never on the request path.
func wbaKey(origin, keyid string) ed25519.PublicKey {
	now := time.Now()
	wbaMu.Lock()
	defer wbaMu.Unlock()
	d := wbaCache[origin]
	if d == nil {
		d = &wbaDir{}
		wbaCache[origin] = d
	}
	if now.After(d.exp) && !d.fetching {
		d.fetching = true
		go refreshDir(origin, d)
	}
	if now.After(d.exp) && d.keys == nil {
		return nil
	}
	return d.keys[keyid] // a stale directory still serves while it refreshes
}

func refreshDir(origin string, d *wbaDir) {
	keys, err := fetchDir(origin)
	wbaMu.Lock()
	defer wbaMu.Unlock()
	d.fetching = false
	if err != nil {
		d.keys, d.exp = nil, time.Now().Add(wbaFailTTL)
		return
	}
	d.keys, d.exp = keys, time.Now().Add(wbaOKTTL)
}

func fetchDir(origin string) (map[string]ed25519.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wbaClient.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+wbaDirPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json")
	resp, err := wbaClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory %s: status %d", origin, resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Crv, X string
			Exp         int64
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, wbaMaxDirSize)).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	now := time.Now().Unix()
	for _, k := range set.Keys {
		if len(keys) >= wbaMaxKeys {
			break
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Exp != 0 && k.Exp < now) {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		keys[jwkThumbprint(k.X)] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("directory " + origin + ": no Ed25519 keys")
	}
	return keys, nil
}

// jwkThumbprint is the RFC 8037 A.3 SHA-256 thumbprint of an Ed25519 JWK.
func jwkThumbprint(x string) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// parseSigAgentHeader reads Signature-Agent as a dictionary, or a
// deprecated bare string (still sent by some agents) under key "".
func parseSigAgentHeader(h string) map[string]sfMember {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, `"`) {
		p := &sfParser{s: h}
		v, _, ok := p.bare()
		params, pok := p.params()
		if !ok || !pok || p.i != len(h) {
			return nil
		}
		return map[string]sfMember{"": {raw: h, value: v, params: params}}
	}
	m, _ := parseSFDict(h)
	return m
}

// Minimal RFC 9651 dictionary parsing: just what Signature, Signature-Input
// and Signature-Agent use. raw keeps each member's and item's exact text,
// which the signature base reuses as its serialization.

type sfItem struct {
	raw, value string
	params     map[string]string
}

type sfMember struct {
	raw, value string // value of a bare item (string, token, integer or byte sequence)
	bytes      bool   // value was a :byte sequence:
	items      []sfItem
	params     map[string]string
}

var errSF = errors.New("malformed structured field")

func parseSFDict(s string) (map[string]sfMember, error) {
	out := map[string]sfMember{}
	p := &sfParser{s: s}
	p.ws()
	for p.i < len(p.s) {
		key := p.key()
		if key == "" || p.next() != '=' {
			return nil, errSF
		}
		p.i++
		start := p.i
		var m sfMember
		if p.next() == '(' {
			p.i++
			m.items = []sfItem{}
			for {
				p.sp()
				if p.next() == ')' {
					p.i++
					break
				}
				is := p.i
				v, _, ok := p.bare()
				if !ok {
					return nil, errSF
				}
				params, ok := p.params()
				if !ok {
					return nil, errSF
				}
				m.items = append(m.items, sfItem{raw: p.s[is:p.i], value: v, params: params})
				if c := p.next(); c != ' ' && c != ')' {
					return nil, errSF
				}
			}
		} else {
			v, bytes, ok := p.bare()
			if !ok {
				return nil, errSF
			}
			m.value, m.bytes = v, bytes
		}
		var ok bool
		if m.params, ok = p.params(); !ok {
			return nil, errSF
		}
		m.raw = p.s[start:p.i]
		out[key] = m
		p.ws()
		if p.i == len(p.s) {
			break
		}
		if p.next() != ',' {
			return nil, errSF
		}
		p.i++
		p.ws()
	}
	return out, nil
}

type sfParser struct {
	s string
	i int
}

func (p *sfParser) next() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *sfParser) ws() {
	for p.next() == ' ' || p.next() == '\t' {
		p.i++
	}
}

func (p *sfParser) sp() {
	for p.next() == ' ' {
		p.i++
	}
}

func (p *sfParser) key() string {
	start := p.i
	for c := p.next(); c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '*'; c = p.next() {
		p.i++
	}
	return p.s[start:p.i]
}

// bare parses a string, byte sequence, token or integer.
func (p *sfParser) bare() (string, bool, bool) {
	switch c := p.next(); {
	case c == '"':
		p.i++
		var b strings.Builder
		for p.i < len(p.s) {
			c := p.s[p.i]
			p.i++
			switch c {
			case '\\':
				if p.i == len(p.s) {
					return "", false, false
				}
				b.WriteByte(p.s[p.i])
				p.i++
			case '"':
				return b.String(), false, true
			default:
				b.WriteByte(c)
			}
		}
		return "", false, false
	case c == ':':
		end := strings.IndexByte(p.s[p.i+1:], ':')
		if end < 0 {
			return "", false, false
		}
		v := p.s[p.i+1 : p.i+1+end]
		p.i += end + 2
		return v, true, true
	case c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '*':
		start := p.i
		for c := p.next(); c > ' ' && c < 0x7f && !strings.ContainsRune(`"(),;=\`, rune(c)); c = p.next() {
			p.i++
		}
		return p.s[start:p.i], false, true
	}
	return "", false, false
}

func (p *sfParser) params() (map[string]string, bool) {
	var out map[string]string
	for p.next() == ';' {
		p.i++
		p.sp()
		k := p.key()
		if k == "" {
			return nil, false
		}
		v := "1" // boolean true
		if p.next() == '=' {
			p.i++
			var ok bool
			if v, _, ok = p.bare(); !ok {
				return nil, false
			}
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out, true
}
