// Package csp collects Content-Security-Policy violation reports (issue
// #235) and keeps a per-service inventory of the script sources they name,
// so a new third-party script (a Magecart skimmer, a swapped CDN) raises an
// alert the first time a browser loads it.
package csp

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"palisade/internal/security/ratelimit"
	"palisade/internal/storage"
)

// ReportPath is where the injected policy sends its reports.
const ReportPath = "/_cz/csp-report"

const (
	maxBody = 64 << 10 // a reports+json batch can carry several reports
	maxLen  = 255      // origin column width
)

// MaxSources caps each service's inventory. Past it new sources are not
// recorded, and the alert fires once with InventoryFull as the source.
const MaxSources = 500

// InventoryFull is the alert source sent once per service (per process)
// when a new source arrives at a full inventory, so filling it with fake
// reports can't silence the next real one without anyone noticing (#311).
const InventoryFull = "(inventory full: new script sources are no longer recorded)"

// Header returns the report-only header value for a service's policy.
func Header(serviceID int, policy string) (csp, endpoints string) {
	u := ReportPath + "?s=" + strconv.Itoa(serviceID)
	return policy + "; report-uri " + u + "; report-to palisade-csp", `palisade-csp="` + u + `"`
}

// EnforcePolicy is the script-src an enforcing service sends as
// Content-Security-Policy (issue #283): the sources of the report-only
// policy's script-src ('self' when it has none) plus the approved inventory
// entries. Only script-src is taken, so other directives the admin wrote
// stay unenforced. Pass the result to Header for the report endpoints.
func EnforcePolicy(policy string, approved []string) string {
	srcs := []string{"'self'"}
	for _, d := range strings.Split(policy, ";") {
		if f := strings.Fields(d); len(f) > 0 && strings.EqualFold(f[0], "script-src") {
			srcs = f[1:]
			break
		}
	}
	for _, a := range approved {
		switch a {
		case "inline":
			a = "'unsafe-inline'"
		case "eval":
			a = "'unsafe-eval'"
		case "wasm-eval":
			a = "'wasm-unsafe-eval'"
		case "trusted-types-policy", "trusted-types-sink":
			continue // not script-src sources
		}
		if !slices.Contains(srcs, a) {
			srcs = append(srcs, a)
		}
	}
	return "script-src " + strings.Join(srcs, " ")
}

// Store is the part of storage.DB the collector uses.
type Store interface {
	AddCSPScript(id int, s storage.CSPScript) (bool, error)
	ListCSPScripts() (map[int][]storage.CSPScript, error)
}

// Collector serves ReportPath.
type Collector struct {
	store    Store
	service  func(id int) (name string, ok bool) // services with a policy on
	clientIP func(*http.Request) string
	alert    func(service, source, page string) // called once per new source, on its own goroutine
	limit    *ratelimit.Limiter
	newSrc   *ratelimit.Limiter // new sources per service + client key (#311)

	mu    sync.Mutex
	known map[int]map[string]bool // loaded from the store on a service's first report
	full  map[int]bool            // InventoryFull already sent
}

// New builds a Collector. alert may be nil.
func New(store Store, service func(int) (string, bool), clientIP func(*http.Request) string, alert func(service, source, page string)) *Collector {
	return &Collector{store: store, service: service, clientIP: clientIP, alert: alert,
		limit: ratelimit.NewWithParams(2, 40), known: map[int]map[string]bool{}, full: map[int]bool{},
		// 10 new sources per client per service, then one an hour: enough
		// for a first page load to seed the inventory, while filling all
		// MaxSources takes 50 client keys instead of one report batch.
		newSrc: ratelimit.NewWithParams(10.0/3600, 10)}
}

// ServeHTTP always answers 204 to a POST: a browser does nothing with the
// status, and a scanner learns nothing from it.
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	id, err := strconv.Atoi(r.URL.Query().Get("s"))
	if err != nil {
		return
	}
	name, ok := c.service(id)
	key := ratelimit.ClientKey(c.clientIP(r))
	if !ok || !c.limit.Allow(key).Allowed {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return
	}
	for _, v := range parse(body) {
		c.record(id, name, key, v)
	}
}

type violation struct{ source, page string }

// parse reads both report formats: report-uri's application/csp-report
// object and the Reporting API's application/reports+json array. Only
// script directives count; anything unparsable is dropped.
func parse(body []byte) []violation {
	type uriReport struct {
		Document  string `json:"document-uri"`
		Blocked   string `json:"blocked-uri"`
		Effective string `json:"effective-directive"`
		Violated  string `json:"violated-directive"`
	}
	type apiReport struct {
		Type string `json:"type"`
		Body struct {
			Document  string `json:"documentURL"`
			Blocked   string `json:"blockedURL"`
			Effective string `json:"effectiveDirective"`
		} `json:"body"`
	}
	var out []violation
	add := func(directive, blocked, doc string) {
		if !strings.HasPrefix(directive, "script-src") {
			return
		}
		if s := source(blocked); s != "" {
			out = append(out, violation{s, page(doc)})
		}
	}
	if b := bytes.TrimSpace(body); len(b) > 0 && b[0] == '[' {
		var reports []apiReport
		if json.Unmarshal(b, &reports) != nil {
			return nil
		}
		for _, r := range reports {
			if r.Type == "csp-violation" {
				add(r.Body.Effective, r.Body.Blocked, r.Body.Document)
			}
		}
		return out
	}
	var r struct {
		Report uriReport `json:"csp-report"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil
	}
	d := r.Report.Effective
	if d == "" { // older browsers send only violated-directive, with its sources
		d, _, _ = strings.Cut(r.Report.Violated, " ")
	}
	add(d, r.Report.Blocked, r.Report.Document)
	return out
}

// source turns a blocked URL into what the inventory records: the origin of
// an http(s) URL, a scheme for data:/blob:, or the inline/eval keyword.
func source(blocked string) string {
	switch blocked {
	case "inline", "eval", "wasm-eval", "trusted-types-policy", "trusted-types-sink":
		return blocked
	case "data", "blob":
		return blocked + ":"
	}
	u, err := url.Parse(blocked)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return ""
		}
		o := u.Scheme + "://" + strings.ToLower(u.Host)
		if len(o) > maxLen {
			return ""
		}
		return o
	case "data", "blob":
		return u.Scheme + ":"
	}
	return ""
}

// page keeps only the path of the reporting document: its query string can
// carry tokens.
func page(doc string) string {
	u, err := url.Parse(doc)
	if err != nil || u.Path == "" {
		return "/"
	}
	if len(u.Path) > 1024 {
		return u.Path[:1024]
	}
	return u.Path
}

func (c *Collector) record(id int, name, key string, v violation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	known := c.known[id]
	if known == nil {
		all, err := c.store.ListCSPScripts()
		if err != nil {
			log.Printf("csp: load inventory: %v", err)
			return
		}
		known = map[string]bool{}
		for _, s := range all[id] {
			known[s.Origin] = true
		}
		c.known[id] = known
	}
	if known[v.source] {
		return
	}
	if len(known) >= MaxSources {
		if !c.full[id] && c.alert != nil {
			c.full[id] = true
			go c.alert(name, InventoryFull, v.page)
		}
		return
	}
	if !c.newSrc.Allow(strconv.Itoa(id) + " " + key).Allowed {
		return
	}
	isNew, err := c.store.AddCSPScript(id, storage.CSPScript{Origin: v.source, Page: v.page, FirstSeen: time.Now().UTC()})
	if err != nil {
		log.Printf("csp: record %s for %s: %v", v.source, name, err)
		return
	}
	known[v.source] = true
	if isNew && c.alert != nil {
		go c.alert(name, v.source, v.page)
	}
}
