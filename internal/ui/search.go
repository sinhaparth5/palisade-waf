package ui

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"text/template/parse"

	"github.com/labstack/echo/v4"

	"palisade/internal/storage"
)

// Top bar search (issue #225): page cards the caller's role can see, then
// live records. Read-only, so every role can use it.

// adminPages are the base.html pages, in sidebar order.
var adminPages = []string{"dashboard", "logs", "services", "certificates", "ip_rules", "geo_rules", "waf_rules", "threat_intel", "ai_usage", "settings"}

var pageHeadings = map[string]string{
	"dashboard":    "Dashboard",
	"logs":         "Live Logs",
	"ip_rules":     "IP Rules",
	"geo_rules":    "Geo Rules",
	"services":     "Services",
	"waf_rules":    "WAF Rules",
	"threat_intel": "Threat Intel",
	"ai_usage":     "AI Usage",
	"certificates": "Certificates",
	"settings":     "Settings",
}

const searchLimit = 8 // hits per group

type searchHit struct{ Title, Detail, URL string }

type searchGroup struct {
	Label, Icon string
	Hits        []searchHit
}

// section is a page or one of its cards, shown to roles of at least need.
type section struct {
	searchHit
	need string
}

var (
	// Components whose "Title" argument is a card heading.
	headerTemplates = map[string]bool{"card-header": true, "panel-header": true, "section-head": true, "settings-section-title": true}
	titleArg        = regexp.MustCompile(`"Title" "([^"]+)"`)
	literalHeading  = regexp.MustCompile(`<h[23][^>]*>([^<]+)</h[23]>`)
)

// searchSections walks each page's "content" parse tree for card headings,
// following {{template}} calls and raising the required role inside
// {{if can .Role "x"}}, so a card is offered only to roles that see it.
func (h *Handler) searchSections() []section {
	var out []section
	for _, page := range adminPages {
		t := h.tmpls[page]
		pageURL := strings.TrimSuffix("/"+strings.ReplaceAll(page, "_", "-"), "/dashboard") // under the admin path
		heading := pageHeadings[page]
		out = append(out, section{searchHit{heading, "Page", pageURL}, storage.RoleViewer})
		seen := map[string]bool{}
		add := func(title, need string) {
			title = strings.TrimSpace(title)
			if title == "" || seen[title] {
				return
			}
			seen[title] = true
			out = append(out, section{searchHit{title, heading, pageURL + "#find=" + url.PathEscape(title)}, need})
		}
		var walk func(n parse.Node, need string, depth int)
		walk = func(n parse.Node, need string, depth int) {
			if n == nil || depth > 20 {
				return
			}
			switch n := n.(type) {
			case *parse.ListNode:
				if n == nil {
					return
				}
				for _, c := range n.Nodes {
					walk(c, need, depth)
				}
			case *parse.TextNode:
				for _, m := range literalHeading.FindAllSubmatch(n.Text, -1) {
					add(string(m[1]), need)
				}
			case *parse.IfNode:
				walk(n.List, higherRole(need, canRole(n.Pipe)), depth)
				walk(n.ElseList, need, depth)
			case *parse.RangeNode:
				walk(n.List, need, depth)
				walk(n.ElseList, need, depth)
			case *parse.WithNode:
				walk(n.List, need, depth)
				walk(n.ElseList, need, depth)
			case *parse.TemplateNode:
				if headerTemplates[n.Name] {
					if m := titleArg.FindStringSubmatch(n.Pipe.String()); m != nil {
						add(m[1], need)
					}
				} else if sub := t.Lookup(n.Name); sub != nil && sub.Tree != nil {
					walk(sub.Tree.Root, need, depth+1)
				}
			}
		}
		if c := t.Lookup("content"); c != nil && c.Tree != nil {
			walk(c.Tree.Root, storage.RoleViewer, 0)
		}
	}
	return out
}

// canRole returns the role an {{if can .Role "x"}} pipe requires, or "".
func canRole(p *parse.PipeNode) string {
	if p == nil || len(p.Cmds) != 1 || len(p.Cmds[0].Args) != 3 {
		return ""
	}
	args := p.Cmds[0].Args
	if id, ok := args[0].(*parse.IdentifierNode); !ok || id.Ident != "can" {
		return ""
	}
	if s, ok := args[2].(*parse.StringNode); ok {
		return s.Text
	}
	return ""
}

func higherRole(a, b string) string {
	if roleRank[b] > roleRank[a] {
		return b
	}
	return a
}

// matchHits returns up to searchLimit hits whose haystack contains q.
func matchHits[T any](q string, rows []T, hit func(T) (searchHit, string)) []searchHit {
	var out []searchHit
	for _, r := range rows {
		if h, hay := hit(r); strings.Contains(strings.ToLower(hay), q) {
			if out = append(out, h); len(out) == searchLimit {
				break
			}
		}
	}
	return out
}

func scope(app string) string {
	if app == "" {
		return "global"
	}
	return app
}

// Search renders the top bar search results for ?q=.
func (h *Handler) Search(c echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("q"))
	q := strings.ToLower(raw)
	data := map[string]any{"Q": raw}
	if q == "" {
		return h.renderPartial(c, "dashboard", "search-results", data)
	}
	role := ""
	if u := currentUser(c); u != nil {
		role = u.Role
	}
	admin := h.cfg.Admin.Path
	var groups []searchGroup
	group := func(label, icon string, hits []searchHit) {
		if len(hits) > 0 {
			groups = append(groups, searchGroup{label, icon, hits})
		}
	}

	var visible []section
	for _, s := range h.sections {
		if roleRank[role] >= roleRank[s.need] {
			visible = append(visible, s)
		}
	}
	// Titles starting with q, then containing it, then page-name matches.
	rank := func(s section) int {
		t := strings.ToLower(s.Title)
		switch {
		case strings.HasPrefix(t, q):
			return 0
		case strings.Contains(t, q):
			return 1
		}
		return 2
	}
	sort.SliceStable(visible, func(i, j int) bool { return rank(visible[i]) < rank(visible[j]) })
	group("Pages", "hgi-file-01", matchHits(q, visible, func(s section) (searchHit, string) {
		hit := s.searchHit
		hit.URL = admin + hit.URL
		return hit, s.Title + " " + s.Detail
	}))

	svcs, err := h.db.ListServices()
	if err != nil {
		return err
	}
	group("Services", "hgi-settings-01", matchHits(q, svcs, func(s storage.Service) (searchHit, string) {
		return searchHit{s.Name, s.Host + s.Prefix, admin + "/services"},
			strings.Join(append([]string{s.Name, s.Host, s.Prefix}, s.HostAliases...), " ")
	}))
	ips, err := h.db.ListIPRules()
	if err != nil {
		return err
	}
	group("IP rules", "hgi-cancel-circle", matchHits(q, ips, func(r storage.IPRule) (searchHit, string) {
		return searchHit{r.IP, r.RuleType + " · " + scope(r.AppName), admin + "/ip-rules"}, r.IP + " " + r.Note
	}))
	geo, err := h.db.ListGeoRules()
	if err != nil {
		return err
	}
	group("Geo rules", "hgi-earth", matchHits(q, geo, func(r storage.GeoRule) (searchHit, string) {
		return searchHit{r.CountryCode, r.RuleType + " · " + scope(r.AppName), admin + "/geo-rules"}, r.CountryCode
	}))
	certs, err := h.db.ListCertificates()
	if err != nil {
		return err
	}
	group("Certificates", "hgi-certificate-01", matchHits(q, certs, func(r storage.CertRecord) (searchHit, string) {
		return searchHit{r.Name, r.Domains, admin + "/certificates"}, r.Name + " " + r.Domains
	}))
	feeds, err := h.db.ListThreatIntelSources()
	if err != nil {
		return err
	}
	group("Threat intel", "hgi-database-01", matchHits(q, feeds, func(r storage.ThreatIntelSource) (searchHit, string) {
		return searchHit{r.Label, r.URL, admin + "/threat-intel"}, r.Label + " " + r.URL
	}))
	rules, err := h.db.ListWAFCustomRules()
	if err != nil {
		return err
	}
	group("Custom WAF rules", "hgi-security-block", matchHits(q, rules, func(r storage.WAFCustomRule) (searchHit, string) {
		title := r.Note
		if title == "" {
			title, _, _ = strings.Cut(r.Rule, "\n")
		}
		return searchHit{title, scope(r.ServiceName), admin + "/waf-rules"}, r.Rule + " " + r.Note + " " + r.ServiceName
	}))

	data["Groups"] = groups
	return h.renderPartial(c, "dashboard", "search-results", data)
}
