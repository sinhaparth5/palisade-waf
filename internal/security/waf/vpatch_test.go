package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"palisade/internal/config"
)

// TestVPatchPack compiles the whole pack: header lines, id range, one rule
// per patch, unique ids. A failure here is what would otherwise panic at
// startup.
func TestVPatchPack(t *testing.T) {
	ps, err := loadVPatches()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]string{}
	for _, p := range ps {
		if prev, dup := seen[p.RuleID]; dup {
			t.Errorf("%s reuses rule id %d of %s", p.CVE, p.RuleID, prev)
		}
		seen[p.RuleID] = p.CVE
		if !strings.HasPrefix(p.CVE, "CVE-") || !strings.HasPrefix(p.Reference, "https://") || len(p.Added) != len("2006-01-02") {
			t.Errorf("%s: bad header %+v", p.CVE, p)
		}
		if _, ok := vpatchCases[p.CVE]; !ok {
			t.Errorf("%s has no blocking/false-positive test case", p.CVE)
		}
	}
}

func TestValidateRulesRejectsOutOfRange(t *testing.T) {
	_, err := validateRules(`SecRule ARGS "@contains x" "id:1000001,phase:2,deny"`, "virtual patch", VPatchIDMin, VPatchIDMax)
	if err == nil || !strings.Contains(err.Error(), "virtual patch range") {
		t.Fatalf("custom-range id accepted as a patch: %v", err)
	}
}

type vpatchCase struct {
	exploit, benign func() *http.Request
}

func get(target string) func() *http.Request {
	return func() *http.Request { return browserReq(httptest.NewRequest(http.MethodGet, target, nil)) }
}

func post(target, form string) func() *http.Request {
	return func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return browserReq(r)
	}
}

func browserReq(r *http.Request) *http.Request {
	r.Host = "app.example.com"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en")
	return r
}

func with(f func() *http.Request, edit func(*http.Request)) func() *http.Request {
	return func() *http.Request { r := f(); edit(r); return r }
}

// vpatchCases holds, per CVE, a request carrying the exploit and a normal
// request to the same product that must pass.
var vpatchCases = map[string]vpatchCase{
	"CVE-2025-29927": {
		exploit: with(get("/dashboard"), func(r *http.Request) {
			r.Header.Set("X-Middleware-Subrequest", "middleware:middleware:middleware:middleware:middleware")
		}),
		benign: get("/_next/static/chunks/main.js"),
	},
	"CVE-2023-22515": {
		exploit: get("/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"),
		benign:  get("/server-info.action?os_username=alice"),
	},
	"CVE-2022-26134": {
		exploit: get("/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/"),
		benign:  get("/display/DOC/Getting+started"),
	},
	"CVE-2024-4577": {
		exploit: get("/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
		benign:  get("/index.php?q=caf%C3%A9+%AD+menu&page=2"),
	},
	"CVE-2024-3400": {
		exploit: with(get("/ssl-vpn/hipreport.esp"), func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "SESSID", Value: "/../../../var/appweb/sslvpndocs/global-protect/portal/images/x.txt"})
		}),
		benign: with(get("/ssl-vpn/hipreport.esp"), func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "SESSID", Value: "a1b2c3d4e5f6"})
		}),
	},
	"CVE-2024-27198": {
		exploit: get("/hax?jsp=/app/rest/users;.jsp"),
		benign:  get("/app/rest/users?locator=username:alice"),
	},
	"CVE-2022-22965": {
		exploit: post("/greeting", "class.module.classLoader.resources.context.parent.pipeline.first.pattern=x"),
		benign:  post("/greeting", "name=alice&classroom=7b"),
	},
}

func TestVPatches(t *testing.T) {
	e, err := New(config.WAFConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range VPatches {
		tc := vpatchCases[p.CVE]
		if tc.exploit == nil {
			continue // reported by TestVPatchPack
		}
		t.Run(p.CVE, func(t *testing.T) {
			res, err := e.Check(tc.exploit(), "203.0.113.9")
			if err != nil {
				t.Fatal(err)
			}
			if !res.Blocked || res.RuleID != p.RuleID {
				t.Errorf("exploit: blocked=%v rule=%d, want blocked by %d", res.Blocked, res.RuleID, p.RuleID)
			}
			res, err = e.Check(tc.benign(), "203.0.113.9")
			if err != nil {
				t.Fatal(err)
			}
			if res.Blocked {
				t.Errorf("normal request blocked by rule %d", res.RuleID)
			}
		})
	}
}

// TestVPatchDisabledByID: switching a patch off is a rule exception, which
// must work although patches load before the SecRuleRemoveById line.
func TestVPatchDisabledByID(t *testing.T) {
	p := VPatches[0]
	e, err := New(config.WAFConfig{Enabled: true}, []int{p.RuleID})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Check(vpatchCases[p.CVE].exploit(), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if res.RuleID == p.RuleID {
		t.Fatalf("disabled patch %s still fired", p.CVE)
	}
}
