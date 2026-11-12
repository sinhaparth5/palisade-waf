package services

import (
	"testing"

	"palisade/internal/storage"
)

func TestParseRateRules(t *testing.T) {
	rules, err := ParseRateRules("# comment\n\npost /reset* 5/h 3\n* /search 2 10\nGET /export 10/m 2")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0].Method != "POST" || rules[0].Prefix != "/reset" || rules[0].RPS != 5.0/3600 || rules[0].Burst != 3 ||
		rules[0].Text != "POST /reset 5/h 3" || rules[1].RPS != 2 || rules[2].RPS != 10.0/60 {
		t.Fatalf("got %+v", rules)
	}
	for _, bad := range []string{
		"POST /reset 5/h", "PO-ST /x 1 1", "POST reset 1 1", "POST /a*b 1 1",
		"POST /x 0 1", "POST /x -1 1", "POST /x 5/d 1", "POST /x abc 1", "POST /x 1 0", "POST /x 1 x",
	} {
		if _, err := ParseRateRules(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestAllowPath: longest prefix wins, a named method beats "*", counters are
// per client and per rule, and unmatched requests pass.
func TestAllowPath(t *testing.T) {
	r := &Registry{rateRules: buildRateRules(map[int]string{1: "* /api 100 100\nPOST /api/reset 1/h 1\n* /api/reset 100 100"},
		[]storage.Service{{ID: 1, Name: "svc"}})}
	defer stopRateRules(r.rateRules)

	if res, rule := r.AllowPath("svc", "POST", "/api/reset", "a"); !res.Allowed || rule != "POST /api/reset 1/h 1" {
		t.Fatalf("first: %+v %q", res, rule)
	}
	if res, _ := r.AllowPath("svc", "POST", "/api/reset/x", "a"); res.Allowed {
		t.Fatal("second request from a allowed")
	}
	if res, _ := r.AllowPath("svc", "POST", "/api/reset", "b"); !res.Allowed {
		t.Fatal("other client limited")
	}
	if res, rule := r.AllowPath("svc", "GET", "/api/reset", "a"); !res.Allowed || rule != "* /api/reset 100 100" {
		t.Fatalf("GET: %+v %q", res, rule)
	}
	if res, rule := r.AllowPath("svc", "POST", "/other", "a"); !res.Allowed || rule != "" {
		t.Fatalf("unmatched: %+v %q", res, rule)
	}
	if _, rule := r.AllowPath("nope", "POST", "/api/reset", "a"); rule != "" {
		t.Fatal("unknown service matched")
	}
}
