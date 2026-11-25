package ui

import (
	"net/http"
	"strings"
	"testing"
)

type intelPage struct {
	Sources []intelView   `json:"sources"`
	Presets []intelPreset `json:"presets"`
}

// TestThreatIntelAPI covers the React Threat Intel page: field errors that
// name the field, duplicates, pause, sync now, delete, and CrowdSec secrets
// that never come back.
func TestThreatIntelAPI(t *testing.T) {
	env := newAdminEnv(t)
	const feeds = "/admin/api/threat-intel"
	for _, tc := range []struct {
		path  string
		body  any
		field string
	}{
		{feeds, intelAddRequest{URL: "https://example.com/l.txt", IntervalHours: 24}, "label"},
		{feeds, intelAddRequest{Label: "x", IntervalHours: 24}, "url"},
		{feeds, intelAddRequest{Label: "x", URL: "file:///etc/passwd", IntervalHours: 24}, "url"},
		{feeds, intelAddRequest{Label: "x", URL: "https://example.com/l.txt"}, "interval_hours"},
		{feeds + "/crowdsec", crowdSecAddRequest{Label: "cs", URL: "http://lapi:8080"}, "api_key"},
		{feeds + "/crowdsec", crowdSecAddRequest{Label: "cs", APIKey: "k"}, "url"},
		{feeds + "/crowdsec", crowdSecAddRequest{Label: "cs", URL: "http://lapi:8080", APIKey: "k", MachineLogin: "m"}, "machine_password"},
		{feeds + "/crowdsec", crowdSecAddRequest{Label: "cs", URL: "http://lapi:8080", APIKey: "k", MachinePassword: "p"}, "machine_login"},
		{feeds + "/crowdsec", crowdSecAddRequest{Label: "cs", URL: "http://lapi:8080", APIKey: "k", MachineLogin: "a\nb", MachinePassword: "p"}, "machine_login"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPost, tc.path, tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%+v: %d %s, want a %s error", tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPost, feeds, "nope", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("non-object body: %d", rec.Code)
	}

	add := intelAddRequest{Label: " Feed ", URL: "https://example.com/l.txt", IntervalHours: 6}
	if rec := env.doJSON(env.session, http.MethodPost, feeds, add, nil); rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	var dup jsonError
	if rec := env.doJSON(env.session, http.MethodPost, feeds, add, &dup); rec.Code != http.StatusConflict || dup.Fields["url"] == "" {
		t.Errorf("duplicate: %d %s", rec.Code, rec.Body)
	}
	cs := crowdSecAddRequest{Label: "cs", URL: "http://lapi:8080/", APIKey: "s3cret-key", MachineLogin: "palisade", MachinePassword: "m4chine-pw"}
	if rec := env.doJSON(env.session, http.MethodPost, feeds+"/crowdsec", cs, nil); rec.Code != http.StatusCreated {
		t.Fatalf("crowdsec: %d %s", rec.Code, rec.Body)
	}
	if rec := env.doJSON(env.session, http.MethodPost, feeds+"/crowdsec", cs, nil); rec.Code != http.StatusConflict {
		t.Errorf("duplicate LAPI: %d", rec.Code)
	}

	viewer := env.sessionAs("viewer")
	var page intelPage
	rec := env.doJSON(viewer, http.MethodGet, feeds, nil, &page)
	if strings.Contains(rec.Body.String(), "s3cret-key") || strings.Contains(rec.Body.String(), "m4chine-pw") {
		t.Error("bouncer key or machine password sent back")
	}
	if len(page.Sources) != 2 || len(page.Presets) == 0 {
		t.Fatalf("page = %+v", page)
	}
	feed, lapi := page.Sources[0], page.Sources[1]
	if feed.Label != "Feed" || feed.Kind != "feed" || feed.IntervalHours != 6 || !feed.Enabled || feed.LastSyncedAt != "" || feed.Push {
		t.Errorf("feed = %+v", feed)
	}
	if lapi.Kind != "crowdsec" || lapi.URL != "http://lapi:8080" || !lapi.Push {
		t.Errorf("crowdsec = %+v", lapi)
	}
	if key, _ := env.db.ThreatIntelKey(lapi.ID); key != "s3cret-key" {
		t.Errorf("stored key = %q", key)
	}

	// Viewers read but can't write.
	if rec := env.doJSON(viewer, http.MethodPost, feeds, add, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer add: %d", rec.Code)
	}

	id := itoa(feed.ID)
	if rec := env.doJSON(env.session, http.MethodPut, feeds+"/"+id, map[string]bool{"enabled": false}, nil); rec.Code != http.StatusNoContent {
		t.Errorf("pause: %d %s", rec.Code, rec.Body)
	}
	if srcs, _ := env.db.ListThreatIntelSources(); srcs[0].Enabled {
		t.Error("pause left the feed enabled")
	}
	if rec := env.doJSON(env.session, http.MethodPut, feeds+"/"+id, map[string]any{}, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("pause without enabled: %d", rec.Code)
	}
	var synced intelView
	if rec := env.doJSON(env.session, http.MethodPost, feeds+"/"+id+"/sync", nil, &synced); rec.Code != http.StatusOK || synced.ID != feed.ID || env.count("intel") != 1 {
		t.Errorf("sync: %d %+v, %d calls", rec.Code, synced, env.count("intel"))
	}
	if rec := env.doJSON(env.session, http.MethodPost, feeds+"/999/sync", nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("sync unknown: %d", rec.Code)
	}
	for _, m := range []string{http.MethodPut, http.MethodDelete} {
		if rec := env.doJSON(env.session, m, feeds+"/x", map[string]bool{"enabled": true}, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s bad id: %d", m, rec.Code)
		}
	}
	if rec := env.doJSON(env.session, http.MethodDelete, feeds+"/"+itoa(lapi.ID), nil, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	if _, _, ok, _ := env.db.CrowdSecMachine(lapi.ID); ok {
		t.Error("delete kept the machine credentials")
	}
	if srcs, _ := env.db.ListThreatIntelSources(); len(srcs) != 1 {
		t.Errorf("%d sources after delete", len(srcs))
	}
}
