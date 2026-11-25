package ui

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"palisade/internal/storage"
)

func TestAPIPurgeService(t *testing.T) {
	var gotService, gotURL string
	varnish := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PURGE" {
			t.Errorf("method = %s, want PURGE", r.Method)
		}
		gotService, gotURL = r.Header.Get("X-Cache-Service"), r.Header.Get("X-Cache-Purge-Url")
	}))
	defer varnish.Close()

	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h, false)
	if err := h.db.AddService("blog", "", "/blog", "http://10.0.0.9:8000/base", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, _ := h.db.ListServices()
	id := strconv.Itoa(list[0].ID)
	if err := h.db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: strings.TrimPrefix(varnish.URL, "http://")}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, id string
		body     any
		status   int
		svc, url string
	}{
		{"whole service", id, nil, http.StatusOK, "blog", ""},
		{"path prefix mapped to backend URL", id, map[string]string{"path": "/blog/x.css"}, http.StatusOK, "blog", "^/base/x[.]css"},
		{"unsafe path", id, map[string]string{"path": "/a && obj.status"}, http.StatusBadRequest, "", ""},
		{"unknown service", "9999", nil, http.StatusNotFound, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotService, gotURL = "", ""
			rec := apiRequest(e, http.MethodPost, "/admin/api/v1/services/"+tc.id+"/purge", key, tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if gotService != tc.svc || gotURL != tc.url {
				t.Errorf("varnish got service=%q url=%q, want %q %q", gotService, gotURL, tc.svc, tc.url)
			}
		})
	}
}
