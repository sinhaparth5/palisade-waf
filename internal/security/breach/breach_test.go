package breach

import (
	"context"
	"crypto/sha1" //nolint:gosec // matches the API under test
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeRange serves a range response listing each password in leaked, plus a
// padding entry, and counts calls.
func fakeRange(t *testing.T, leaked ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Add-Padding") != "true" {
			t.Error("Add-Padding header missing")
		}
		prefix := strings.TrimPrefix(r.URL.Path, "/")
		if len(prefix) != 5 {
			t.Errorf("sent %q, want only a 5-character prefix", prefix)
		}
		for _, pw := range leaked {
			sum := sha1.Sum([]byte(pw)) //nolint:gosec // see import
			h := strings.ToUpper(hex.EncodeToString(sum[:]))
			if h[:5] == prefix {
				fmt.Fprintf(w, "%s:42\r\n", h[5:])
			}
		}
		fmt.Fprintf(w, "%s:0\r\n", strings.Repeat("0", 35))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestLeaked(t *testing.T) {
	srv, calls := fakeRange(t, "password123")
	c := New(srv.URL + "/")
	ctx := context.Background()

	if leaked, ok := c.Leaked(ctx, "password123"); !leaked || !ok {
		t.Fatalf("password123: leaked=%v ok=%v", leaked, ok)
	}
	if leaked, ok := c.Leaked(ctx, "password123"); !leaked || !ok || calls.Load() != 1 {
		t.Fatalf("second lookup must come from the cache: calls=%d", calls.Load())
	}
	if leaked, ok := c.Leaked(ctx, "correct horse battery staple 9f2c"); leaked || !ok {
		t.Fatalf("unique password: leaked=%v ok=%v", leaked, ok)
	}

	// One cached range per distinct prefix.
	if got := len(c.cache); got != 2 {
		t.Fatalf("cache has %d prefixes, want 2", got)
	}
}

func TestLeakedFailsOpen(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	c := New(down.URL + "/")
	if leaked, ok := c.Leaked(context.Background(), "password123"); leaked || ok {
		t.Fatalf("leaked=%v ok=%v, want false false", leaked, ok)
	}
	if len(c.cache) != 0 {
		t.Fatal("a failed lookup must not be cached")
	}
	warned := c.lastWarn
	c.Leaked(context.Background(), "password123")
	if c.lastWarn != warned {
		t.Fatal("warning must be rate-limited, not logged per login")
	}
}

func TestCacheBounded(t *testing.T) {
	srv, _ := fakeRange(t)
	c := New(srv.URL + "/")
	for i := range cacheCap + 10 {
		c.Leaked(context.Background(), fmt.Sprint("pw", i))
	}
	if n := len(c.cache); n > cacheCap {
		t.Fatalf("cache grew to %d, cap %d", n, cacheCap)
	}
}

func TestPassword(t *testing.T) {
	tests := []struct {
		name, ct, body, basic string
		fields                []string
		want                  string
	}{
		{"form", "application/x-www-form-urlencoded", "user=a&password=hunter2", "", nil, "hunter2"},
		{"form with charset", "application/x-www-form-urlencoded; charset=utf-8", "pwd=x1", "", nil, "x1"},
		{"form custom field", "application/x-www-form-urlencoded", "user_pass=wp&password=other", "", []string{"user_pass"}, "wp"},
		{"custom field replaces defaults", "application/x-www-form-urlencoded", "password=other", "", []string{"user_pass"}, ""},
		{"json top level", "application/json", `{"email":"a@b","password":"j1"}`, "", nil, "j1"},
		{"json nested", "application/json", `{"user":{"Password":"j2"}}`, "", nil, "j2"},
		{"json non-string ignored", "application/json", `{"password":123}`, "", nil, ""},
		{"basic auth wins", "application/x-www-form-urlencoded", "password=form", "u:basic", nil, "basic"},
		{"basic auth only", "", "", "u:b2", nil, "b2"},
		{"multipart ignored", "multipart/form-data; boundary=x", "password=nope", "", nil, ""},
		{"empty", "application/x-www-form-urlencoded", "", "", nil, ""},
		{"bad json", "application/json", `{"password":`, "", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", tt.ct)
			if u, p, ok := strings.Cut(tt.basic, ":"); ok {
				r.SetBasicAuth(u, p)
			}
			if got := Password(r, []byte(tt.body), tt.fields); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
