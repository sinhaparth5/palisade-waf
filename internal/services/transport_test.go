package services

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"palisade/internal/ext"
	"palisade/internal/security/egress"
)

// TestBackendTransportReusesConns pins issue #107: with Go's default of 2
// idle conns per host, repeated bursts of concurrent requests to one backend
// open new connections every burst. The count must stay at the burst size.
func TestBackendTransportReusesConns(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond) // keep the burst in flight together
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	client := &http.Client{Transport: backendTransport}
	const concurrency, rounds = 20, 10
	for range rounds {
		var wg sync.WaitGroup
		for range concurrency {
			wg.Go(func() {
				resp, err := client.Get(srv.URL)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			})
		}
		wg.Wait()
	}
	if n := newConns.Load(); n > concurrency {
		t.Fatalf("opened %d backend connections for %d rounds of %d concurrent requests, want <= %d", n, rounds, concurrency, concurrency)
	}
}

// TestBackendTransportRefusesMetadata pins issue #270: the check is on the
// IP dialed, so it holds for a hostname that passed Validate when the
// service was saved and resolves to the metadata address later.
func TestBackendTransportRefusesMetadata(t *testing.T) {
	resp, err := (&http.Client{Transport: backendTransport}).Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		resp.Body.Close()
	}
	if !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("err = %v, want egress.ErrBlocked", err)
	}
}

// TestExtDial pins issue #343: a registered ext.Dial takes the backend
// connections it handles, and anything it passes on still meets the
// metadata check.
func TestExtDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	errHook := errors.New("tunnel down")
	tunnel := func(ctx context.Context, network, addr string) (net.Conn, bool, error) {
		switch addr {
		case "tunnel.invalid:80":
			c, err := (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
			return c, true, err
		case "down.invalid:80":
			return nil, true, errHook
		}
		return nil, false, nil
	}
	for _, tc := range []struct {
		name    string
		hook    func(context.Context, string, string) (net.Conn, bool, error)
		backend string
		fail    bool
		is      error // when set, the failure must wrap it
	}{
		{"no hook", nil, srv.URL, false, nil},
		{"no hook, unknown host", nil, "http://tunnel.invalid/", true, nil},
		{"handled", tunnel, "http://tunnel.invalid/", false, nil},
		{"handled error", tunnel, "http://down.invalid/", true, errHook},
		{"passed on", tunnel, srv.URL, false, nil},
		{"passed on, metadata", tunnel, "http://169.254.169.254/", true, egress.ErrBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ext.Dial = tc.hook
			defer func() { ext.Dial = nil }()
			err := Probe(tc.backend)
			if (err != nil) != tc.fail || (tc.is != nil && !errors.Is(err, tc.is)) {
				t.Fatalf("Probe(%s) = %v, want fail=%v (%v)", tc.backend, err, tc.fail, tc.is)
			}
		})
	}
}
