package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"palisade/internal/services"
	"palisade/internal/storage"
)

// fakeDocker serves GET /containers/json and a /events stream on a unix
// socket. Setting the containers pushes one event.
type fakeDocker struct {
	mu     sync.Mutex
	cs     []container
	events chan struct{}
}

func (f *fakeDocker) set(cs ...container) {
	f.mu.Lock()
	f.cs = cs
	f.mu.Unlock()
	select {
	case f.events <- struct{}{}:
	default:
	}
}

func startFake(t *testing.T) (*fakeDocker, string) {
	t.Helper()
	f := &fakeDocker{events: make(chan struct{}, 1)}
	dir, err := os.MkdirTemp("", "dock") // short: unix socket paths cap at ~104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			if !strings.Contains(r.URL.Query().Get("filters"), "palisade.enable=true") {
				t.Errorf("containers listed without the label filter: %s", r.URL.RawQuery)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(f.cs)
		case "/events":
			w.(http.Flusher).Flush()
			for {
				select {
				case <-f.events:
					_, _ = w.Write([]byte(`{"Type":"container","Action":"start"}` + "\n"))
					w.(http.Flusher).Flush()
				case <-r.Context().Done():
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return f, "unix://" + sock
}

func ctr(name, ip string, labels ...string) container {
	c := container{ID: name + "-id", Names: []string{"/" + name}, State: "running", Labels: map[string]string{"palisade.enable": "true"}}
	for i := 0; i+1 < len(labels); i += 2 {
		c.Labels["palisade."+labels[i]] = labels[i+1]
	}
	c.NetworkSettings.Networks = map[string]struct {
		IPAddress         string `json:"IPAddress"`
		GlobalIPv6Address string `json:"GlobalIPv6Address"`
	}{"web": {IPAddress: ip}}
	return c
}

func byName(t *testing.T, db *storage.DB, name string) (storage.Service, bool) {
	t.Helper()
	list, err := db.ListServices()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list {
		if s.Name == name {
			return s, true
		}
	}
	return storage.Service{}, false
}

func audits(t *testing.T, db *storage.DB) int {
	t.Helper()
	_, n, err := db.ListAudit(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSync pins issue #341: labelled containers become a service (several
// with one name load-balance), stopping them empties the backends but
// keeps the row and its settings, a restart rebuilds the same state without
// rewriting it, and a hand-made service is never taken over.
func TestSync(t *testing.T) {
	f, addr := startFake(t)
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.AddService("manual", "manual.test", "", "http://10.0.0.9:80", 0, 0); err != nil {
		t.Fatal(err)
	}
	reg, err := services.New(db)
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(addr, db, reg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	f.set(
		ctr("app-1", "172.20.0.3", "host", "x.test, www.x.test", "port", "8080", "name", "app"),
		ctr("app-2", "172.20.0.2", "host", "x.test, www.x.test", "port", "8080", "name", "app"),
		ctr("api", "172.20.0.4", "prefix", "/api", "port", "80"),
		ctr("noport", "172.20.0.5", "host", "np.test"),
		ctr("manual", "172.20.0.6", "host", "other.test", "port", "80"),
		ctr("steal", "172.20.0.7", "host", "manual.test", "port", "80"),
	)
	if err := w.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	app, ok := byName(t, db, "app")
	if !ok || !app.DockerManaged || app.Host != "x.test" || strings.Join(app.HostAliases, ",") != "www.x.test" ||
		strings.Join(app.Backends(), ",") != "http://172.20.0.2:8080,http://172.20.0.3:8080" {
		t.Fatalf("app = %+v", app)
	}
	if api, _ := byName(t, db, "api"); api.Prefix != "/api" || api.Backend != "http://172.20.0.4:80" {
		t.Errorf("api = %+v", api)
	}
	for _, name := range []string{"noport", "steal"} {
		if _, ok := byName(t, db, name); ok {
			t.Errorf("%s was created from bad labels", name)
		}
	}
	if m, _ := byName(t, db, "manual"); m.DockerManaged || m.Host != "manual.test" {
		t.Errorf("hand-made service taken over: %+v", m)
	}
	if got := reg.Match("x.test", "/"); got == nil || got.Name != "app" {
		t.Errorf("registry not reloaded: Match(x.test) = %v", got)
	}
	if n := audits(t, db); n != 2 {
		t.Errorf("%d audit rows, want one per created service", n)
	}

	// Settings survive a stop; the backends don't.
	if err := db.SetServiceBotMode(app.ID, "off"); err != nil {
		t.Fatal(err)
	}
	f.set(ctr("api", "172.20.0.4", "prefix", "/api", "port", "80"))
	if err := w.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	app, _ = byName(t, db, "app")
	if app.Backend != "" || app.ExtraBackends != nil || app.Host != "x.test" || app.BotMode != "off" {
		t.Errorf("stopped app = %+v", app)
	}

	// Back up, then a fresh watcher (a Palisade restart) changes nothing.
	f.set(ctr("app-1", "172.20.0.3", "host", "x.test, www.x.test", "port", "8080", "name", "app"),
		ctr("api", "172.20.0.4", "prefix", "/api", "port", "80"))
	if err := w.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	before := audits(t, db)
	w2, _ := New(addr, db, reg)
	if err := w2.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if after := audits(t, db); after != before {
		t.Errorf("restart rewrote %d services", after-before)
	}
	if app, _ = byName(t, db, "app"); app.Backend != "http://172.20.0.3:8080" || app.BotMode != "off" {
		t.Errorf("restarted app = %+v", app)
	}
}

// Run picks a new container up from the event stream, within seconds.
func TestRunEvents(t *testing.T) {
	f, addr := startFake(t)
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg, _ := services.New(db)
	w, _ := New(addr, db, reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(200 * time.Millisecond) // first sync and the event stream are up
	f.set(ctr("web", "172.20.0.8", "host", "web.test", "port", "80"))
	deadline := time.Now().Add(5 * time.Second)
	for reg.Match("web.test", "/") == nil {
		if time.Now().After(deadline) {
			t.Fatal("container start not picked up from events")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestParse(t *testing.T) {
	two := ctr("c", "172.20.0.2", "host", "a.test", "port", "80")
	two.NetworkSettings.Networks["db"] = two.NetworkSettings.Networks["web"]
	picked := ctr("c", "172.20.0.2", "host", "a.test", "port", "80", "network", "web")
	picked.NetworkSettings.Networks["db"] = two.NetworkSettings.Networks["web"]
	v6 := ctr("c", "", "host", "a.test", "port", "80")
	v6.NetworkSettings.Networks["web"] = struct {
		IPAddress         string `json:"IPAddress"`
		GlobalIPv6Address string `json:"GlobalIPv6Address"`
	}{GlobalIPv6Address: "fd00::2"}
	for name, tc := range map[string]struct {
		c       container
		backend string
	}{
		"ok":            {ctr("c", "172.20.0.2", "host", "A.test", "port", "80"), "http://172.20.0.2:80"},
		"ipv6":          {v6, "http://[fd00::2]:80"},
		"network label": {picked, "http://172.20.0.2:80"},
		"two networks":  {two, ""},
		"no route":      {ctr("c", "172.20.0.2", "port", "80"), ""},
		"bad prefix":    {ctr("c", "172.20.0.2", "prefix", "api", "port", "80"), ""},
		"bad port":      {ctr("c", "172.20.0.2", "host", "a.test", "port", "99999"), ""},
		"no ip":         {ctr("c", "", "host", "a.test", "port", "80"), ""},
		"wrong network": {ctr("c", "172.20.0.2", "host", "a.test", "port", "80", "network", "db"), ""},
	} {
		_, r, err := parse(tc.c)
		if tc.backend == "" {
			if err == nil {
				t.Errorf("%s: parsed, want an error", name)
			}
			continue
		}
		if err != nil || r.backends[0] != tc.backend || r.hosts[0] != "a.test" {
			t.Errorf("%s: %+v, %v", name, r, err)
		}
	}
}

func TestNew(t *testing.T) {
	for raw, ok := range map[string]bool{
		"":                            true,
		"unix:///var/run/docker.sock": true,
		"tcp://socket-proxy:2375":     true,
		"/var/run/docker.sock":        false,
		"http://socket-proxy:2375":    false,
		"tcp://":                      false,
	} {
		if _, err := New(raw, nil, nil); (err == nil) != ok {
			t.Errorf("New(%q) = %v, want ok=%v", raw, err, ok)
		}
	}
}
