// Package docker creates services from container labels (issue #341). It
// talks to the Docker Engine API over plain HTTP on the socket (or a socket
// proxy), lists running containers labelled palisade.enable=true, and keeps
// the Docker-managed services in the DB in step: on startup, on container
// events and every resyncEvery.
package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"palisade/internal/security/egress"
	"palisade/internal/services"
	"palisade/internal/storage"
)

const (
	resyncEvery = 5 * time.Minute
	// settle batches the events of one `compose up` into one sync.
	settle = time.Second
	// enableFilter is the Docker API filter for opted-in containers.
	enableFilter = `{"label":["palisade.enable=true"]}`
)

// Watcher keeps Docker-managed services in step with running containers.
type Watcher struct {
	client *http.Client // no timeout: /events streams
	base   string       // "http://docker" for a unix socket, else the proxy URL
	db     *storage.DB
	reg    *services.Registry
}

// New parses unix:///path or tcp://host:port; "" returns nil (discovery off).
func New(raw string, db *storage.DB, reg *services.Registry) (*Watcher, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("docker address: %w", err)
	}
	t := &http.Transport{MaxIdleConns: 2, IdleConnTimeout: time.Minute}
	w := &Watcher{client: &http.Client{Transport: t}, db: db, reg: reg}
	switch {
	case u.Scheme == "unix" && u.Path != "":
		path := u.Path
		t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}
		w.base = "http://docker"
	case u.Scheme == "tcp" && u.Host != "":
		t.DialContext = egress.Dialer(10 * time.Second).DialContext
		w.base = "http://" + u.Host
	default:
		return nil, fmt.Errorf("docker address %q: want unix:///path or tcp://host:port", raw)
	}
	return w, nil
}

// Run syncs now, then on every container event and every resyncEvery,
// until ctx ends. A Docker API that's down is logged and retried.
func (w *Watcher) Run(ctx context.Context) {
	kick := make(chan struct{}, 1)
	go w.watchEvents(ctx, kick)
	tick := time.NewTicker(resyncEvery)
	defer tick.Stop()
	for {
		if err := w.Sync(ctx); err != nil && ctx.Err() == nil {
			log.Printf("docker discovery: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-kick:
			// Let the rest of a burst arrive, then sync once.
			select {
			case <-time.After(settle):
			case <-ctx.Done():
				return
			}
			select {
			case <-kick:
			default:
			}
		}
	}
}

// watchEvents streams container events of opted-in containers and pokes
// kick on each; on a broken stream it reconnects and pokes once, since
// events may have been missed.
func (w *Watcher) watchEvents(ctx context.Context, kick chan<- struct{}) {
	poke := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	filters := `{"type":["container"],"label":["palisade.enable=true"],"event":["start","die","destroy","unpause","pause"]}`
	for first := true; ctx.Err() == nil; first = false {
		if !first {
			poke()
		}
		err := w.stream(ctx, "/events?filters="+url.QueryEscape(filters), poke)
		if ctx.Err() != nil {
			return
		}
		log.Printf("docker discovery: event stream: %v; reconnecting", err)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (w *Watcher) stream(ctx context.Context, path string, onEvent func()) error {
	resp, err := w.get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		onEvent()
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("closed by the Docker API")
}

func (w *Watcher) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return resp, nil
}

// container is the part of GET /containers/json that discovery reads.
type container struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Labels          map[string]string `json:"Labels"`
	State           string            `json:"State"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (w *Watcher) containers(ctx context.Context) ([]container, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := w.get(ctx, "/containers/json?filters="+url.QueryEscape(enableFilter))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []container
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("containers: %w", err)
	}
	return out, nil
}

// route is one service as its containers' labels describe it.
type route struct {
	hosts    []string
	prefix   string
	backends []string
}

// routes groups running, opted-in containers by service name. A container
// with unusable labels is logged and skipped; containers sharing a name
// become backends of one service, routed by the first one's labels.
func routes(cs []container) map[string]*route {
	slices.SortFunc(cs, func(a, b container) int { return strings.Compare(containerName(a), containerName(b)) })
	out := map[string]*route{}
	for _, c := range cs {
		if c.State != "running" || c.Labels["palisade.enable"] != "true" {
			continue
		}
		name, r, err := parse(c)
		if err != nil {
			log.Printf("docker discovery: container %s: %v", containerName(c), err)
			continue
		}
		if have, ok := out[name]; ok {
			if !slices.Equal(have.hosts, r.hosts) || have.prefix != r.prefix {
				log.Printf("docker discovery: container %s: host/prefix labels differ from the rest of service %q; using theirs", containerName(c), name)
			}
			if !slices.Contains(have.backends, r.backends[0]) {
				have.backends = append(have.backends, r.backends[0])
			}
			continue
		}
		out[name] = r
	}
	for _, r := range out {
		slices.Sort(r.backends) // stable order: no rewrite when only list order changed
	}
	return out
}

func containerName(c container) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return c.ID
}

// parse reads one container's labels into its service name and route.
func parse(c container) (string, *route, error) {
	l := c.Labels
	name := strings.TrimSpace(l["palisade.name"])
	if name == "" {
		name = containerName(c)
	}
	r := &route{prefix: strings.TrimSpace(l["palisade.prefix"])}
	for _, h := range strings.Split(l["palisade.host"], ",") {
		if h = services.NormalizeHost(h); h != "" && !slices.Contains(r.hosts, h) {
			r.hosts = append(r.hosts, h)
		}
	}
	if len(r.hosts) == 0 && r.prefix == "" {
		return "", nil, errors.New("needs palisade.host or palisade.prefix")
	}
	if r.prefix != "" && !strings.HasPrefix(r.prefix, "/") {
		return "", nil, fmt.Errorf("palisade.prefix %q must start with /", r.prefix)
	}
	port, err := strconv.Atoi(l["palisade.port"])
	if err != nil || port < 1 || port > 65535 {
		return "", nil, fmt.Errorf("palisade.port %q is not a port", l["palisade.port"])
	}
	nets := c.NetworkSettings.Networks
	netName := strings.TrimSpace(l["palisade.network"])
	if netName == "" {
		if len(nets) != 1 {
			return "", nil, fmt.Errorf("on %d networks: set palisade.network to the one Palisade shares", len(nets))
		}
		for n := range nets {
			netName = n
		}
	}
	n, ok := nets[netName]
	if !ok {
		return "", nil, fmt.Errorf("not on network %q", netName)
	}
	ip := n.IPAddress
	if ip == "" {
		ip = n.GlobalIPv6Address
	}
	if ip == "" {
		return "", nil, fmt.Errorf("no IP on network %q (host networking?)", netName)
	}
	r.backends = []string{"http://" + net.JoinHostPort(ip, strconv.Itoa(port))}
	return name, r, nil
}

// Sync lists the containers once and writes every change to a
// Docker-managed service: new routes become services, changed ones are
// updated, and a service with no running container keeps its row and
// settings but loses its backends. Each change is checked like a UI save,
// audited and followed by one Registry.Reload.
func (w *Watcher) Sync(ctx context.Context) error {
	cs, err := w.containers(ctx)
	if err != nil {
		return err
	}
	want := routes(cs)
	list := w.reg.List()
	for _, s := range list {
		if s.DockerManaged {
			if _, ok := want[s.Name]; !ok {
				want[s.Name] = &route{hosts: s.Hosts(), prefix: s.Prefix} // stopped: no backends
			}
		}
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	slices.Sort(names)
	changed := false
	for _, name := range names {
		r := want[name]
		if err := check(name, r, list); err != nil {
			log.Printf("docker discovery: service %q: %v", name, err)
			continue
		}
		ok, err := w.db.SetDockerService(name, r.hosts, r.prefix, r.backends)
		if errors.Is(err, storage.ErrNotDockerManaged) {
			log.Printf("docker discovery: service %q: %v; set palisade.name to another name", name, err)
			continue
		}
		if err != nil {
			return err
		}
		if ok {
			changed = true
			w.audit(name, r)
		}
	}
	if !changed {
		return nil
	}
	return w.reg.Reload(w.db)
}

// check runs the UI's own host and backend validation on a route.
func check(name string, r *route, list []storage.Service) error {
	id := 0
	for _, s := range list {
		if s.Name == name {
			id = s.ID
		}
	}
	if len(r.hosts) > 0 {
		if _, _, err := services.ValidateHosts(id, r.hosts[0], r.hosts[1:], "", list); err != nil {
			return err
		}
	}
	if len(r.backends) > 0 {
		return services.ValidateBackends(r.backends, "", 0)
	}
	return nil
}

func (w *Watcher) audit(name string, r *route) {
	summary := fmt.Sprintf("hosts=%s prefix=%s backends=%s", strings.Join(r.hosts, ","), r.prefix, strings.Join(r.backends, ","))
	if len(r.backends) == 0 {
		summary += " (no running container)"
	}
	if err := w.db.InsertAudit(storage.AuditEntry{Actor: "docker discovery", Action: "SYNC service", Target: "name=" + name, Summary: summary}); err != nil {
		log.Printf("docker discovery: audit: %v", err)
	}
}
