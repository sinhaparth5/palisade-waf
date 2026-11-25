package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"palisade/internal/notify/metrics"
	"palisade/internal/storage"
)

// Pushing autobans to CrowdSec (issue #342): each ban becomes an alert with
// one decision on every CrowdSec source that has machine credentials, so
// other bouncers on that LAPI block it too.

const (
	pushQueue = 1000 // bans waiting to be pushed; more are dropped
	pushBatch = 100  // alerts per POST /v1/alerts
	// permanentBan stands in for an autoban that never expires (BanHours 0):
	// a CrowdSec decision needs a duration.
	permanentBan = 10 * 365 * 24 * time.Hour
)

// pushRetry spaces out retries of a failed push; after the last the batch
// is dropped. A var so tests can shorten it.
var pushRetry = []time.Duration{time.Second, 10 * time.Second, time.Minute}

type ban struct {
	value, reason string
	dur           time.Duration
	at            time.Time
}

// PushBan queues an autoban (an IP or CIDR) for the CrowdSec sources. It
// never blocks: with the queue full the ban is dropped and counted as an
// error. dur 0 means the ban never expires.
func (w *Worker) PushBan(value, reason string, dur time.Duration) {
	select {
	case w.bans <- ban{value, reason, dur, w.now()}:
	default:
		metrics.CrowdSecPushErrors.Inc()
		log.Printf("threat-intel: crowdsec push queue full, dropped ban of %s", value)
	}
}

// pushLoop sends queued bans, batching whatever queued up while the last
// push was in flight.
func (w *Worker) pushLoop() {
	for {
		var batch []ban
		select {
		case b := <-w.bans:
			batch = append(batch, b)
		case <-w.stop:
			return
		}
	drain:
		for len(batch) < pushBatch {
			select {
			case b := <-w.bans:
				batch = append(batch, b)
			default:
				break drain
			}
		}
		w.pushBatch(batch)
	}
}

// pushBatch pushes batch to every enabled CrowdSec source with machine
// credentials, retrying each source with backoff.
func (w *Worker) pushBatch(batch []ban) {
	batch = w.notPulled(batch)
	if len(batch) == 0 {
		return
	}
	sources, err := w.db.ListThreatIntelSources()
	if err != nil {
		log.Printf("threat-intel: crowdsec push: list sources: %v", err)
		return
	}
	for _, s := range sources {
		if !s.Enabled || !s.CrowdSec() {
			continue
		}
		login, password, ok, err := w.db.CrowdSecMachine(s.ID)
		if !ok {
			if err != nil {
				log.Printf("threat-intel: %q crowdsec machine credentials: %v", s.Label, err)
			}
			continue
		}
		lapi := strings.TrimPrefix(s.URL, storage.CrowdSecPrefix)
		for try := 0; ; try++ {
			err := w.pushAlerts(lapi, login, password, batch)
			if err == nil {
				break
			}
			metrics.CrowdSecPushErrors.Inc()
			log.Printf("threat-intel: %q crowdsec push of %d bans: %v", s.Label, len(batch), err)
			if try == len(pushRetry) {
				break
			}
			select {
			case <-time.After(pushRetry[try]):
			case <-w.stop:
				return
			}
		}
	}
}

// notPulled drops bans of values a CrowdSec source handed us, so a decision
// never echoes back to the LAPI it came from. Autoban already never scores
// ip_blocked:crowdsec requests; this covers a ban racing the pull.
func (w *Worker) notPulled(batch []ban) []ban {
	w.csMu.Lock()
	defer w.csMu.Unlock()
	out := batch[:0]
	for _, b := range batch {
		v, ok := canonical(decision{Scope: scopeOf(b.value), Value: b.value})
		if !ok {
			continue
		}
		pulled := false
		for _, set := range w.cs {
			if _, pulled = set[v]; pulled {
				break
			}
		}
		if !pulled {
			b.value = v
			out = append(out, b)
		}
	}
	return out
}

func scopeOf(value string) string {
	if strings.Contains(value, "/") {
		return "Range"
	}
	return "Ip"
}

type alertSource struct {
	Scope string `json:"scope"`
	Value string `json:"value"`
	IP    string `json:"ip,omitempty"`
	Range string `json:"range,omitempty"`
}

type alertDecision struct {
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

type alert struct {
	Scenario        string          `json:"scenario"`
	ScenarioHash    string          `json:"scenario_hash"`
	ScenarioVersion string          `json:"scenario_version"`
	Message         string          `json:"message"`
	EventsCount     int             `json:"events_count"`
	StartAt         string          `json:"start_at"`
	StopAt          string          `json:"stop_at"`
	Capacity        int             `json:"capacity"`
	Leakspeed       string          `json:"leakspeed"`
	Simulated       bool            `json:"simulated"`
	Remediation     bool            `json:"remediation"`
	Events          []struct{}      `json:"events"`
	Source          alertSource     `json:"source"`
	Decisions       []alertDecision `json:"decisions"`
}

const scenario = "palisade/autoban"

func toAlert(b ban) alert {
	dur := b.dur
	if dur <= 0 {
		dur = permanentBan
	}
	scope := scopeOf(b.value)
	src := alertSource{Scope: scope, Value: b.value}
	if scope == "Ip" {
		src.IP = b.value
	} else {
		src.Range = b.value
	}
	at := b.at.UTC().Format(time.RFC3339)
	return alert{
		Scenario: scenario, Message: "Palisade autoban: " + b.reason,
		EventsCount: 1, StartAt: at, StopAt: at, Leakspeed: "0", Remediation: true,
		Events: []struct{}{}, Source: src,
		Decisions: []alertDecision{{Origin: "crowdsec", Type: "ban", Scope: scope,
			Value: b.value, Duration: dur.String(), Scenario: scenario}},
	}
}

// pushAlerts logs in as the machine and posts the batch as alerts.
// ponytail: logs in on every batch; bans are rare. Cache the JWT until its
// expire if pushes ever get frequent.
func (w *Worker) pushAlerts(lapi, login, password string, batch []ban) error {
	var auth struct {
		Token string `json:"token"`
	}
	if err := w.lapiPost(lapi+"/v1/watchers/login", "", map[string]any{
		"machine_id": login, "password": password, "scenarios": []string{scenario},
	}, &auth); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if auth.Token == "" {
		return fmt.Errorf("login: LAPI returned no token")
	}
	alerts := make([]alert, len(batch))
	for i, b := range batch {
		alerts[i] = toAlert(b)
	}
	return w.lapiPost(lapi+"/v1/alerts", auth.Token, alerts, nil)
}

func (w *Worker) lapiPost(url, token string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "palisade/threat-intel")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("LAPI returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(out)
}
