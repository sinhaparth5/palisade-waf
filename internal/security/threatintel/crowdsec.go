package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"palisade/internal/storage"
)

// crowdSecPoll is how often CrowdSec LAPI sources are polled. Polls after the
// first only transfer changes, so this can be short.
const crowdSecPoll = 30 * time.Second

// decision is one entry of a LAPI bouncer stream response.
type decision struct {
	Duration string `json:"duration"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

type decisionStream struct {
	New     []decision `json:"new"`
	Deleted []decision `json:"deleted"`
}

// syncCrowdSecSource pulls a CrowdSec LAPI's decision stream (issue #194):
// the full set on the first poll after startup, changes after that. Only
// "ban" decisions on Ip and Range scopes block; captcha and others are
// ignored. A failed poll keeps the last known decisions, minus any that
// have expired.
// ponytail: expiries live in memory, so decisions loaded from the DB before
// the first successful poll after a restart don't expire until that poll.
func (w *Worker) syncCrowdSecSource(s storage.ThreatIntelSource) {
	w.csMu.Lock()
	defer w.csMu.Unlock()

	now := w.now()
	set, started := w.cs[s.ID]
	changed := false
	stream, err := w.fetchDecisions(s, !started)
	if err == nil {
		if !started {
			set, changed = make(map[string]time.Time), true
			w.cs[s.ID] = set
		}
		// ponytail: a deleted decision drops the value even if another
		// decision still bans it; the next restart's full sync restores it.
		for _, d := range stream.Deleted {
			if v, ok := canonical(d); ok {
				if _, had := set[v]; had {
					delete(set, v)
					changed = true
				}
			}
		}
		for _, d := range stream.New {
			if v, exp, ok := banned(d, now); ok && exp.After(set[v]) {
				set[v] = exp
				changed = true
			}
		}
	}
	for v, exp := range set {
		if !exp.After(now) {
			delete(set, v)
			changed = true
		}
	}

	if changed {
		values := slices.Sorted(maps.Keys(set))
		if serr := w.db.ReplaceThreatIntelIPs(s.ID, values); serr != nil && err == nil {
			err = serr
		} else if serr == nil && w.reloadIPBL != nil {
			w.reloadIPBL()
		}
	}
	if err != nil {
		log.Printf("threat-intel: %q crowdsec error: %v", s.Label, err)
		_ = w.db.UpdateThreatIntelSync(s.ID, 0, err.Error())
		return
	}
	_ = w.db.UpdateThreatIntelSync(s.ID, len(set), "")
}

// banned returns the canonical value and expiry of a ban decision on an IP
// or range, or ok=false for anything the blocklist doesn't enforce.
func banned(d decision, now time.Time) (value string, expires time.Time, ok bool) {
	dur, err := time.ParseDuration(d.Duration)
	if !strings.EqualFold(d.Type, "ban") || err != nil || dur <= 0 {
		return "", time.Time{}, false
	}
	value, ok = canonical(d)
	return value, now.Add(dur), ok
}

// canonical normalises an Ip or Range decision value so a later delete
// matches however LAPI spelled it.
func canonical(d decision) (string, bool) {
	switch strings.ToLower(d.Scope) {
	case "ip":
		if a, err := netip.ParseAddr(d.Value); err == nil {
			return a.String(), true
		}
	case "range":
		if p, err := netip.ParsePrefix(d.Value); err == nil {
			return p.Masked().String(), true
		}
	}
	return "", false
}

// fetchDecisions calls GET /v1/decisions/stream with the source's bouncer key.
func (w *Worker) fetchDecisions(s storage.ThreatIntelSource, startup bool) (*decisionStream, error) {
	key, err := w.db.ThreatIntelKey(s.ID)
	if err != nil {
		return nil, err
	}
	url := strings.TrimPrefix(s.URL, storage.CrowdSecPrefix) + "/v1/decisions/stream?scopes=ip,range&startup=" + fmt.Sprint(startup)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("User-Agent", "palisade/threat-intel")
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LAPI returned %s", resp.Status)
	}
	var stream decisionStream
	// The community blocklist runs to tens of thousands of decisions.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&stream); err != nil {
		return nil, fmt.Errorf("decode LAPI response: %w", err)
	}
	return &stream, nil
}
