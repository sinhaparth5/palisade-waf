package storage

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// ── Threat intelligence ───────────────────────────────────────────────────────

// ThreatIntelSource is one row from threat_intel_sources.
type ThreatIntelSource struct {
	ID            int64
	Label         string
	URL           string
	IntervalHours int
	Enabled       bool
	LastSyncedAt  time.Time // zero = never synced
	LastError     string
	IPCount       int
	RangeCount    int // CIDR entries among IPCount; filled by ThreatIntelRangeCounts, not ListThreatIntelSources
	CreatedAt     time.Time
}

// CrowdSecPrefix marks a threat-intel source as a CrowdSec LAPI (issue #194)
// rather than a plain-text feed: its URL is stored as "crowdsec+<LAPI URL>".
const CrowdSecPrefix = "crowdsec+"

// CrowdSec reports whether s is a CrowdSec LAPI source.
func (s ThreatIntelSource) CrowdSec() bool { return strings.HasPrefix(s.URL, CrowdSecPrefix) }

// AddCrowdSecSource adds a CrowdSec LAPI source and stores its bouncer key
// sealed (threatintel_api_keys).
func (db *DB) AddCrowdSecSource(label, lapiURL, apiKey string) error {
	url := CrowdSecPrefix + strings.TrimRight(lapiURL, "/")
	if err := db.AddThreatIntelSource(label, url, 1); err != nil {
		return err
	}
	var id int64
	if err := db.queryRow(`SELECT id FROM threat_intel_sources WHERE url = ?`, url).Scan(&id); err != nil {
		return err
	}
	return db.setThreatIntelKey(id, apiKey)
}

// ThreatIntelKey returns a source's API key ("" when it has none).
func (db *DB) ThreatIntelKey(id int64) (string, error) {
	keys, err := db.threatIntelKeys()
	return keys[strconv.FormatInt(id, 10)], err
}

// threatIntelKeys reads every source's API key. They share one sealed meta
// value, a JSON object keyed by source id, so secretMetaKeys stays a fixed list.
func (db *DB) threatIntelKeys() (map[string]string, error) {
	keys := map[string]string{}
	v, err := db.getSecretMeta("threatintel_api_keys")
	if err != nil || v == "" {
		return keys, err
	}
	return keys, json.Unmarshal([]byte(v), &keys)
}

// setThreatIntelKey stores (or, with "", removes) a source's API key.
func (db *DB) setThreatIntelKey(id int64, key string) error {
	keys, err := db.threatIntelKeys()
	if err != nil {
		return err
	}
	if key == "" {
		delete(keys, strconv.FormatInt(id, 10))
	} else {
		keys[strconv.FormatInt(id, 10)] = key
	}
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return db.setSecretMeta("threatintel_api_keys", string(b))
}

// ThreatIntelRangeCounts returns how many CIDR entries each source holds.
func (db *DB) ThreatIntelRangeCounts() (map[int64]int, error) {
	rows, err := db.query(`SELECT source_id, COUNT(*) FROM threat_intel_ips WHERE ip LIKE '%/%' GROUP BY source_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		counts[id] = n
	}
	return counts, rows.Err()
}

func (db *DB) AddThreatIntelSource(label, url string, intervalHours int) error {
	_, err := db.exec(
		`INSERT INTO threat_intel_sources (label, url, interval_hours) VALUES (?, ?, ?)`,
		label, url, intervalHours,
	)
	return err
}

func (db *DB) DeleteThreatIntelSource(id int64) error {
	if _, err := db.exec(`DELETE FROM threat_intel_sources WHERE id = ?`, id); err != nil {
		return err
	}
	return db.setThreatIntelKey(id, "")
}

func (db *DB) SetThreatIntelSourceEnabled(id int64, enabled bool) error {
	_, err := db.exec(
		`UPDATE threat_intel_sources SET enabled = ? WHERE id = ?`, boolToInt(enabled), id,
	)
	return err
}

func (db *DB) ListThreatIntelSources() ([]ThreatIntelSource, error) {
	rows, err := db.query(`
		SELECT id, label, url, interval_hours, enabled,
		       last_synced_at, last_error, ip_count, created_at
		FROM threat_intel_sources ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []ThreatIntelSource
	for rows.Next() {
		var s ThreatIntelSource
		var enabled int
		var lastSyncedStr string
		if err := rows.Scan(&s.ID, &s.Label, &s.URL, &s.IntervalHours, &enabled,
			&lastSyncedStr, &s.LastError, &s.IPCount, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		if lastSyncedStr != "" {
			s.LastSyncedAt = parseTS(lastSyncedStr)
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

// UpdateThreatIntelSync records the outcome of a sync run. On error only the
// timestamp and error message are updated; ip_count is left at its last good
// value so the UI still shows how many IPs were loaded from the previous run.
func (db *DB) UpdateThreatIntelSync(id int64, ipCount int, lastError string) error {
	if lastError != "" {
		_, err := db.exec(
			`UPDATE threat_intel_sources SET last_synced_at = ?, last_error = ? WHERE id = ?`,
			time.Now().UTC(), lastError, id,
		)
		return err
	}
	_, err := db.exec(
		`UPDATE threat_intel_sources SET last_synced_at = ?, last_error = '', ip_count = ? WHERE id = ?`,
		time.Now().UTC(), ipCount, id,
	)
	return err
}

// ReplaceThreatIntelIPs atomically replaces all IPs for a source in a single
// transaction so the blocklist never sees a partial update.
func (db *DB) ReplaceThreatIntelIPs(sourceID int64, ips []string) error {
	tx, err := db.conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	if _, err := tx.ExecContext(context.Background(), db.conn.Rebind(`DELETE FROM threat_intel_ips WHERE source_id = ?`), sourceID); err != nil {
		return err
	}
	insertStmt := db.dialect.upsertIgnore("threat_intel_ips", []string{"source_id", "ip"}, "?, ?", []string{"source_id", "ip"})
	stmt, err := tx.PrepareContext(context.Background(), db.conn.Rebind(insertStmt))
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, ip := range ips {
		if _, err := stmt.ExecContext(context.Background(), sourceID, ip); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListThreatIntelIPs returns all distinct IPs/CIDRs from enabled feed
// sources. Used by IPBlocklist.ReloadIntel to populate the in-memory intel
// block set.
func (db *DB) ListThreatIntelIPs() ([]string, error) {
	return db.listIntelIPs(`NOT LIKE`)
}

// ListCrowdSecIPs is ListThreatIntelIPs for enabled CrowdSec sources.
func (db *DB) ListCrowdSecIPs() ([]string, error) {
	return db.listIntelIPs(`LIKE`)
}

func (db *DB) listIntelIPs(like string) ([]string, error) {
	rows, err := db.query(`
		SELECT DISTINCT ti.ip
		FROM threat_intel_ips ti
		JOIN threat_intel_sources ts ON ti.source_id = ts.id
		WHERE ts.enabled = 1 AND ts.url `+like+` ?`, CrowdSecPrefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}
