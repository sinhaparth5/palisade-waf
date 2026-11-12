package storage

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ── Threat score ──────────────────────────────────────────────────────────────
//
// Unified per-IP threat-intelligence score (issue #12) — a composite read
// model combining autoban history, bot score, ASN/hosting classification,
// geo risk, and JA4 repeat-offender history. Computed incrementally by
// internal/security/threatscore.Scorer.Record, registered via
// SetThreatScoreFn like every other log-worker fan-out hook. Distinct from
// the unrelated internal/security/threatintel package (external IP
// block-list sync) despite the similar name.

// IPThreatScore is one row in ip_threat_scores: the latest composite score
// for an IP plus the per-signal breakdown that produced it, so the admin UI
// can show *why* an IP scored what it did, not just the total.
type IPThreatScore struct {
	IP           string
	Total        int
	AutobanScore int
	BotScore     int
	ASNScore     int
	GeoScore     int
	JA4Score     int
	UpdatedAt    time.Time
}

// UpsertIPThreatScore stores s's latest composite score, replacing any
// previous score for the same IP.
func (db *DB) UpsertIPThreatScore(s IPThreatScore) error {
	cols := []string{"ip", "total_score", "autoban_score", "bot_score", "asn_score", "geo_score", "ja4_score", "updated_at"}
	updateCols := []string{"total_score", "autoban_score", "bot_score", "asn_score", "geo_score", "ja4_score", "updated_at"}
	_, err := db.exec(
		upsertUpdate("ip_threat_scores", cols, "?, ?, ?, ?, ?, ?, ?, ?", []string{"ip"}, updateCols),
		s.IP, s.Total, s.AutobanScore, s.BotScore, s.ASNScore, s.GeoScore, s.JA4Score, s.UpdatedAt.UTC(),
	)
	return err
}

// GetIPThreatScore returns ip's latest composite score. The second return
// value is false if no score has been recorded for ip yet.
func (db *DB) GetIPThreatScore(ip string) (IPThreatScore, bool, error) {
	var s IPThreatScore
	s.IP = ip
	err := db.queryRow(
		`SELECT total_score, autoban_score, bot_score, asn_score, geo_score, ja4_score, updated_at
		 FROM ip_threat_scores WHERE ip = ?`, ip,
	).Scan(&s.Total, &s.AutobanScore, &s.BotScore, &s.ASNScore, &s.GeoScore, &s.JA4Score, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return IPThreatScore{}, false, nil
	}
	if err != nil {
		return IPThreatScore{}, false, err
	}
	return s, true, nil
}

// GetIPThreatScores returns the total score for every IP in ips that has
// one on record, keyed by IP. IPs with no recorded score are simply absent
// from the result rather than reported as zero. A single bulk query, used by
// the IP Rules page to avoid an N+1 lookup per row.
func (db *DB) GetIPThreatScores(ips []string) (map[string]int, error) {
	out := make(map[string]int, len(ips))
	if len(ips) == 0 {
		return out, nil
	}

	placeholders := strings.Repeat("?,", len(ips))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ips))
	for i, ip := range ips {
		args[i] = ip
	}

	rows, err := db.query(
		`SELECT ip, total_score FROM ip_threat_scores WHERE ip IN (`+placeholders+`)`, args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var score int
		if err := rows.Scan(&ip, &score); err != nil {
			return nil, err
		}
		out[ip] = score
	}
	return out, rows.Err()
}

// BumpJA4Reputation records one observed request for ja4 (a hit, and a
// blocked hit if blocked is true) and returns the fingerprint's updated
// lifetime totals. Used to track JA4 fingerprints that keep showing up on
// blocked traffic across many IPs/connections — the ja4 package's own store
// is connection-scoped and forgets fingerprints as soon as the connection
// closes.
func (db *DB) BumpJA4Reputation(ja4 string, blocked bool) (hits, blockedHits int, err error) {
	blockedInc := 0
	if blocked {
		blockedInc = 1
	}
	_, err = db.exec(
		`INSERT INTO ja4_reputation (ja4, hits, blocked_hits, last_seen) VALUES (?, 1, ?, ?)
		 ON CONFLICT(ja4) DO UPDATE SET
		   hits = hits + 1,
		   blocked_hits = blocked_hits + ?,
		   last_seen = excluded.last_seen`,
		ja4, blockedInc, time.Now().UTC(), blockedInc,
	)
	if err != nil {
		return 0, 0, err
	}
	err = db.queryRow(
		`SELECT hits, blocked_hits FROM ja4_reputation WHERE ja4 = ?`, ja4,
	).Scan(&hits, &blockedHits)
	return hits, blockedHits, err
}
