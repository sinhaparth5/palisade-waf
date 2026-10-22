package storage

import "time"

// AuditEntry is one admin action: a successful state-changing request to
// the admin UI or REST API.
type AuditEntry struct {
	ID      int
	TS      time.Time
	Actor   string // "admin" (session) or "api key <name> (<prefix>)"
	IP      string
	Action  string // method + route pattern, e.g. "DELETE /ip-rules/:id"
	Target  string // route params, e.g. "id=12"
	Summary string // allowlisted, non-secret form/JSON fields
}

// AuditRetentionDays is the floor on how long audit rows are kept: admin
// actions are rare and small, and a trail shorter than the request-log
// retention would be too short to investigate anything.
const AuditRetentionDays = 365

func (db *DB) InsertAudit(e AuditEntry) error {
	_, err := db.exec(
		`INSERT INTO audit_log (ts, actor, ip, action, target, summary) VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().UTC(), e.Actor, e.IP, e.Action, e.Target, e.Summary,
	)
	return err
}

// ListAudit returns one page of entries, newest first, plus the total count.
func (db *DB) ListAudit(limit, offset int) ([]AuditEntry, int, error) {
	var total int
	if err := db.queryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.query(
		`SELECT id, ts, actor, ip, action, target, summary FROM audit_log ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Summary); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// PruneAudit deletes audit rows older than days and returns how many went.
// Unbatched, unlike PruneOldRequests: the table grows by admin clicks, not
// traffic.
func (db *DB) PruneAudit(days int) (int64, error) {
	res, err := db.exec(`DELETE FROM audit_log WHERE ts < ?`, time.Now().UTC().AddDate(0, 0, -days))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
