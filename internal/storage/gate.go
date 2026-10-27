package storage

import (
	"time"
)

// ServiceGate is a service's maintenance mode and waiting room (issue #198).
// The zero value is both off.
type ServiceGate struct {
	Maintenance bool
	MaintMsg    string
	// MaintStart/MaintEnd bound maintenance in time; zero means open-ended.
	// Past MaintEnd it turns itself off without anyone saving the form.
	MaintStart time.Time
	MaintEnd   time.Time
	// BypassToken lets the team through during maintenance: visiting any
	// URL with ?palisade_bypass=<token> sets a cookie. "" = no bypass.
	BypassToken string

	WaitingRoom bool
	MaxActive   int    // concurrently admitted visitors
	IdleSecs    int    // an admitted visitor's slot frees after this much inactivity
	WaitMsg     string // shown on the queue page
	Crawlers    string // verified crawlers: "bypass" (default) or "deny" (503)
}

// MaintenanceActive reports whether maintenance applies at now.
func (g ServiceGate) MaintenanceActive(now time.Time) bool {
	return g.Maintenance && (g.MaintStart.IsZero() || !now.Before(g.MaintStart)) &&
		(g.MaintEnd.IsZero() || now.Before(g.MaintEnd))
}

// IdleMins is IdleSecs as the form shows it.
func (g ServiceGate) IdleMins() int { return g.IdleSecs / 60 }

// gateTime stores a schedule bound as RFC 3339 text, "" for none: TEXT keeps
// the zero value out of every dialect's DATETIME range checks.
func gateTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseGateTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

const gateColumns = `maintenance, maint_message, maint_start, maint_end, bypass_token, waiting_room, wr_max, wr_idle, wr_message, wr_crawlers`

// SetServiceGate stores a service's maintenance and waiting room settings.
func (db *DB) SetServiceGate(id int, g ServiceGate) error {
	cols := []string{"service_id", "maintenance", "maint_message", "maint_start", "maint_end", "bypass_token",
		"waiting_room", "wr_max", "wr_idle", "wr_message", "wr_crawlers"}
	_, err := db.exec(db.dialect.upsertUpdate("service_gate", cols, placeholders(len(cols)), []string{"service_id"}, cols[1:]),
		id, boolToInt(g.Maintenance), g.MaintMsg, gateTime(g.MaintStart), gateTime(g.MaintEnd), g.BypassToken,
		boolToInt(g.WaitingRoom), g.MaxActive, g.IdleSecs, g.WaitMsg, g.Crawlers)
	return err
}

// ListServiceGates returns every stored gate by service id.
func (db *DB) ListServiceGates() (map[int]ServiceGate, error) {
	rows, err := db.query(`SELECT service_id, ` + gateColumns + ` FROM service_gate`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]ServiceGate{}
	for rows.Next() {
		var id int
		var g ServiceGate
		var start, end string
		if err := rows.Scan(&id, &g.Maintenance, &g.MaintMsg, &start, &end, &g.BypassToken,
			&g.WaitingRoom, &g.MaxActive, &g.IdleSecs, &g.WaitMsg, &g.Crawlers); err != nil {
			return nil, err
		}
		g.MaintStart, g.MaintEnd = parseGateTime(start), parseGateTime(end)
		out[id] = g
	}
	return out, rows.Err()
}

func migrateServiceGateTable(source, target *DB, _ bool) (int, error) {
	gates, err := source.ListServiceGates()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, g := range gates {
		if err := target.SetServiceGate(id, g); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
