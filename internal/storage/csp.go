package storage

import "time"

// CSPScript is one script source a service's report-only CSP has reported
// (issue #235): an origin such as https://cdn.example.com, or a keyword
// such as "inline" or "eval".
type CSPScript struct {
	Origin    string
	Page      string // document path of the first report
	FirstSeen time.Time
}

// SetServiceCSP stores a service's report-only CSP; "" turns it off. The
// inventory is kept, so turning it back on doesn't re-alert.
func (db *DB) SetServiceCSP(id int, policy string) error {
	if policy == "" {
		_, err := db.exec(`DELETE FROM service_csp WHERE service_id = ?`, id)
		return err
	}
	_, err := db.exec(db.dialect.upsertUpdate("service_csp", []string{"service_id", "policy"}, "?, ?",
		[]string{"service_id"}, []string{"policy"}), id, policy)
	return err
}

// ListServiceCSP returns every service's report-only policy by service id.
func (db *DB) ListServiceCSP() (map[int]string, error) {
	rows, err := db.query(`SELECT service_id, policy FROM service_csp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var id int
		var p string
		if err := rows.Scan(&id, &p); err != nil {
			return nil, err
		}
		out[id] = p
	}
	return out, rows.Err()
}

// AddCSPScript records a script source for a service and reports whether it
// was new.
func (db *DB) AddCSPScript(id int, s CSPScript) (bool, error) {
	res, err := db.exec(db.dialect.upsertIgnore("csp_scripts", []string{"service_id", "origin", "page", "first_seen"}, "?, ?, ?, ?",
		[]string{"service_id", "origin"}), id, s.Origin, s.Page, s.FirstSeen)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ListCSPScripts returns every service's script inventory by service id,
// oldest first.
func (db *DB) ListCSPScripts() (map[int][]CSPScript, error) {
	rows, err := db.query(`SELECT service_id, origin, page, first_seen FROM csp_scripts ORDER BY first_seen, origin`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int][]CSPScript{}
	for rows.Next() {
		var id int
		var s CSPScript
		if err := rows.Scan(&id, &s.Origin, &s.Page, &s.FirstSeen); err != nil {
			return nil, err
		}
		out[id] = append(out[id], s)
	}
	return out, rows.Err()
}

func migrateServiceCSPTable(source, target *DB, _ bool) (int, error) {
	policies, err := source.ListServiceCSP()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, p := range policies {
		if err := target.SetServiceCSP(id, p); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func migrateCSPScriptsTable(source, target *DB, _ bool) (int, error) {
	all, err := source.ListCSPScripts()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, list := range all {
		for _, s := range list {
			if _, err := target.AddCSPScript(id, s); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}
