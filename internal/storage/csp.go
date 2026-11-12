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

// CSPEnforcement is a service's enforce switch and approved inventory
// entries (issue #283).
type CSPEnforcement struct {
	Enforce  bool
	Approved []string // csp_scripts origins
}

// SetCSPEnforcement replaces a service's approved sources and enforce flag.
func (db *DB) SetCSPEnforcement(id int, e CSPEnforcement) error {
	for _, t := range []string{"csp_approved", "service_csp_enforce"} {
		if _, err := db.exec(`DELETE FROM `+t+` WHERE service_id = ?`, id); err != nil {
			return err
		}
	}
	for _, o := range e.Approved {
		if _, err := db.exec(`INSERT INTO csp_approved (service_id, origin) VALUES (?, ?)`, id, o); err != nil {
			return err
		}
	}
	if e.Enforce {
		_, err := db.exec(`INSERT INTO service_csp_enforce (service_id) VALUES (?)`, id)
		return err
	}
	return nil
}

// ListCSPEnforcement returns every service's enforce flag and approved
// sources by service id.
func (db *DB) ListCSPEnforcement() (map[int]CSPEnforcement, error) {
	out := map[int]CSPEnforcement{}
	rows, err := db.query(`SELECT service_id, origin FROM csp_approved ORDER BY origin`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var o string
		if err := rows.Scan(&id, &o); err != nil {
			return nil, err
		}
		e := out[id]
		e.Approved = append(e.Approved, o)
		out[id] = e
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids, err := db.query(`SELECT service_id FROM service_csp_enforce`)
	if err != nil {
		return nil, err
	}
	defer ids.Close()
	for ids.Next() {
		var id int
		if err := ids.Scan(&id); err != nil {
			return nil, err
		}
		e := out[id]
		e.Enforce = true
		out[id] = e
	}
	return out, ids.Err()
}

func migrateCSPApprovedTable(source, target *DB, _ bool) (int, error) {
	all, err := source.ListCSPEnforcement()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, e := range all {
		for _, o := range e.Approved {
			if _, err := target.exec(`INSERT INTO csp_approved (service_id, origin) VALUES (?, ?)`, id, o); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func migrateCSPEnforceTable(source, target *DB, _ bool) (int, error) {
	all, err := source.ListCSPEnforcement()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, e := range all {
		if e.Enforce {
			if _, err := target.exec(`INSERT INTO service_csp_enforce (service_id) VALUES (?)`, id); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}
