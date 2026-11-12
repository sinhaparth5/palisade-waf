package storage

import "strings"

// SetServiceCookiePolicy turns Set-Cookie hardening on for a service, with
// the cookie names to leave alone (issue #281); on=false removes the row.
func (db *DB) SetServiceCookiePolicy(id int, on bool, exempt []string) error {
	if !on {
		_, err := db.exec(`DELETE FROM service_cookie_policy WHERE service_id = ?`, id)
		return err
	}
	_, err := db.exec(db.dialect.upsertUpdate("service_cookie_policy", []string{"service_id", "exempt"}, "?, ?",
		[]string{"service_id"}, []string{"exempt"}), id, strings.Join(exempt, " "))
	return err
}

// ListServiceCookiePolicies returns the exempt cookie names of every service
// with hardening on, by service id.
func (db *DB) ListServiceCookiePolicies() (map[int][]string, error) {
	rows, err := db.query(`SELECT service_id, exempt FROM service_cookie_policy`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int][]string{}
	for rows.Next() {
		var id int
		var exempt string
		if err := rows.Scan(&id, &exempt); err != nil {
			return nil, err
		}
		out[id] = strings.Fields(exempt)
	}
	return out, rows.Err()
}

func migrateServiceCookiePolicyTable(source, target *DB, _ bool) (int, error) {
	all, err := source.ListServiceCookiePolicies()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, exempt := range all {
		if err := target.SetServiceCookiePolicy(id, true, exempt); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
