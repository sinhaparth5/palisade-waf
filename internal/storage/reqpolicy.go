package storage

import "strings"

// RequestPolicy is what a service accepts (issue #282): methods, request
// Content-Types and body size. Mode "" is off, "log" or "enforce".
type RequestPolicy struct {
	Mode         string
	Methods      []string // upper case; empty = any
	ContentTypes []string // lower-case media types, "type/*" allowed; empty = any
	MaxBodyKiB   int      // 0 = no limit
}

// SetServiceRequestPolicy stores a service's policy; Mode "" removes it.
func (db *DB) SetServiceRequestPolicy(id int, p RequestPolicy) error {
	if p.Mode == "" {
		_, err := db.exec(`DELETE FROM service_request_policy WHERE service_id = ?`, id)
		return err
	}
	_, err := db.exec(db.dialect.upsertUpdate("service_request_policy",
		[]string{"service_id", "mode", "methods", "content_types", "max_body_kib"}, "?, ?, ?, ?, ?",
		[]string{"service_id"}, []string{"mode", "methods", "content_types", "max_body_kib"}),
		id, p.Mode, strings.Join(p.Methods, " "), strings.Join(p.ContentTypes, " "), p.MaxBodyKiB)
	return err
}

// ListServiceRequestPolicies returns every stored policy by service id.
func (db *DB) ListServiceRequestPolicies() (map[int]RequestPolicy, error) {
	rows, err := db.query(`SELECT service_id, mode, methods, content_types, max_body_kib FROM service_request_policy`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]RequestPolicy{}
	for rows.Next() {
		var id int
		var p RequestPolicy
		var methods, types string
		if err := rows.Scan(&id, &p.Mode, &methods, &types, &p.MaxBodyKiB); err != nil {
			return nil, err
		}
		p.Methods, p.ContentTypes = strings.Fields(methods), strings.Fields(types)
		out[id] = p
	}
	return out, rows.Err()
}

func migrateServiceRequestPolicyTable(source, target *DB, _ bool) (int, error) {
	all, err := source.ListServiceRequestPolicies()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, p := range all {
		if err := target.SetServiceRequestPolicy(id, p); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
