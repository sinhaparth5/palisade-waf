package storage

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ── IP rules ─────────────────────────────────────────────────────────────────

type IPRule struct {
	ID        int
	AppName   string // "" = global
	IP        string
	RuleType  string // "block" | "allow"
	Note      string // "" for manual rules; ban reason for auto-banned IPs
	CreatedAt time.Time
}

// Auto reports whether this rule was created by the automatic IP banner
// (rather than entered by an admin). Used by the IP Rules page template.
func (r IPRule) Auto() bool { return strings.HasPrefix(r.Note, "Auto-banned") }

func (db *DB) AddIPRule(appName, ip, ruleType string) error {
	return db.AddIPRuleWithNote(appName, ip, ruleType, "")
}

// AddIPRuleWithNote upserts an IP rule carrying a note (shown on the IP Rules
// page). The autoban package uses the note to record why an IP was banned.
func (db *DB) AddIPRuleWithNote(appName, ip, ruleType, note string) error {
	_, err := db.exec(
		db.dialect.upsertUpdate("ip_rules", []string{"app_name", "ip", "rule_type", "note"}, "?, ?, ?, ?",
			[]string{"app_name", "ip"}, []string{"rule_type", "note"}),
		appName, ip, ruleType, note,
	)
	return err
}

// GetIPRuleType returns the rule type ("block" or "allow") for an exact
// app+IP pair, or "" when no rule exists. The autoban package checks this
// before banning so an admin allow rule (or an existing ban) is never
// overwritten.
func (db *DB) GetIPRuleType(appName, ip string) (string, error) {
	var rt string
	err := db.queryRow(
		`SELECT rule_type FROM ip_rules WHERE app_name = ? AND ip = ?`, appName, ip,
	).Scan(&rt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return rt, err
}

func (db *DB) RemoveIPRule(id int) error {
	_, err := db.exec(`DELETE FROM ip_rules WHERE id = ?`, id)
	return err
}

func (db *DB) ListIPRules() ([]IPRule, error) {
	rows, err := db.query(
		`SELECT id, app_name, ip, rule_type, note, created_at FROM ip_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []IPRule
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.AppName, &r.IP, &r.RuleType, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ListIPRulesPaginated returns one page of rules (newest first) plus the
// total row count, mirroring ListRequestsFiltered's "COUNT then SELECT ...
// LIMIT ? OFFSET ?" shape — used by the IP Rules admin page so a large,
// autoban-grown ip_rules table is never pulled into memory in one query.
func (db *DB) ListIPRulesPaginated(limit, offset int) ([]IPRule, int, error) {
	var total int
	if err := db.queryRow(`SELECT COUNT(*) FROM ip_rules`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.query(
		`SELECT id, app_name, ip, rule_type, note, created_at FROM ip_rules ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []IPRule
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.AppName, &r.IP, &r.RuleType, &r.Note, &r.CreatedAt); err != nil {
			return nil, 0, err
		}
		rules = append(rules, r)
	}
	return rules, total, rows.Err()
}

// CountIPRulesByType returns the global block/allow counts across the whole
// ip_rules table (not just the current page) — used for the IP Rules page's
// "Rules overview" percentages, which must reflect the full table regardless
// of which page is currently displayed.
func (db *DB) CountIPRulesByType() (blockCount, allowCount int, err error) {
	rows, err := db.query(`SELECT rule_type, COUNT(*) FROM ip_rules GROUP BY rule_type`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var ruleType string
		var n int
		if err := rows.Scan(&ruleType, &n); err != nil {
			return 0, 0, err
		}
		if ruleType == "block" {
			blockCount = n
		} else {
			allowCount = n
		}
	}
	return blockCount, allowCount, rows.Err()
}
