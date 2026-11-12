package storage

import (
	"database/sql"
	"strconv"
	"time"
)

// ── WAF disabled rules ────────────────────────────────────────────────────────

// DisabledWAFRule is one row from the waf_disabled_rules table.
type DisabledWAFRule struct {
	ID        int64
	RuleID    int
	Reason    string
	CreatedAt time.Time
}

// RuleHit summarises how often a particular WAF rule has fired in request logs.
type RuleHit struct {
	RuleID   int
	HitCount int
	LastSeen time.Time
	Disabled bool // true if the rule is currently in waf_disabled_rules
}

// DisableWAFRule adds (or updates the reason for) a disabled rule.
func (db *DB) DisableWAFRule(ruleID int, reason string) error {
	_, err := db.exec(
		upsertUpdate("waf_disabled_rules", []string{"rule_id", "reason"}, "?, ?",
			[]string{"rule_id"}, []string{"reason"}),
		ruleID, reason,
	)
	return err
}

// EnableWAFRule removes a disabled rule by its row ID.
func (db *DB) EnableWAFRule(id int64) error {
	_, err := db.exec(`DELETE FROM waf_disabled_rules WHERE id = ?`, id)
	return err
}

// ListDisabledWAFRules returns all disabled rules, newest first.
func (db *DB) ListDisabledWAFRules() ([]DisabledWAFRule, error) {
	rows, err := db.query(
		`SELECT id, rule_id, reason, created_at FROM waf_disabled_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []DisabledWAFRule
	for rows.Next() {
		var r DisabledWAFRule
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// GetDisabledWAFRuleIDs returns just the rule IDs of all disabled rules.
// Used by the WAF engine to inject SecRuleRemoveById directives at startup.
func (db *DB) GetDisabledWAFRuleIDs() ([]int, error) {
	rows, err := db.query(`SELECT rule_id FROM waf_disabled_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ── WAF custom rules (issue #112) ───────────────────────────────────────────

// WAFCustomRule is an admin-written SecRule (or chain) stored in the DB and
// compiled into the engine after CRS. ServiceName "" means every service.
type WAFCustomRule struct {
	ID          int64
	ServiceName string
	Rule        string
	Note        string
	Enabled     bool
	CreatedAt   time.Time
}

// SaveWAFCustomRule inserts r when r.ID is 0, otherwise updates its scope,
// text and note. Enabled is only set on insert; see SetWAFCustomRuleEnabled.
func (db *DB) SaveWAFCustomRule(r WAFCustomRule) error {
	if r.ID == 0 {
		_, err := db.exec(`INSERT INTO waf_custom_rules (service_name, rule, note, enabled) VALUES (?, ?, ?, ?)`,
			r.ServiceName, r.Rule, r.Note, boolToInt(r.Enabled))
		return err
	}
	res, err := db.exec(`UPDATE waf_custom_rules SET service_name = ?, rule = ?, note = ? WHERE id = ?`,
		r.ServiceName, r.Rule, r.Note, r.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) SetWAFCustomRuleEnabled(id int64, enabled bool) error {
	_, err := db.exec(`UPDATE waf_custom_rules SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	return err
}

func (db *DB) DeleteWAFCustomRule(id int64) error {
	_, err := db.exec(`DELETE FROM waf_custom_rules WHERE id = ?`, id)
	return err
}

// ListWAFCustomRules returns every custom rule, oldest first, which is also
// the order they are loaded into the engine.
func (db *DB) ListWAFCustomRules() ([]WAFCustomRule, error) {
	rows, err := db.query(`SELECT id, service_name, rule, note, enabled, created_at FROM waf_custom_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []WAFCustomRule
	for rows.Next() {
		var r WAFCustomRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.ServiceName, &r.Rule, &r.Note, &enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ── WAF per-service rule exceptions ─────────────────────────────────────────
//
// A separate table rather than a service_name column on waf_disabled_rules:
// that table's rule_id column is UNIQUE (one row per rule ID, ever), so the
// same rule can't also have a service-scoped row without a constraint change
// SQLite can't do via ALTER TABLE. This mirrors the ip_threat_scores/
// ja4_reputation precedent — a new bolt-on table instead of reshaping an
// existing one.

// WAFServiceException is one row from the waf_service_rule_exceptions table:
// a CRS rule disabled for a single service rather than globally.
type WAFServiceException struct {
	ID          int64
	ServiceName string
	RuleID      int
	Reason      string
	CreatedAt   time.Time
}

// DisableWAFRuleForService adds (or updates the reason for) a rule exception
// scoped to one service.
func (db *DB) DisableWAFRuleForService(serviceName string, ruleID int, reason string) error {
	_, err := db.exec(
		upsertUpdate("waf_service_rule_exceptions", []string{"service_name", "rule_id", "reason"}, "?, ?, ?",
			[]string{"service_name", "rule_id"}, []string{"reason"}),
		serviceName, ruleID, reason,
	)
	return err
}

// EnableWAFRuleForService removes a per-service rule exception by its row ID.
func (db *DB) EnableWAFRuleForService(id int64) error {
	_, err := db.exec(`DELETE FROM waf_service_rule_exceptions WHERE id = ?`, id)
	return err
}

// ListWAFServiceExceptions returns all per-service rule exceptions, newest first.
func (db *DB) ListWAFServiceExceptions() ([]WAFServiceException, error) {
	rows, err := db.query(
		`SELECT id, service_name, rule_id, reason, created_at
		 FROM waf_service_rule_exceptions ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exceptions []WAFServiceException
	for rows.Next() {
		var e WAFServiceException
		if err := rows.Scan(&e.ID, &e.ServiceName, &e.RuleID, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		exceptions = append(exceptions, e)
	}
	return exceptions, rows.Err()
}

// GetWAFRuleIDsForService returns the rule IDs disabled specifically for
// serviceName. It does not include globally-disabled rules — callers union
// this with GetDisabledWAFRuleIDs themselves.
func (db *DB) GetWAFRuleIDsForService(serviceName string) ([]int, error) {
	rows, err := db.query(
		`SELECT rule_id FROM waf_service_rule_exceptions WHERE service_name = ?`, serviceName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListWAFExceptionServiceNames returns the distinct service names that have
// at least one per-service rule exception. Used to know which services need
// their own compiled WAF engine on top of the shared default one.
func (db *DB) ListWAFExceptionServiceNames() ([]string, error) {
	rows, err := db.query(`SELECT DISTINCT service_name FROM waf_service_rule_exceptions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// ── WAF rule feedback (issue #76) ───────────────────────────────────────────
//
// Suggestion-only signal collection: an admin marks a blocked request's rule
// as a false or true positive from the Logs page (MarkWAFRuleFeedback).
// GetWAFRuleSuggestions surfaces (service, rule) pairs with enough
// false-positive marks and no true-positive marks in a rolling window as a
// one-click "add exception" prompt on the WAF Rules page — it never disables
// a rule itself, only DisableWAFRule/DisableWAFRuleForService do that.

// MarkWAFRuleFeedback records one false/true-positive mark for a blocked
// request's rule, scoped to the service it hit (serviceName is "" for
// unmatched-host/global traffic, matching RequestLog.AppName).
func (db *DB) MarkWAFRuleFeedback(serviceName string, ruleID int, falsePositive bool) error {
	_, err := db.exec(
		`INSERT INTO waf_rule_feedback (service_name, rule_id, false_positive) VALUES (?, ?, ?)`,
		serviceName, ruleID, boolToInt(falsePositive),
	)
	return err
}

// WAFRuleFeedbackConfig controls the false-positive-mark threshold/window
// GetWAFRuleSuggestions uses. Stored in meta, mirrors AutobanConfig's shape.
type WAFRuleFeedbackConfig struct {
	Threshold  int // false-positive marks needed within the window, with zero true-positive marks
	WindowDays int // rolling window size
}

// DefaultWAFRuleFeedbackConfig is used when nothing is stored yet: suggest
// after 5 false-positive marks in 7 days.
func DefaultWAFRuleFeedbackConfig() WAFRuleFeedbackConfig {
	return WAFRuleFeedbackConfig{Threshold: 5, WindowDays: 7}
}

func (db *DB) GetWAFRuleFeedbackConfig() (WAFRuleFeedbackConfig, error) {
	cfg := DefaultWAFRuleFeedbackConfig()
	if v, err := db.getMeta("waf_feedback_threshold"); err != nil {
		return cfg, err
	} else if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Threshold = n
		}
	}
	if v, _ := db.getMeta("waf_feedback_window_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.WindowDays = n
		}
	}
	return cfg, nil
}

func (db *DB) SetWAFRuleFeedbackConfig(cfg WAFRuleFeedbackConfig) error {
	if err := db.setMeta("waf_feedback_threshold", strconv.Itoa(cfg.Threshold)); err != nil {
		return err
	}
	return db.setMeta("waf_feedback_window_days", strconv.Itoa(cfg.WindowDays))
}

// WAFRuleSuggestion is one (service, rule) pair with enough false-positive
// marks and no true-positive marks in the configured window to suggest
// adding an exception for it.
type WAFRuleSuggestion struct {
	ServiceName        string // "" = global/unmatched-host traffic
	RuleID             int
	FalsePositiveCount int
	LastMarked         time.Time
}

// GetWAFRuleSuggestions aggregates waf_rule_feedback within cfg.WindowDays
// and returns pairs at or above cfg.Threshold false-positive marks with zero
// true-positive marks in that same window, excluding any pair that already
// has an exception (global or per-service) — suggesting one for a rule
// that's already suppressed for that service would be a dead-end button.
func (db *DB) GetWAFRuleSuggestions(cfg WAFRuleFeedbackConfig) ([]WAFRuleSuggestion, error) {
	cutoff := time.Now().Add(-time.Duration(cfg.WindowDays) * 24 * time.Hour)
	rows, err := db.query(
		`SELECT service_name, rule_id,
		        SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) AS fp,
		        SUM(CASE WHEN false_positive = 0 THEN 1 ELSE 0 END) AS tp,
		        MAX(created_at) AS last_marked
		 FROM waf_rule_feedback
		 WHERE created_at >= ?
		 GROUP BY service_name, rule_id`,
		cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type ruleKey struct {
		service string
		ruleID  int
	}
	var candidates []WAFRuleSuggestion
	seen := make(map[ruleKey]bool)
	for rows.Next() {
		var svc string
		var ruleID, fp, tp int
		var lastMarkedStr string
		if err := rows.Scan(&svc, &ruleID, &fp, &tp, &lastMarkedStr); err != nil {
			return nil, err
		}
		if fp < cfg.Threshold || tp > 0 {
			continue
		}
		key := ruleKey{svc, ruleID}
		if seen[key] {
			continue
		}
		seen[key] = true
		candidates = append(candidates, WAFRuleSuggestion{
			ServiceName:        svc,
			RuleID:             ruleID,
			FalsePositiveCount: fp,
			LastMarked:         parseTS(lastMarkedStr),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	globalDisabled, err := db.GetDisabledWAFRuleIDs()
	if err != nil {
		return nil, err
	}
	globalSet := make(map[int]bool, len(globalDisabled))
	for _, id := range globalDisabled {
		globalSet[id] = true
	}
	exceptions, err := db.ListWAFServiceExceptions()
	if err != nil {
		return nil, err
	}
	exceptionSet := make(map[ruleKey]bool, len(exceptions))
	for _, e := range exceptions {
		exceptionSet[ruleKey{e.ServiceName, e.RuleID}] = true
	}

	var suggestions []WAFRuleSuggestion
	for _, c := range candidates {
		if globalSet[c.RuleID] || exceptionSet[ruleKey{c.ServiceName, c.RuleID}] {
			continue
		}
		suggestions = append(suggestions, c)
	}
	return suggestions, nil
}

// tsFormats lists the candidate layouts for parsing timestamps returned by
// SQLite aggregate functions (e.g. MAX(ts)). The driver stores time.Time
// values as strings internally; aggregate results come back as plain strings
// that database/sql won't auto-convert — see the CLAUDE.md SQLite date gotcha.
var tsFormats = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST", // Go time.String() with sub-seconds
	"2006-01-02 15:04:05 -0700 MST",           // Go time.String() exact seconds
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05",
}

func parseTS(s string) time.Time {
	for _, layout := range tsFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetRuleHitCounts returns how many logged blocks each rule id in
// [minID, maxID] caused, for the rules that caused any.
func (db *DB) GetRuleHitCounts(minID, maxID int) (map[int]int, error) {
	rows, err := db.query(
		`SELECT rule_id, COUNT(*) FROM requests WHERE rule_id BETWEEN ? AND ? AND blocked = 1 GROUP BY rule_id`,
		minID, maxID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hits := map[int]int{}
	for rows.Next() {
		var id, n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		hits[id] = n
	}
	return hits, rows.Err()
}

// GetTopFiringRules returns the most-blocked WAF rule IDs from request history,
// annotated with whether each rule is currently disabled.
func (db *DB) GetTopFiringRules(limit int) ([]RuleHit, error) {
	rows, err := db.query(
		`SELECT rule_id, COUNT(*) AS hit_count, MAX(ts) AS last_seen
		 FROM requests
		 WHERE rule_id > 0 AND blocked = 1
		 GROUP BY rule_id
		 ORDER BY hit_count DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hits []RuleHit
	for rows.Next() {
		var h RuleHit
		var lastSeenStr string
		if err := rows.Scan(&h.RuleID, &h.HitCount, &lastSeenStr); err != nil {
			return nil, err
		}
		h.LastSeen = parseTS(lastSeenStr)
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Mark which rules are currently disabled.
	disabled, _ := db.GetDisabledWAFRuleIDs()
	disabledSet := make(map[int]bool, len(disabled))
	for _, id := range disabled {
		disabledSet[id] = true
	}
	for i := range hits {
		hits[i].Disabled = disabledSet[hits[i].RuleID]
	}
	return hits, nil
}
