package storage

import (
	"fmt"
	"time"
)

// ── Webhook ───────────────────────────────────────────────────────────────────

// WebhookConfig is stored in the singleton webhook_config row (id=1).
type WebhookConfig struct {
	URL             string
	Secret          string // sent as X-WAF-Secret header value
	Enabled         bool
	Events          string // comma-separated event categories: "blocked", "challenged"
	DestinationType string // "generic" (default, unchanged JSON body), "slack" (Block Kit), "discord" (embeds)
}

// webhookDestinationTypes is the allowed set for WebhookConfig.DestinationType.
// Anything else (empty, typo, a value from a future version rolled back) is
// normalized to "generic" — the original unformatted-JSON behavior — rather
// than silently failing to deliver.
var webhookDestinationTypes = map[string]bool{
	"generic": true,
	"slack":   true,
	"discord": true,
}

func (db *DB) GetWebhookConfig() (WebhookConfig, error) {
	var cfg WebhookConfig
	var enabled int
	err := db.queryRow(
		`SELECT url, secret, enabled, events, destination_type FROM webhook_config WHERE id = 1`,
	).Scan(&cfg.URL, &cfg.Secret, &enabled, &cfg.Events, &cfg.DestinationType)
	if err != nil {
		return WebhookConfig{}, err
	}
	cfg.Enabled = enabled == 1
	if !webhookDestinationTypes[cfg.DestinationType] {
		cfg.DestinationType = "generic"
	}
	if cfg.Secret, err = db.openSecret(cfg.Secret); err != nil {
		return WebhookConfig{}, fmt.Errorf("webhook secret: %w", err)
	}
	return cfg, nil
}

func (db *DB) SetWebhookConfig(cfg WebhookConfig) error {
	sealed, err := db.sealSecret(cfg.Secret)
	if err != nil {
		return err
	}
	if !webhookDestinationTypes[cfg.DestinationType] {
		cfg.DestinationType = "generic"
	}
	_, err = db.exec(
		`UPDATE webhook_config SET url=?, secret=?, enabled=?, events=?, destination_type=? WHERE id=1`,
		cfg.URL, sealed, boolToInt(cfg.Enabled), cfg.Events, cfg.DestinationType,
	)
	return err
}

// ── Email alerts ──────────────────────────────────────────────────────────────

// EmailConfig holds the daily-report email settings. Delivery is
// Cloudflare-only — host, port, username and sender address are hardcoded in
// the mailer package; only the recipient list and the API token are
// configurable. Stored in the meta table and managed from the admin UI — the
// token never lives in the binary.
type EmailConfig struct {
	Enabled bool
	Token   string // Cloudflare API token with Email Sending: Edit (SMTP password)
	To      string // comma-separated recipient list
}

func (db *DB) GetEmailConfig() (EmailConfig, error) {
	var cfg EmailConfig
	enabled, err := db.getMeta("email_enabled")
	if err != nil {
		return EmailConfig{}, err
	}
	cfg.Enabled = enabled == "1"
	if cfg.Token, err = db.getSecretMeta("email_token"); err != nil {
		return EmailConfig{}, err
	}
	if cfg.To, err = db.getMeta("email_to"); err != nil {
		return EmailConfig{}, err
	}
	return cfg, nil
}

func (db *DB) SetEmailConfig(cfg EmailConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	for key, val := range map[string]string{
		"email_enabled": enabled,
		"email_to":      cfg.To,
	} {
		if err := db.setMeta(key, val); err != nil {
			return err
		}
	}
	return db.setSecretMeta("email_token", cfg.Token)
}

// GetEmailReportSentFor returns the day ("2006-01-02") the last daily report
// was sent for, so a restart shortly after midnight doesn't send a duplicate.
func (db *DB) GetEmailReportSentFor() (string, error) {
	return db.getMeta("email_report_sent_for")
}

func (db *DB) SetEmailReportSentFor(day string) error {
	return db.setMeta("email_report_sent_for", day)
}

// DailyReport aggregates one reporting window of the requests table for the
// daily alert email.
type DailyReport struct {
	Total            int // all requests in the window
	Blocked          int // requests blocked by any stage
	Status403        int // requests answered with HTTP 403
	UniqueBlockedIPs int // distinct client IPs that had at least one block
	WAFBlocked       int // blocked by a Coraza rule
	IPBlocked        int // blocked by the IP blocklist (manual or threat intel)
	GeoBlocked       int // blocked by a geo rule
	RateLimited      int // rejected by a rate limiter
	BotChallenged    int // served the JS proof-of-work challenge
}

// GetDailyReport crunches [from, to) in a single pass. Time bounds are plain
// comparisons against ts — never SQLite date functions, which can't parse the
// Go time format modernc/sqlite stores (see GetHourlyTraffic).
func (db *DB) GetDailyReport(from, to time.Time) (DailyReport, error) {
	var rep DailyReport
	err := db.queryRow(`
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 403 THEN 1 ELSE 0 END), 0),
		       COUNT(DISTINCT CASE WHEN blocked = 1 THEN real_ip END),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND rule_id > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND action LIKE 'ip_blocked%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND action LIKE 'geo_blocked%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND action LIKE 'rate_limited%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action LIKE 'bot_challenge%' THEN 1 ELSE 0 END), 0)
		FROM requests WHERE ts >= ? AND ts < ?`,
		from.UTC(), to.UTC(),
	).Scan(&rep.Total, &rep.Blocked, &rep.Status403, &rep.UniqueBlockedIPs,
		&rep.WAFBlocked, &rep.IPBlocked, &rep.GeoBlocked, &rep.RateLimited, &rep.BotChallenged)
	return rep, err
}

// LabelCount is one row of a top-N breakdown.
type LabelCount struct {
	Label string
	Count int
}

// ReportDetails is the chart and top-N data behind the daily report email.
// Kept apart from DailyReport so the dashboard, which also reads
// DailyReport, doesn't pay for these queries.
type ReportDetails struct {
	Hourly       []HourlyPoint // one bucket per hour of [from, to), gaps zero-filled
	TopCountries []LabelCount  // blocked requests by country
	TopIPs       []LabelCount  // blocked requests by client IP
	TopRules     []LabelCount  // blocked requests by WAF rule ID
}

// GetReportDetails buckets [from, to) by hour (in Go, see GetHourlyTraffic)
// and returns the top `limit` blocked countries, IPs and WAF rules.
func (db *DB) GetReportDetails(from, to time.Time, limit int) (ReportDetails, error) {
	var d ReportDetails
	d.Hourly = make([]HourlyPoint, int(to.Sub(from)/time.Hour))
	for i := range d.Hourly {
		d.Hourly[i].Hour = from.Add(time.Duration(i) * time.Hour)
	}
	rows, err := db.query(`SELECT ts, blocked FROM requests WHERE ts >= ? AND ts < ?`, from.UTC(), to.UTC())
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var ts time.Time
		var blocked int
		if err := rows.Scan(&ts, &blocked); err != nil {
			return d, err
		}
		if i := int(ts.Sub(from) / time.Hour); i >= 0 && i < len(d.Hourly) {
			d.Hourly[i].Total++
			d.Hourly[i].Blocked += blocked
		}
	}
	if err := rows.Err(); err != nil {
		return d, err
	}

	// col is one of three fixed literals below, never caller input.
	top := func(col, cond string) ([]LabelCount, error) {
		rows, err := db.query(`SELECT `+col+`, COUNT(*) AS c FROM requests
			WHERE blocked = 1 AND ts >= ? AND ts < ? AND `+cond+`
			GROUP BY `+col+` ORDER BY c DESC LIMIT ?`, from.UTC(), to.UTC(), limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []LabelCount
		for rows.Next() {
			var lc LabelCount
			if err := rows.Scan(&lc.Label, &lc.Count); err != nil {
				return nil, err
			}
			out = append(out, lc)
		}
		return out, rows.Err()
	}
	if d.TopCountries, err = top("country", "country != ''"); err != nil {
		return d, err
	}
	if d.TopIPs, err = top("real_ip", "real_ip != ''"); err != nil {
		return d, err
	}
	d.TopRules, err = top("rule_id", "rule_id > 0")
	return d, err
}
