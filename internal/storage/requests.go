package storage

import (
	"database/sql"
	"slices"
	"time"
)

const insertRequestSQL = `
		INSERT INTO requests
			(ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
			 status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
			 request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org,
			 ja3_hash, ja4, visitor_id, bot_score, cache_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func insertRequestArgs(r RequestLog) []any {
	return []any{
		r.Timestamp.UTC(),
		r.AppName,
		r.RealIP,
		r.ProxyIP,
		r.Country,
		r.Method,
		r.Host,
		r.Path,
		r.Query,
		r.Status,
		boolToInt(r.Blocked),
		r.RuleID,
		r.Action,
		r.UserAgent,
		r.Duration,
		r.HeadersJSON,
		r.RequestID,
		r.Proto,
		r.TLSVersion,
		r.TLSCipher,
		r.TLSSNI,
		r.ASN,
		r.Org,
		r.JA3Hash,
		r.JA4,
		r.VisitorID,
		r.BotScore,
		r.CacheStatus,
	}
}

// InsertRequest writes one request log entry and returns the new row ID.
func (db *DB) InsertRequest(r RequestLog) (int64, error) {
	return db.insertReturningID(insertRequestSQL, insertRequestArgs(r)...)
}

// CacheResult counts one service's Varnish verdicts (requests.cache_status)
// over a time window — the per-service view varnishstat can't give, since
// Varnish's own counters are global across every service sharing it.
type CacheResult struct {
	App    string
	Hits   int
	Misses int
	Passes int
	Errors int // Varnish failed; served from the backend (X-Cache: ERROR)
}

// CacheResultsSince groups cache verdicts per service for requests at or
// after since. Rows with no verdict (not cache-routed) are excluded.
func (db *DB) CacheResultsSince(since time.Time) ([]CacheResult, error) {
	rows, err := db.query(`
		SELECT app_name,
		       SUM(CASE WHEN cache_status = 'HIT'  THEN 1 ELSE 0 END),
		       SUM(CASE WHEN cache_status = 'MISS' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN cache_status = 'PASS' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN cache_status = 'ERROR' THEN 1 ELSE 0 END)
		FROM requests
		WHERE ts >= ? AND cache_status != ''
		GROUP BY app_name
		ORDER BY app_name`, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CacheResult
	for rows.Next() {
		var r CacheResult
		if err := rows.Scan(&r.App, &r.Hits, &r.Misses, &r.Passes, &r.Errors); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LogDetail is the full representation of one request log row, including
// headers and enrichment fields omitted from list queries for performance.
type LogDetail struct {
	ID          int
	Timestamp   time.Time
	AppName     string
	RealIP      string
	ProxyIP     string
	Country     string
	Method      string
	Host        string
	Path        string
	Query       string
	Status      int
	Blocked     bool
	RuleID      int
	Action      string
	UserAgent   string
	Duration    int64
	HeadersJSON string
	RequestID   string
	Proto       string
	TLSVersion  string
	TLSCipher   string
	TLSSNI      string
	ASN         uint
	Org         string
	JA3Hash     string
	JA4         string
	VisitorID   string
	BotScore    int
	CacheStatus string
}

// GetRequestByID fetches a single request log entry including all enrichment
// fields and headers. Returns sql.ErrNoRows when the id does not exist.
func (db *DB) GetRequestByID(id int) (*LogDetail, error) {
	var d LogDetail
	var blocked int
	err := db.queryRow(`
		SELECT id, ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
		       status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
		       request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org,
		       ja3_hash, ja4, visitor_id, bot_score, cache_status
		FROM requests WHERE id = ?`, id).Scan(
		&d.ID, &d.Timestamp, &d.AppName, &d.RealIP, &d.ProxyIP, &d.Country,
		&d.Method, &d.Host, &d.Path, &d.Query,
		&d.Status, &blocked, &d.RuleID, &d.Action, &d.UserAgent, &d.Duration,
		&d.HeadersJSON, &d.RequestID, &d.Proto, &d.TLSVersion, &d.TLSCipher,
		&d.TLSSNI, &d.ASN, &d.Org, &d.JA3Hash, &d.JA4, &d.VisitorID, &d.BotScore, &d.CacheStatus,
	)
	if err != nil {
		return nil, err
	}
	d.Blocked = blocked == 1
	return &d, nil
}

// ListReplayRequests returns the newest limit request rows with just the
// fields the WAF dry-run (issue #8) needs to rebuild each request, newest
// first. Bodies are never logged, so replay covers headers/URL only.
func (db *DB) ListReplayRequests(limit int) ([]RequestLog, error) {
	rows, err := db.query(
		`SELECT id, ts, app_name, real_ip, method, host, path, query, headers_json
		 FROM requests ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RequestLog
	for rows.Next() {
		var r RequestLog
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.AppName, &r.RealIP, &r.Method, &r.Host, &r.Path, &r.Query, &r.HeadersJSON); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Query helpers (used by dashboard later) ---

type Stats struct {
	TotalToday   int
	BlockedToday int
	TotalAll     int
	BlockedAll   int
}

// BotStats holds today's bot-challenge vs clean-pass counts.
type BotStats struct {
	ChallengedToday int // requests redirected to the JS PoW challenge today
	PassedToday     int // requests that reached a backend without being blocked today
}

// AtAGlanceStats contains the live metric strip values shown on the dashboard.
type AtAGlanceStats struct {
	RequestsLastMinute     int
	RequestsPrevMinute     int
	AvgLatencyMS           int
	PrevAvgLatencyMS       int
	BlockedLastMinute      int
	BlockedPrevMinute      int
	WAFRuleHitsToday       int
	WAFRuleHitsPreviousDay int
	UniqueVisitorsToday    int // distinct FingerprintJS visitor IDs since UTC midnight
	UniqueVisitorsPrevDay  int
}

// GetBotStats returns today's bot-challenge count alongside clean (unblocked)
// requests. Same UTC-midnight boundary trick as GetStats — no SQLite date funcs.
func (db *DB) GetBotStats() BotStats {
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var challenged, total, blocked int
	db.queryRow(
		`SELECT
			COALESCE(SUM(CASE WHEN action LIKE 'bot_challenge%' THEN 1 ELSE 0 END), 0),
			COUNT(*),
			COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0)
		FROM requests WHERE ts >= ?`, startOfDay,
	).Scan(&challenged, &total, &blocked) //nolint
	passed := total - blocked
	if passed < 0 {
		passed = 0
	}
	return BotStats{ChallengedToday: challenged, PassedToday: passed}
}

// GetStats computes today/all-time totals. "Today" is a UTC midnight
// boundary compared with a plain >= rather than SQLite's date()/strftime()
// functions: this driver stores time.Time using Go's default String()
// format ("... +0000 UTC"), which those functions can't parse and would
// silently return NULL (and therefore always-false) for every row.
func (db *DB) GetStats() (Stats, error) {
	var s Stats
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Three bounded queries instead of one pass over the whole table (#288):
	// today's rows by the ts index, the all-time counts from an index alone.
	if err := db.queryRow(`
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0)
		FROM requests WHERE ts >= ?`, startOfDay).Scan(&s.TotalToday, &s.BlockedToday); err != nil {
		return s, err
	}
	if err := db.queryRow(`SELECT COUNT(*) FROM requests`).Scan(&s.TotalAll); err != nil {
		return s, err
	}
	err := db.queryRow(`SELECT COUNT(*) FROM requests WHERE blocked = 1`).Scan(&s.BlockedAll)
	return s, err
}

// GetAtAGlanceStats computes compact dashboard metrics without SQLite date
// functions, because requests.ts is stored in Go's time.String() format.
func (db *DB) GetAtAGlanceStats() (AtAGlanceStats, error) {
	now := time.Now().UTC()
	thisMinute := now.Add(-1 * time.Minute)
	prevMinute := now.Add(-2 * time.Minute)
	thisLatency := now.Add(-5 * time.Minute)
	prevLatency := now.Add(-10 * time.Minute)
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	startOfPrevDay := startOfDay.Add(-24 * time.Hour)

	var s AtAGlanceStats
	var avgLatency, prevAvgLatency sql.NullFloat64
	err := db.queryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND ts < ? THEN 1 ELSE 0 END), 0),
			AVG(CASE WHEN ts >= ? THEN duration_ms END),
			AVG(CASE WHEN ts >= ? AND ts < ? THEN duration_ms END),
			COALESCE(SUM(CASE WHEN ts >= ? AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND ts < ? AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND rule_id > 0 AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND ts < ? AND rule_id > 0 AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT CASE WHEN ts >= ? AND visitor_id != '' THEN visitor_id END),
			COUNT(DISTINCT CASE WHEN ts >= ? AND ts < ? AND visitor_id != '' THEN visitor_id END)
		FROM requests WHERE ts >= ?`,
		thisMinute,
		prevMinute, thisMinute,
		thisLatency,
		prevLatency, thisLatency,
		thisMinute,
		prevMinute, thisMinute,
		startOfDay,
		startOfPrevDay, startOfDay,
		startOfDay,
		startOfPrevDay, startOfDay,
		startOfPrevDay, // nothing older is counted; lets the ts index bound the scan (#288)
	).Scan(
		&s.RequestsLastMinute,
		&s.RequestsPrevMinute,
		&avgLatency,
		&prevAvgLatency,
		&s.BlockedLastMinute,
		&s.BlockedPrevMinute,
		&s.WAFRuleHitsToday,
		&s.WAFRuleHitsPreviousDay,
		&s.UniqueVisitorsToday,
		&s.UniqueVisitorsPrevDay,
	)
	if err != nil {
		return AtAGlanceStats{}, err
	}
	if avgLatency.Valid {
		s.AvgLatencyMS = int(avgLatency.Float64 + 0.5)
	}
	if prevAvgLatency.Valid {
		s.PrevAvgLatencyMS = int(prevAvgLatency.Float64 + 0.5)
	}
	return s, nil
}

type LogRow struct {
	ID        int
	Timestamp time.Time
	AppName   string
	RealIP    string
	Country   string
	Method    string
	Host      string
	Path      string
	Status    int
	Blocked   bool
	RuleID    int
	Action    string
	UserAgent string
	Duration  int64
}

// ListRecentRequestLogs returns up to limit requests since the given time,
// oldest first. It seeds the Logs page's live Stats view, which then keeps
// counting from the SSE stream. The query is ORDER BY ts DESC so LIMIT keeps
// the most recent N within the window, then reversed in Go.
func (db *DB) ListRecentRequestLogs(since time.Time, limit int) ([]RequestLog, error) {
	rows, err := db.query(
		`SELECT id, ts, app_name, real_ip, country, method, path, status, blocked,
		        rule_id, action, user_agent, duration_ms, cache_status
		 FROM requests WHERE ts >= ? ORDER BY ts DESC LIMIT ?`,
		since.UTC(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RequestLog
	for rows.Next() {
		var r RequestLog
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.AppName, &r.RealIP, &r.Country, &r.Method, &r.Path, &r.Status,
			&r.Blocked, &r.RuleID, &r.Action, &r.UserAgent, &r.Duration, &r.CacheStatus); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// ListRequests returns paginated request logs, newest first.
// Optionally filter by blocked-only or IP.
func (db *DB) ListRequests(blockedOnly bool, ip string, limit, offset int) ([]LogRow, error) {
	query := `SELECT id, ts, app_name, real_ip, country, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms
	          FROM requests WHERE 1=1`
	args := []any{}

	if blockedOnly {
		query += " AND blocked = 1"
	}
	if ip != "" {
		query += " AND real_ip = ?"
		args = append(args, ip)
	}
	query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []LogRow
	for rows.Next() {
		var row LogRow
		var blocked int
		if err := rows.Scan(
			&row.ID, &row.Timestamp, &row.AppName, &row.RealIP, &row.Country,
			&row.Method, &row.Host, &row.Path, &row.Status,
			&blocked, &row.RuleID, &row.Action, &row.UserAgent, &row.Duration,
		); err != nil {
			return nil, err
		}
		row.Blocked = blocked == 1
		results = append(results, row)
	}
	return results, rows.Err()
}

// LogFilter describes the search/filter criteria for ListRequestsFiltered.
// Zero values mean "no constraint" for that field.
type LogFilter struct {
	From        time.Time // ts >= From, if non-zero
	To          time.Time // ts <= To, if non-zero
	AppName     string    // exact match, if non-empty
	IP          string    // exact real_ip match, if non-empty
	StatusClass string    // "" | "2xx" | "3xx" | "4xx" | "5xx" | "blocked" | "cache_error"
	Limit       int
	Offset      int
}

func (f LogFilter) where() (string, []any) {
	clause := "WHERE 1=1"
	args := []any{}

	if !f.From.IsZero() {
		clause += " AND ts >= ?"
		args = append(args, f.From.UTC())
	}
	if !f.To.IsZero() {
		clause += " AND ts <= ?"
		args = append(args, f.To.UTC())
	}
	if f.AppName != "" {
		clause += " AND app_name = ?"
		args = append(args, f.AppName)
	}
	if f.IP != "" {
		clause += " AND real_ip = ?"
		args = append(args, f.IP)
	}
	switch f.StatusClass {
	case "2xx":
		clause += " AND status >= 200 AND status < 300"
	case "3xx":
		clause += " AND status >= 300 AND status < 400"
	case "4xx":
		clause += " AND status >= 400 AND status < 500"
	case "5xx":
		clause += " AND status >= 500"
	case "blocked":
		clause += " AND blocked = 1"
	case "cache_error":
		clause += " AND cache_status = 'ERROR'"
	}
	return clause, args
}

// ListRequestsFiltered returns matching request logs (newest first) plus the
// total count of matching rows (ignoring Limit/Offset), for pagination.
func (db *DB) ListRequestsFiltered(f LogFilter) ([]LogRow, int, error) {
	clause, args := f.where()

	var total int
	if err := db.queryRow(`SELECT COUNT(*) FROM requests `+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, ts, app_name, real_ip, country, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms
	          FROM requests ` + clause + ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), f.Limit, f.Offset)

	rows, err := db.query(query, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []LogRow
	for rows.Next() {
		var row LogRow
		var blocked int
		if err := rows.Scan(
			&row.ID, &row.Timestamp, &row.AppName, &row.RealIP, &row.Country,
			&row.Method, &row.Host, &row.Path, &row.Status,
			&blocked, &row.RuleID, &row.Action, &row.UserAgent, &row.Duration,
		); err != nil {
			return nil, 0, err
		}
		row.Blocked = blocked == 1
		results = append(results, row)
	}
	return results, total, rows.Err()
}

// HourlyPoint is one bucket of traffic counts for the dashboard chart.
type HourlyPoint struct {
	Hour    time.Time
	Total   int
	Blocked int
}

// GetHourlyTraffic returns per-hour total/blocked counts for the last `hours`
// hours, newest bucket last. Hours with no traffic are omitted; callers
// should fill gaps with zero values for a continuous chart.
//
// Bucketing is done in Go rather than via SQLite's strftime(): this driver
// stores time.Time using Go's default String() format ("... +0000 UTC"),
// which strftime() can't parse and would silently group everything under a
// NULL bucket.
func (db *DB) GetHourlyTraffic(hours int) ([]HourlyPoint, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	// "blocked IN (0, 1)" is always true; it lets the (blocked, ts) index
	// answer the query without touching the table (#288). Buckets are sorted
	// below, so no ORDER BY.
	rows, err := db.query(`SELECT ts, blocked FROM requests WHERE blocked IN (0, 1) AND ts >= ?`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	buckets := make(map[time.Time]*HourlyPoint)
	var order []time.Time
	for rows.Next() {
		var ts time.Time
		var blocked int
		if err := rows.Scan(&ts, &blocked); err != nil {
			return nil, err
		}
		hour := ts.Truncate(time.Hour)
		p, ok := buckets[hour]
		if !ok {
			p = &HourlyPoint{Hour: hour}
			buckets[hour] = p
			order = append(order, hour)
		}
		p.Total++
		if blocked == 1 {
			p.Blocked++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	slices.SortFunc(order, time.Time.Compare)
	points := make([]HourlyPoint, 0, len(order))
	for _, hour := range order {
		points = append(points, *buckets[hour])
	}
	return points, nil
}

// CountryCount is one entry in a top-blocked-countries breakdown.
type CountryCount struct {
	Country string
	Count   int
}

// GetTopBlockedCountries returns the countries with the most blocked
// requests in the last `hours` hours, descending, capped at `limit`.
func (db *DB) GetTopBlockedCountries(limit, hours int) ([]CountryCount, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.query(`
		SELECT country, COUNT(*) AS c
		FROM requests
		WHERE blocked = 1 AND ts >= ? AND country != ''
		GROUP BY country
		ORDER BY c DESC
		LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CountryCount
	for rows.Next() {
		var cc CountryCount
		if err := rows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, err
		}
		out = append(out, cc)
	}
	return out, rows.Err()
}

// IPCount is one entry in a top-blocked-IPs breakdown.
type IPCount struct {
	IP    string
	Count int
}

// GetTopBlockedIPs returns the client IPs with the most blocked requests in
// the last `hours` hours, descending, capped at `limit`.
func (db *DB) GetTopBlockedIPs(limit, hours int) ([]IPCount, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.query(`
		SELECT real_ip, COUNT(*) AS c
		FROM requests
		WHERE blocked = 1 AND ts >= ?
		GROUP BY real_ip
		ORDER BY c DESC
		LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IPCount
	for rows.Next() {
		var ic IPCount
		if err := rows.Scan(&ic.IP, &ic.Count); err != nil {
			return nil, err
		}
		out = append(out, ic)
	}
	return out, rows.Err()
}

// GetTopCountries returns the countries with the most total requests (blocked
// or allowed) in the last `hours` hours, descending, capped at `limit`.
func (db *DB) GetTopCountries(limit, hours int) ([]CountryCount, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.query(`
		SELECT country, COUNT(*) AS c
		FROM requests
		WHERE ts >= ? AND country != ''
		GROUP BY country
		ORDER BY c DESC
		LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CountryCount
	for rows.Next() {
		var cc CountryCount
		if err := rows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, err
		}
		out = append(out, cc)
	}
	return out, rows.Err()
}

// CountBlockedSince returns the number of blocked requests at or after t.
// Used to drive the notification badge.
func (db *DB) CountBlockedSince(t time.Time) (int, error) {
	var n int
	err := db.queryRow(`SELECT COUNT(*) FROM requests WHERE blocked = 1 AND ts >= ?`, t.UTC()).Scan(&n)
	return n, err
}

// pruneBatchSize bounds how many rows PruneOldRequests deletes per
// transaction. SQLite holds its one process-wide write lock for the whole
// duration of a DELETE — on a large table, a single unbatched
// "DELETE WHERE ts < cutoff" can hold that lock for many seconds, during
// which the async log worker (and any admin-UI write) blocks up to
// busy_timeout and then fails. Chunking keeps each transaction's lock hold
// time small, and the pause between batches gives queued writers a chance
// to run instead of starving behind back-to-back prune transactions.
const pruneBatchSize = 2000

// PruneOldRequests deletes request logs older than `days` days and returns
// how many rows were removed.
func (db *DB) PruneOldRequests(days int) (int64, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	var total int64
	for {
		res, err := db.exec(
			`DELETE FROM requests WHERE id IN (SELECT id FROM requests WHERE ts < ? LIMIT ?)`,
			cutoff, pruneBatchSize,
		)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < pruneBatchSize {
			return total, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ── Export ────────────────────────────────────────────────────────────────────

// ExportRequests streams all matching request logs through fn. fn returns false
// to stop early. Uses the same LogFilter WHERE clause as ListRequestsFiltered
// but selects all columns and has no pagination cap.
func (db *DB) ExportRequests(f LogFilter, fn func(RequestLog) bool) error {
	where, args := f.where()
	query := `SELECT id, ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
	                 status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
	                 request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org, ja3_hash, ja4, visitor_id, bot_score
	          FROM requests ` + where + ` ORDER BY ts DESC`
	rows, err := db.query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r RequestLog
		var blocked int
		if err := rows.Scan(
			&r.ID, &r.Timestamp, &r.AppName, &r.RealIP, &r.ProxyIP, &r.Country,
			&r.Method, &r.Host, &r.Path, &r.Query,
			&r.Status, &blocked, &r.RuleID, &r.Action, &r.UserAgent, &r.Duration, &r.HeadersJSON,
			&r.RequestID, &r.Proto, &r.TLSVersion, &r.TLSCipher, &r.TLSSNI, &r.ASN, &r.Org, &r.JA3Hash, &r.JA4, &r.VisitorID, &r.BotScore,
		); err != nil {
			return err
		}
		r.Blocked = blocked == 1
		if !fn(r) {
			return nil
		}
	}
	return rows.Err()
}
