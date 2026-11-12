package storage

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmoiron/sqlx"
)

// logQueueSize bounds how many request-log entries can be buffered waiting
// to be written. At sustained traffic far beyond what this WAF is sized for,
// entries are dropped (and logged) rather than blocking the request path —
// see QueueRequest.
const logQueueSize = 10000

// slowWriteThreshold gates the diagnostic log in runLogWorker — a single
// InsertRequest taking this long usually means something else (a long-held
// writer lock, e.g. a prune batch, or slow disk I/O) is making every queued
// write wait its turn.
const slowWriteThreshold = 500 * time.Millisecond

// logBatchMax caps how many queued entries runLogWriter commits in one
// transaction. The writer never waits to fill a batch: it takes whatever is
// already queued, so a quiet server still writes row by row with no delay.
const logBatchMax = 500

// dropLogInterval spaces out the "dropping" log line: under a flood one line
// per dropped entry would itself be a load problem.
const dropLogInterval = 5 * time.Second

type DB struct {
	conn          *sqlx.DB
	dialect       dialect
	logQueue      chan RequestLog // request path -> runLogWorker (in-memory hooks)
	writeQueue    chan RequestLog // runLogWorker -> runLogWriter (batched inserts)
	logDone       chan struct{}
	logDropped    atomic.Uint64 // entries that never reached the requests table
	dropLogged    atomic.Int64  // unix nanos of the last "dropping" log line
	logMu         sync.RWMutex  // guards logClosed against a send on the closed logQueue
	logClosed     bool
	broadcastFn   func(RequestLog)
	webhookFn     func(RequestLog)
	autobanFn     func(RequestLog)
	threatScoreFn func(RequestLog)
	accessLogFn   func(RequestLog)
	secretGCM     cipher.AEAD // non-nil = secrets-at-rest encryption active (see secretenc.go)
	bg            sync.WaitGroup
}

// Go runs fn on its own goroutine for slow writes kept off the request path
// (TouchSession, TouchAPIKey). Close waits for them, so none can hit a
// closed connection.
func (db *DB) Go(fn func()) { db.bg.Go(fn) }

// SetAutobanFn registers a callback invoked (from the log worker goroutine)
// for every queued entry, before and regardless of the DB insert (entry.ID is 0). Used to feed blocked events to the
// automatic IP banner without coupling storage to the autoban package.
// The callback must be fast — it runs on the single log worker goroutine.
func (db *DB) SetAutobanFn(fn func(RequestLog)) {
	db.autobanFn = fn
}

// SetWebhookFn registers a callback invoked (from the log worker goroutine)
// after each successful DB insert. Used to push security events to the webhook
// pusher without coupling storage to the webhook package.
func (db *DB) SetWebhookFn(fn func(RequestLog)) {
	db.webhookFn = fn
}

// SetBroadcastFn registers a callback invoked after each successful DB insert,
// with entry.ID set to the real row ID. Called from internal/app to wire the UI
// broadcaster without importing ui from storage.
func (db *DB) SetBroadcastFn(fn func(RequestLog)) {
	db.broadcastFn = fn
}

// SetAccessLogFn registers a callback invoked (from the log worker goroutine)
// for every queued entry, before and regardless of the DB insert (entry.ID is 0). Used to feed the nginx-style access.log
// writer without coupling storage to the accesslog package.
func (db *DB) SetAccessLogFn(fn func(RequestLog)) {
	db.accessLogFn = fn
}

// SetThreatScoreFn registers a callback invoked (from the log worker
// goroutine) for every queued entry, before and regardless of the DB insert (entry.ID is 0). Used to feed the unified
// per-IP threat-score subsystem without coupling storage to the
// threatscore package.
func (db *DB) SetThreatScoreFn(fn func(RequestLog)) {
	db.threatScoreFn = fn
}

// RequestLog is one row in the requests table.
type RequestLog struct {
	ID          int // populated after DB insert; 0 until then
	Timestamp   time.Time
	AppName     string
	RealIP      string
	ProxyIP     string // raw TCP RemoteAddr (CDN/LB edge IP when behind Cloudflare)
	Country     string // ISO 3166-1 alpha-2, e.g. "US", "CN"
	Method      string
	Host        string
	Path        string
	Query       string // raw query string (without leading "?")
	Status      int
	Blocked     bool
	RuleID      int
	Action      string
	UserAgent   string
	Duration    int64  // milliseconds
	HeadersJSON string `json:"-"` // JSON-encoded map[string]string of request headers; kept out of webhook payloads
	RequestID   string // random hex per-request correlation ID
	Proto       string // HTTP/1.1, HTTP/2.0, etc.
	TLSVersion  string // "TLS 1.3", "TLS 1.2", "" for plaintext
	TLSCipher   string // e.g. "TLS_AES_128_GCM_SHA256"
	TLSSNI      string // SNI hostname from TLS ClientHello
	ASN         uint   // autonomous system number
	Org         string // ISP / organization name
	JA4         string // JA4 TLS fingerprint (a_b_c format); empty for plain HTTP
	VisitorID   string // FingerprintJS browser fingerprint from the bot-challenge bypass cookie; "" when unchallenged
	BotScore    int    // anomaly score from bot signal analysis (0 = clean)
	CacheStatus string // Varnish X-Cache verdict (HIT/MISS/PASS); "" when the request didn't go through Varnish
	// Exempt marks a trusted IP, open path or verified crawler, whose
	// response status must not count against it (issue #193). Not stored.
	Exempt bool `json:"-"`
}

// Open opens the default SQLite-backed store at path. It is a thin wrapper
// around OpenWithDriver("sqlite", path) kept for backward compatibility with
// every existing caller (internal/app's default bootstrap path, every storage
// test) that only ever spoke SQLite before external-database support (issue
// database-backends) was added — none of them need to change.
func Open(path string) (*DB, error) {
	return OpenWithDriver("sqlite", path)
}

// OpenWithDriver opens a store against the given backend. driverName is one
// of "sqlite" (default), "mysql" (also accepts "mariadb"), or "postgres"
// (also accepts "postgresql", "cockroachdb"/"cockroach", or "neon" — all
// four speak the Postgres wire protocol and share the same driver/dialect,
// so there is no separate code path per provider, only DSN differences the
// caller supplies). dsn is a plain SQLite file path for the sqlite dialect,
// or a driver-appropriate connection string for the others (e.g.
// "user:pass@tcp(host:3306)/dbname" for MySQL, "postgres://user:pass@host/db
// ?sslmode=require" for Postgres/CockroachDB/Neon).
func OpenWithDriver(driverName, dsn string) (*DB, error) {
	d, err := resolveDialect(driverName)
	if err != nil {
		return nil, err
	}
	conn, err := d.openDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db := &DB{
		conn:       conn,
		dialect:    d,
		logQueue:   make(chan RequestLog, logQueueSize),
		writeQueue: make(chan RequestLog, logQueueSize),
		logDone:    make(chan struct{}),
	}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	go db.runLogWorker()
	go db.runLogWriter()
	return db, nil
}

// runLogWorker is stage one of the log pipeline (issue #259). It drains
// logQueue on one goroutine, runs the hooks that only need memory (autoban,
// threat score, access log) and hands the entry to runLogWriter. Scoring so
// never waits on the database: a slow or failing write loses log rows, not
// bans. Exits once logQueue is closed and drained.
func (db *DB) runLogWorker() {
	defer close(db.writeQueue)
	for entry := range db.logQueue {
		if db.autobanFn != nil {
			db.autobanFn(entry)
		}
		if db.threatScoreFn != nil {
			db.threatScoreFn(entry)
		}
		if db.accessLogFn != nil {
			db.accessLogFn(entry)
		}
		select {
		case db.writeQueue <- entry:
		default:
			db.dropped(1, "write queue full")
		}
	}
}

// runLogWriter is stage two: it writes queued entries in batches and then
// runs the hooks that need the row id (live log, webhook). Exits
// once writeQueue is closed and drained.
func (db *DB) runLogWriter() {
	defer close(db.logDone)
	batch := make([]RequestLog, 0, logBatchMax)
	for entry := range db.writeQueue {
		batch = append(batch[:0], entry)
	fill:
		for len(batch) < logBatchMax {
			select {
			case e, ok := <-db.writeQueue:
				if !ok {
					break fill
				}
				batch = append(batch, e)
			default:
				break fill
			}
		}

		writeStart := time.Now()
		db.insertRequestBatch(batch)
		if dur := time.Since(writeStart); dur >= slowWriteThreshold {
			log.Printf("storage: slow request log write, %d rows took %s (queue depth now %d)", len(batch), dur, db.QueueDepth())
		}
		for _, e := range batch {
			if e.ID == 0 {
				continue // not stored
			}
			if db.broadcastFn != nil {
				db.broadcastFn(e)
			}
			if db.webhookFn != nil {
				db.webhookFn(e)
			}
		}
	}
}

// insertRequestBatch stores batch in one transaction and sets each entry's
// ID. If the transaction fails (Postgres aborts it on the first bad row) the
// rows are retried one by one, so a single bad entry costs only itself.
func (db *DB) insertRequestBatch(batch []RequestLog) {
	if len(batch) > 1 && db.insertRequestTx(batch) == nil {
		return
	}
	failed := 0
	var lastErr error
	for i := range batch {
		id, err := db.InsertRequest(batch[i])
		if err != nil {
			failed++
			lastErr = err
			batch[i].ID = 0
			continue
		}
		batch[i].ID = int(id)
	}
	if failed > 0 {
		db.dropped(failed, "write failed: "+lastErr.Error())
	}
}

// insertRequestTx is the batch path: one prepared INSERT run once per row
// inside a single transaction, which keeps a real row id per entry on every
// dialect.
// ponytail: still one round trip per row on a remote database; a multi-row
// VALUES insert if that is ever the bottleneck.
func (db *DB) insertRequestTx(batch []RequestLog) (err error) {
	tx, err := db.conn.Beginx()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	q := insertRequestSQL
	if db.dialect.name == "postgres" {
		q += " RETURNING id"
	}
	stmt, err := tx.Preparex(db.conn.Rebind(q))
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck // the transaction owns the statement
	ids := make([]int64, len(batch))
	for i := range batch {
		args := insertRequestArgs(batch[i])
		if db.dialect.name == "postgres" {
			err = stmt.QueryRowContext(context.Background(), args...).Scan(&ids[i])
		} else {
			var res sql.Result
			if res, err = stmt.ExecContext(context.Background(), args...); err == nil {
				ids[i], err = res.LastInsertId()
			}
		}
		if err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for i := range batch {
		batch[i].ID = int(ids[i])
	}
	return nil
}

// dropped counts n entries that will never reach the requests table and
// logs about it at most once per dropLogInterval.
func (db *DB) dropped(n int, why string) {
	total := db.logDropped.Add(uint64(n)) //nolint:gosec // n is a small positive batch count
	now := time.Now().UnixNano()
	last := db.dropLogged.Load()
	if now-last >= int64(dropLogInterval) && db.dropLogged.CompareAndSwap(last, now) {
		log.Printf("storage: dropping request log entries (%s), %d dropped since start", why, total)
	}
}

// LogDropped returns how many request-log entries were dropped instead of
// stored since startup. Backs the palisade_log_dropped_total metric.
func (db *DB) LogDropped() uint64 { return db.logDropped.Load() }

// QueueRequest enqueues a request log entry for the background pipeline
// instead of blocking the caller on the DB write. If the first-stage queue
// is full (the in-memory hooks themselves can't keep up) the entry is
// dropped rather than blocking the request that triggered it.
func (db *DB) QueueRequest(entry RequestLog) {
	// A handler can outlive a timed-out graceful shutdown and log after Close.
	db.logMu.RLock()
	defer db.logMu.RUnlock()
	if db.logClosed {
		return
	}
	select {
	case db.logQueue <- entry:
	default:
		db.dropped(1, "log queue full")
	}
}

// QueueDepth returns the number of entries buffered in the log pipeline,
// waiting to be scored or written. Used by the /metrics endpoint to surface
// logging backpressure.
func (db *DB) QueueDepth() int {
	return len(db.logQueue) + len(db.writeQueue)
}

// exec, query, and queryRow are the rebinding equivalents of db.conn's own
// Exec/Query/QueryRow. Every query in this package is written once against
// "?" placeholders; sqlx.DB.Rebind translates that to the target dialect's
// native placeholder syntax before the query reaches the driver — a no-op
// for SQLite and MySQL (both accept "?" natively), but required for
// Postgres, which only understands positional "$1, $2, ..." placeholders
// and returns a syntax error on a literal "?". Centralizing the Rebind call
// here means every existing call site written against "?" keeps working
// unmodified across all three dialects instead of needing its own Rebind.
func (db *DB) exec(query string, args ...any) (sql.Result, error) {
	return db.conn.ExecContext(context.Background(), db.conn.Rebind(query), args...)
}

func (db *DB) query(query string, args ...any) (*sql.Rows, error) {
	return db.conn.QueryContext(context.Background(), db.conn.Rebind(query), args...)
}

func (db *DB) queryRow(query string, args ...any) *sql.Row {
	return db.conn.QueryRowContext(context.Background(), db.conn.Rebind(query), args...)
}

// insertReturningID runs an INSERT and returns the id of the new row.
// SQLite and MySQL support this via the driver's LastInsertId(); Postgres
// has no equivalent at the wire-protocol level, so an INSERT there must
// instead append "RETURNING id" and read the new id back like any other
// query result. Every call site's INSERT targets a table whose primary key
// column is literally named "id".
func (db *DB) insertReturningID(query string, args ...any) (int64, error) {
	if db.dialect.name == "postgres" {
		var id int64
		err := db.queryRow(query+" RETURNING id", args...).Scan(&id)
		return id, err
	}
	res, err := db.exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) Close() error {
	db.logMu.Lock()
	if db.logClosed {
		db.logMu.Unlock()
		return nil
	}
	db.logClosed = true
	close(db.logQueue)
	db.logMu.Unlock()
	<-db.logDone
	db.bg.Wait()
	return db.conn.Close()
}

// Ping checks the database is reachable; backs the /_cz/readyz probe.
func (db *DB) Ping(ctx context.Context) error {
	return db.conn.PingContext(ctx)
}

// schemaMigrations lists every idempotent "ALTER TABLE ... ADD COLUMN ..."
// applied to an existing database on every startup, rendered per dialect via
// dialect.addColumnIfNotExists. Table/column-def pairs, in the same order
// they were historically added as a single hardcoded SQLite string each —
// preserved here so a fresh database and an upgraded one converge on an
// identical schema regardless of dialect.
var schemaMigrations = []struct{ table, columnDef string }{
	{"requests", "country TEXT NOT NULL DEFAULT ''"},
	{"requests", "proxy_ip TEXT NOT NULL DEFAULT ''"},
	{"requests", "headers_json TEXT NOT NULL DEFAULT ''"},
	{"requests", "request_id TEXT NOT NULL DEFAULT ''"},
	{"requests", "proto TEXT NOT NULL DEFAULT ''"},
	{"requests", "tls_version TEXT NOT NULL DEFAULT ''"},
	{"requests", "tls_cipher TEXT NOT NULL DEFAULT ''"},
	{"requests", "tls_sni TEXT NOT NULL DEFAULT ''"},
	{"requests", "asn_num INTEGER NOT NULL DEFAULT 0"},
	{"requests", "org TEXT NOT NULL DEFAULT ''"},
	{"requests", "query TEXT NOT NULL DEFAULT ''"},
	{"requests", "ja4 TEXT NOT NULL DEFAULT ''"},
	{"requests", "visitor_id TEXT NOT NULL DEFAULT ''"},
	{"requests", "bot_score INTEGER NOT NULL DEFAULT 0"},
	{"requests", "cache_status TEXT NOT NULL DEFAULT ''"},
	{"services", "tls_mode TEXT NOT NULL DEFAULT 'none'"},
	{"services", "tls_cert_path TEXT NOT NULL DEFAULT ''"},
	{"services", "tls_key_path TEXT NOT NULL DEFAULT ''"},
	{"services", "tls_expires_at TEXT NOT NULL DEFAULT ''"},
	{"services", "rate_limit_rps REAL NOT NULL DEFAULT 0"},
	{"services", "rate_limit_burst INTEGER NOT NULL DEFAULT 0"},
	{"services", "bot_mode TEXT NOT NULL DEFAULT 'inherit'"},
	{"services", "cert_id INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_enabled INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_by_session INTEGER NOT NULL DEFAULT 0"},
	{"services", "session_cookie_name TEXT NOT NULL DEFAULT ''"},
	{"services", "cache_ttl_floor INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_ttl_ceiling INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_grace INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_keep INTEGER NOT NULL DEFAULT 0"},
	{"services", "allow_large_js_uploads INTEGER NOT NULL DEFAULT 0"},
	{"ip_rules", "note TEXT NOT NULL DEFAULT ''"},
	{"webhook_config", "destination_type TEXT NOT NULL DEFAULT 'generic'"},
	{"sessions", "ip TEXT NOT NULL DEFAULT ''"},
	{"sessions", "user_agent TEXT NOT NULL DEFAULT ''"},
	{"sessions", "last_active_at TEXT NOT NULL DEFAULT ''"},
	{"sessions", "revoked_at TEXT NOT NULL DEFAULT ''"},
	{"sessions", "device_id TEXT NOT NULL DEFAULT ''"},
	{"sessions", "user_id INTEGER NOT NULL DEFAULT 0"},
	{"webauthn_credentials", "user_id INTEGER NOT NULL DEFAULT 0"},
	{"api_keys", "read_only INTEGER NOT NULL DEFAULT 0"},
	{"services", "request_schema TEXT NOT NULL DEFAULT ''"},
	{"services", "schema_mode TEXT NOT NULL DEFAULT 'off'"},
	{"services", "http3_enabled INTEGER NOT NULL DEFAULT 0"},
	{"services", "compress_enabled INTEGER NOT NULL DEFAULT 0"},
	{"services", "extra_backends TEXT NOT NULL DEFAULT ''"},
	{"services", "lb_policy TEXT NOT NULL DEFAULT 'round_robin'"},
	{"services", "health_path TEXT NOT NULL DEFAULT ''"},
	{"services", "health_interval INTEGER NOT NULL DEFAULT 0"},
	{"services", "host_aliases TEXT NOT NULL DEFAULT ''"},
	{"services", "canonical_host TEXT NOT NULL DEFAULT ''"},
	{"services", "login_paths TEXT NOT NULL DEFAULT ''"},
	{"services", "ai_crawler_policy TEXT NOT NULL DEFAULT ''"},
	{"services", "breach_action TEXT NOT NULL DEFAULT ''"},
	{"services", "breach_fields TEXT NOT NULL DEFAULT ''"},
	{"services", "response_inspect TEXT NOT NULL DEFAULT ''"},
	{"services", "cache_rules TEXT NOT NULL DEFAULT ''"},
}

func (db *DB) migrate() error {
	// Idempotent column migration for existing databases. MySQL/Postgres
	// use native "ADD COLUMN IF NOT EXISTS" (see addColumnIfNotExists) and
	// so never actually error here; SQLite has no such clause and always
	// errors with "duplicate column" once a column already exists — that
	// error is expected and intentionally ignored on every startup after
	// the first, exactly as the single hardcoded statements this loop
	// replaced always did (each was itself an ignored, //nolint'd Exec).
	for _, m := range schemaMigrations {
		db.exec(db.dialect.addColumnIfNotExists(m.table, m.columnDef)) //nolint
	}

	for _, stmt := range db.schemaStatements() {
		// CREATE INDEX statements are the one schemaStatements() entry not
		// safely rerunnable on every dialect: MySQL's CREATE INDEX has no
		// IF NOT EXISTS clause at all (see dialect.createIndexIfNotExists/
		// createIndexOnText), so re-running migrate() against an existing
		// MySQL database (e.g. every server restart) always errors
		// "Duplicate key name" here — expected and ignored, the same
		// swallow-the-error convention the ALTER TABLE loop above uses.
		if strings.HasPrefix(stmt, "CREATE INDEX") {
			db.exec(stmt) //nolint
			continue
		}
		if _, err := db.exec(stmt); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}

	if err := db.migrateAdminFromMeta(); err != nil {
		return err
	}
	if err := db.hashSessionTokens(); err != nil {
		return err
	}

	// Seed the notifications baseline at startup (not lazily on first access)
	// so a block that happens before any admin page has ever been loaded
	// still counts as "unread" instead of racing the lazy-init.
	metaKeyCol := db.dialect.quoteIdent("key")
	_, err := db.exec(
		db.dialect.upsertIgnore("meta", []string{metaKeyCol, "value"}, "?, ?", []string{metaKeyCol}),
		metaKeyNotificationsSeenAt, time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
