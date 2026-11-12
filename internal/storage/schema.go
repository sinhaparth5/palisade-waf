package storage

// schemaStatements is every table and index, one statement per Exec.
func (db *DB) schemaStatements() []string {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS requests (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			ts           DATETIME NOT NULL,
			app_name     TEXT NOT NULL,
			real_ip      TEXT NOT NULL,
			proxy_ip     TEXT NOT NULL DEFAULT '',
			country      TEXT NOT NULL DEFAULT '',
			method       TEXT NOT NULL,
			host         TEXT NOT NULL,
			path         TEXT NOT NULL,
			query        TEXT NOT NULL DEFAULT '',
			status       INTEGER NOT NULL,
			blocked      INTEGER NOT NULL DEFAULT 0,
			rule_id      INTEGER NOT NULL DEFAULT 0,
			action       TEXT NOT NULL DEFAULT '',
			user_agent   TEXT NOT NULL DEFAULT '',
			duration_ms  INTEGER NOT NULL DEFAULT 0,
			headers_json TEXT NOT NULL DEFAULT '',
			request_id   TEXT NOT NULL DEFAULT '',
			proto        TEXT NOT NULL DEFAULT '',
			tls_version  TEXT NOT NULL DEFAULT '',
			tls_cipher   TEXT NOT NULL DEFAULT '',
			tls_sni      TEXT NOT NULL DEFAULT '',
			asn_num      INTEGER NOT NULL DEFAULT 0,
			org          TEXT NOT NULL DEFAULT '',
			ja4          TEXT NOT NULL DEFAULT '',
			visitor_id   TEXT NOT NULL DEFAULT '',
			bot_score    INTEGER NOT NULL DEFAULT 0,
			cache_status TEXT NOT NULL DEFAULT ''
		)`,
		"CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts)",
		"CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(real_ip)",
		"CREATE INDEX IF NOT EXISTS idx_requests_blocked ON requests(blocked)",
		"CREATE INDEX IF NOT EXISTS idx_requests_app ON requests(app_name)",
		"CREATE INDEX IF NOT EXISTS idx_requests_blocked_ts ON requests(blocked, ts)",

		`CREATE TABLE IF NOT EXISTS ip_rules (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			app_name   VARCHAR(255) NOT NULL DEFAULT '',
			ip         VARCHAR(45) NOT NULL,
			rule_type  TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
			note       TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(app_name, ip)
		)`,

		`CREATE TABLE IF NOT EXISTS geo_rules (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			app_name     VARCHAR(255) NOT NULL DEFAULT '',
			country_code VARCHAR(8) NOT NULL,
			rule_type    TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(app_name, country_code)
		)`,

		`CREATE TABLE IF NOT EXISTS meta (
			key VARCHAR(255) PRIMARY KEY,
			value TEXT NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS services (
			id               INTEGER PRIMARY KEY AUTOINCREMENT,
			name             VARCHAR(255) NOT NULL UNIQUE,
			host             TEXT NOT NULL DEFAULT '',
			prefix           TEXT NOT NULL DEFAULT '',
			backend          TEXT NOT NULL,
			created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			tls_mode         TEXT NOT NULL DEFAULT 'none',
			tls_cert_path    TEXT NOT NULL DEFAULT '',
			tls_key_path     TEXT NOT NULL DEFAULT '',
			tls_expires_at   TEXT NOT NULL DEFAULT '',
			rate_limit_rps   REAL NOT NULL DEFAULT 0,
			rate_limit_burst INTEGER NOT NULL DEFAULT 0,
			bot_mode         TEXT NOT NULL DEFAULT 'inherit',
			cert_id          INTEGER NOT NULL DEFAULT 0,
			cache_enabled    INTEGER NOT NULL DEFAULT 0,
			cache_by_session INTEGER NOT NULL DEFAULT 0,
			session_cookie_name TEXT NOT NULL DEFAULT '',
			cache_ttl_floor    INTEGER NOT NULL DEFAULT 0,
			cache_ttl_ceiling  INTEGER NOT NULL DEFAULT 0,
			cache_grace        INTEGER NOT NULL DEFAULT 0,
			cache_keep         INTEGER NOT NULL DEFAULT 0,
			allow_large_js_uploads INTEGER NOT NULL DEFAULT 0,
			request_schema   TEXT NOT NULL DEFAULT '',
			schema_mode      TEXT NOT NULL DEFAULT 'off',
			http3_enabled    INTEGER NOT NULL DEFAULT 0,
			compress_enabled INTEGER NOT NULL DEFAULT 0,
			extra_backends   TEXT NOT NULL DEFAULT '',
			lb_policy        TEXT NOT NULL DEFAULT 'round_robin',
			health_path      TEXT NOT NULL DEFAULT '',
			health_interval  INTEGER NOT NULL DEFAULT 0,
			host_aliases     TEXT NOT NULL DEFAULT '',
			canonical_host   TEXT NOT NULL DEFAULT '',
			login_paths      TEXT NOT NULL DEFAULT '',
			ai_crawler_policy TEXT NOT NULL DEFAULT '',
			breach_action    TEXT NOT NULL DEFAULT '',
			breach_fields    TEXT NOT NULL DEFAULT '',
			response_inspect TEXT NOT NULL DEFAULT '',
			cache_rules      TEXT NOT NULL DEFAULT ''
		)`,

		`CREATE TABLE IF NOT EXISTS certificates (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        VARCHAR(255) NOT NULL UNIQUE,
			domains     TEXT     NOT NULL DEFAULT '',
			expires_at  TEXT     NOT NULL DEFAULT '',
			cert_path   TEXT     NOT NULL DEFAULT '',
			key_path    TEXT     NOT NULL DEFAULT '',
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// Admin accounts (issue #196), see users.go. The totp_* columns are
		// the old admin_totp_* meta keys, per user.
		`CREATE TABLE IF NOT EXISTS admin_users (
			id                  INTEGER PRIMARY KEY AUTOINCREMENT,
			email               VARCHAR(255) NOT NULL UNIQUE,
			password_hash       TEXT NOT NULL,
			role                TEXT NOT NULL,
			disabled            INTEGER NOT NULL DEFAULT 0,
			totp_secret         TEXT NOT NULL DEFAULT '',
			totp_pending_secret TEXT NOT NULL DEFAULT '',
			totp_backup_codes   TEXT NOT NULL DEFAULT '',
			totp_last_counter   TEXT NOT NULL DEFAULT '',
			webauthn_handle     TEXT NOT NULL DEFAULT '',
			created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// OIDC single sign-on (issue #197), see sso.go. Pending invites are
		// deleted when used or revoked; an identity binds one user to the
		// IdP's iss+sub.
		`CREATE TABLE IF NOT EXISTS admin_sso_invites (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			email      VARCHAR(255) NOT NULL UNIQUE,
			role       TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS admin_sso_identities (
			user_id INTEGER PRIMARY KEY,
			issuer  VARCHAR(255) NOT NULL,
			subject VARCHAR(255) NOT NULL,
			UNIQUE (issuer, subject)
		)`,

		// Password invites (issue #229), see users.go: one live set-password
		// link per pending user, stored as the token's SHA-256.
		`CREATE TABLE IF NOT EXISTS admin_user_invites (
			user_id    INTEGER PRIMARY KEY,
			token_hash VARCHAR(64) NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL
		)`,

		// token is 32 random bytes hex-encoded (64 chars, see
		// DB.CreateSession) — VARCHAR(64) fits exactly.
		// One row per login. Only one row per user is ever live at a time
		// (see CreateSession); superseded and revoked rows are kept, with
		// revoked_at set, as the device history the Settings page lists.
		`CREATE TABLE IF NOT EXISTS sessions (
			token          VARCHAR(64) PRIMARY KEY,
			user_id        INTEGER NOT NULL DEFAULT 0,
			created_at     TEXT NOT NULL,
			ip             TEXT NOT NULL DEFAULT '',
			user_agent     TEXT NOT NULL DEFAULT '',
			last_active_at TEXT NOT NULL DEFAULT '',
			revoked_at     TEXT NOT NULL DEFAULT '',
			device_id      TEXT NOT NULL DEFAULT ''
		)`,

		// key_hash is a SHA-256 hex digest (64 chars, see ui.CreateAPIKey).
		`CREATE TABLE IF NOT EXISTS api_keys (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			name         TEXT NOT NULL,
			key_prefix   TEXT NOT NULL,
			key_hash     VARCHAR(64) NOT NULL UNIQUE,
			read_only    INTEGER NOT NULL DEFAULT 0,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME
		)`,

		`CREATE TABLE IF NOT EXISTS rate_state (
			ip          VARCHAR(45) PRIMARY KEY,
			tokens      REAL NOT NULL,
			last_refill TEXT NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS waf_disabled_rules (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id    INTEGER NOT NULL UNIQUE,
			reason     TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS waf_service_rule_exceptions (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			service_name VARCHAR(255) NOT NULL,
			rule_id      INTEGER NOT NULL,
			reason       TEXT NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(service_name, rule_id)
		)`,

		`CREATE TABLE IF NOT EXISTS waf_custom_rules (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			service_name VARCHAR(255) NOT NULL DEFAULT '',
			rule         TEXT NOT NULL,
			note         TEXT NOT NULL DEFAULT '',
			enabled      INTEGER NOT NULL DEFAULT 1,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS threat_intel_sources (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			label          TEXT NOT NULL,
			url            VARCHAR(768) NOT NULL UNIQUE,
			interval_hours INTEGER NOT NULL DEFAULT 24,
			enabled        INTEGER NOT NULL DEFAULT 1,
			last_synced_at TEXT NOT NULL DEFAULT '',
			last_error     TEXT NOT NULL DEFAULT '',
			ip_count       INTEGER NOT NULL DEFAULT 0,
			created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS threat_intel_ips (
			source_id INTEGER NOT NULL,
			ip        VARCHAR(45) NOT NULL,
			PRIMARY KEY (source_id, ip)
		)`,

		`CREATE TABLE IF NOT EXISTS webhook_config (
			id               INTEGER PRIMARY KEY CHECK (id = 1),
			url              TEXT    NOT NULL DEFAULT '',
			secret           TEXT    NOT NULL DEFAULT '',
			enabled          INTEGER NOT NULL DEFAULT 0,
			events           TEXT    NOT NULL DEFAULT 'blocked,challenged',
			destination_type TEXT    NOT NULL DEFAULT 'generic'
		)`,
		upsertIgnore("webhook_config", []string{"id"}, "1", []string{"id"}),

		`CREATE TABLE IF NOT EXISTS ip_threat_scores (
			ip            VARCHAR(45) PRIMARY KEY,
			total_score   INTEGER NOT NULL DEFAULT 0,
			autoban_score INTEGER NOT NULL DEFAULT 0,
			bot_score     INTEGER NOT NULL DEFAULT 0,
			asn_score     INTEGER NOT NULL DEFAULT 0,
			geo_score     INTEGER NOT NULL DEFAULT 0,
			ja4_score     INTEGER NOT NULL DEFAULT 0,
			updated_at    DATETIME NOT NULL
		)`,

		// ja4 fingerprints are a fixed ~36-char format (see ja4.Compute);
		// VARCHAR(64) leaves headroom without needing to track the exact
		// spec length here.
		`CREATE TABLE IF NOT EXISTS ja4_reputation (
			ja4          VARCHAR(64) PRIMARY KEY,
			hits         INTEGER NOT NULL DEFAULT 0,
			blocked_hits INTEGER NOT NULL DEFAULT 0,
			last_seen    DATETIME NOT NULL
		)`,

		// Client-certificate policy per service (issue #191). The CA
		// bundle itself lives on disk next to the service's TLS cert.
		`CREATE TABLE IF NOT EXISTS service_mtls (
			service_id INTEGER PRIMARY KEY,
			mode       VARCHAR(16) NOT NULL,
			ca_path    TEXT NOT NULL,
			allow_list TEXT NOT NULL
		)`,

		// MCP endpoint guard per service (issue #234). Lists are
		// newline-separated.
		`CREATE TABLE IF NOT EXISTS service_mcp (
			service_id INTEGER PRIMARY KEY,
			mode       VARCHAR(16) NOT NULL,
			path       TEXT NOT NULL,
			origins    TEXT NOT NULL,
			methods    TEXT NOT NULL,
			tools      TEXT NOT NULL
		)`,

		// Per-path rate limits per service (issue #280): one
		// "METHOD /prefix rate burst" per line, see services.ParseRateRules.
		`CREATE TABLE IF NOT EXISTS service_rate_rules (
			service_id INTEGER PRIMARY KEY,
			rules      TEXT NOT NULL
		)`,

		// Bearer JWT check per service (issue #279). Lists are
		// newline-separated; public_key is PEM.
		`CREATE TABLE IF NOT EXISTS service_jwt (
			service_id INTEGER PRIMARY KEY,
			mode       VARCHAR(16) NOT NULL,
			jwks_url   TEXT NOT NULL,
			public_key TEXT NOT NULL,
			issuer     TEXT NOT NULL,
			audience   TEXT NOT NULL,
			algorithms TEXT NOT NULL,
			prefixes   TEXT NOT NULL
		)`,

		// Report-only CSP per service and the script sources its reports
		// named (issue #235). origin is a scheme://host or a CSP keyword.
		`CREATE TABLE IF NOT EXISTS service_csp (
			service_id INTEGER PRIMARY KEY,
			policy     TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS csp_scripts (
			service_id INTEGER NOT NULL,
			origin     VARCHAR(255) NOT NULL,
			page       TEXT NOT NULL,
			first_seen DATETIME NOT NULL,
			PRIMARY KEY (service_id, origin)
		)`,

		// Set-Cookie hardening per service (issue #281): a row means on;
		// exempt is space-separated cookie names left alone.
		`CREATE TABLE IF NOT EXISTS service_cookie_policy (
			service_id INTEGER PRIMARY KEY,
			exempt     TEXT NOT NULL
		)`,

		// CSP enforce mode (issue #283): approved inventory entries, and a
		// row per service that sends them as an enforcing policy.
		`CREATE TABLE IF NOT EXISTS csp_approved (
			service_id INTEGER NOT NULL,
			origin     VARCHAR(255) NOT NULL,
			PRIMARY KEY (service_id, origin)
		)`,
		`CREATE TABLE IF NOT EXISTS service_csp_enforce (
			service_id INTEGER PRIMARY KEY
		)`,

		// Accepted methods, Content-Types and body size per service
		// (issue #282); lists are space-separated.
		`CREATE TABLE IF NOT EXISTS service_request_policy (
			service_id    INTEGER PRIMARY KEY,
			mode          TEXT NOT NULL,
			methods       TEXT NOT NULL,
			content_types TEXT NOT NULL,
			max_body_kib  INTEGER NOT NULL DEFAULT 0
		)`,

		// Maintenance mode and waiting room per service (issue #198).
		// Schedule bounds are RFC 3339 text, "" for none.
		`CREATE TABLE IF NOT EXISTS service_gate (
			service_id    INTEGER PRIMARY KEY,
			maintenance   INTEGER NOT NULL DEFAULT 0,
			maint_message TEXT NOT NULL,
			maint_start   TEXT NOT NULL,
			maint_end     TEXT NOT NULL,
			bypass_token  TEXT NOT NULL,
			waiting_room  INTEGER NOT NULL DEFAULT 0,
			wr_max        INTEGER NOT NULL DEFAULT 0,
			wr_idle       INTEGER NOT NULL DEFAULT 0,
			wr_message    TEXT NOT NULL,
			wr_crawlers   VARCHAR(16) NOT NULL
		)`,

		// One OpenAPI document per service (issue #190).
		`CREATE TABLE IF NOT EXISTS service_openapi (
			service_id INTEGER PRIMARY KEY,
			spec       TEXT NOT NULL,
			mode       VARCHAR(16) NOT NULL
		)`,

		// One row per false/true-positive mark an admin makes on a blocked
		// request from the Logs page (issue #76). Append-only signal log, not
		// upserted — GetWAFRuleSuggestions aggregates it per (service_name,
		// rule_id) over a rolling window.
		`CREATE TABLE IF NOT EXISTS waf_rule_feedback (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			service_name   VARCHAR(255) NOT NULL,
			rule_id        INTEGER NOT NULL,
			false_positive INTEGER NOT NULL,
			created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// One row per registered passkey (issue #78), owned by user_id.
		// Unlike the single TOTP secret, a user normally
		// registers more than one authenticator (phone, laptop, a security
		// key), so this is a list, not another meta key. `data` is the
		// go-webauthn Credential JSON-encoded whole (public key, sign
		// counter, flags, attestation) rather than split into columns —
		// it's opaque application data the library round-trips, never
		// queried or filtered on in SQL, so decomposing it would only add
		// risk of drifting from whatever fields a future library version adds.
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       INTEGER NOT NULL DEFAULT 0,
			credential_id VARCHAR(768) NOT NULL UNIQUE,
			data          TEXT NOT NULL,
			name          TEXT NOT NULL DEFAULT '',
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at  TEXT NOT NULL DEFAULT ''
		)`,

		// Admin audit trail (issue #129): who changed what, from the admin
		// UI or the REST API. Never holds secret values; see ui.auditLog.
		`CREATE TABLE IF NOT EXISTS audit_log (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			ts      DATETIME NOT NULL,
			actor   TEXT NOT NULL,
			ip      TEXT NOT NULL DEFAULT '',
			action  TEXT NOT NULL,
			target  TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL DEFAULT ''
		)`,
		"CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts)",
	}

	return stmts
}
