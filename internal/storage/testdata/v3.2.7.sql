-- A database written by Palisade v3.2.7 (issue #302): TypeSafe settings
-- and calls, a saved MySQL/Postgres connection and requests.ja3_hash.
-- Secrets are sealed with sha256("palisade-v3.2.7-fixture-key-not-a-secret-0123456789").
CREATE TABLE admin_sso_identities (
			user_id INTEGER PRIMARY KEY,
			issuer  VARCHAR(255) NOT NULL,
			subject VARCHAR(255) NOT NULL,
			UNIQUE (issuer, subject)
		);
CREATE TABLE admin_sso_invites (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			email      VARCHAR(255) NOT NULL UNIQUE,
			role       TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
CREATE TABLE admin_user_invites (
			user_id    INTEGER PRIMARY KEY,
			token_hash VARCHAR(64) NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL
		);
CREATE TABLE admin_users (
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
		);
CREATE TABLE api_keys (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			name         TEXT NOT NULL,
			key_prefix   TEXT NOT NULL,
			key_hash     VARCHAR(64) NOT NULL UNIQUE,
			read_only    INTEGER NOT NULL DEFAULT 0,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME
		);
CREATE TABLE audit_log (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			ts      DATETIME NOT NULL,
			actor   TEXT NOT NULL,
			ip      TEXT NOT NULL DEFAULT '',
			action  TEXT NOT NULL,
			target  TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL DEFAULT ''
		);
CREATE TABLE certificates (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        VARCHAR(255) NOT NULL UNIQUE,
			domains     TEXT     NOT NULL DEFAULT '',
			expires_at  TEXT     NOT NULL DEFAULT '',
			cert_path   TEXT     NOT NULL DEFAULT '',
			key_path    TEXT     NOT NULL DEFAULT '',
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
CREATE TABLE csp_approved (
			service_id INTEGER NOT NULL,
			origin     VARCHAR(255) NOT NULL,
			PRIMARY KEY (service_id, origin)
		);
CREATE TABLE csp_scripts (
			service_id INTEGER NOT NULL,
			origin     VARCHAR(255) NOT NULL,
			page       TEXT NOT NULL,
			first_seen DATETIME NOT NULL,
			PRIMARY KEY (service_id, origin)
		);
CREATE TABLE geo_rules (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			app_name     VARCHAR(255) NOT NULL DEFAULT '',
			country_code VARCHAR(8) NOT NULL,
			rule_type    TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(app_name, country_code)
		);
CREATE TABLE ip_rules (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			app_name   VARCHAR(255) NOT NULL DEFAULT '',
			ip         VARCHAR(45) NOT NULL,
			rule_type  TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
			note       TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(app_name, ip)
		);
CREATE TABLE ip_threat_scores (
			ip            VARCHAR(45) PRIMARY KEY,
			total_score   INTEGER NOT NULL DEFAULT 0,
			autoban_score INTEGER NOT NULL DEFAULT 0,
			bot_score     INTEGER NOT NULL DEFAULT 0,
			asn_score     INTEGER NOT NULL DEFAULT 0,
			geo_score     INTEGER NOT NULL DEFAULT 0,
			ja4_score     INTEGER NOT NULL DEFAULT 0,
			updated_at    DATETIME NOT NULL
		);
CREATE TABLE ja4_reputation (
			ja4          VARCHAR(64) PRIMARY KEY,
			hits         INTEGER NOT NULL DEFAULT 0,
			blocked_hits INTEGER NOT NULL DEFAULT 0,
			last_seen    DATETIME NOT NULL
		);
CREATE TABLE meta (
			key VARCHAR(255) PRIMARY KEY,
			value TEXT NOT NULL
		);
CREATE TABLE rate_state (
			ip          VARCHAR(45) PRIMARY KEY,
			tokens      REAL NOT NULL,
			last_refill TEXT NOT NULL
		);
CREATE TABLE requests (
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
			ja3_hash     TEXT NOT NULL DEFAULT '',
			ja4          TEXT NOT NULL DEFAULT '',
			visitor_id   TEXT NOT NULL DEFAULT '',
			bot_score    INTEGER NOT NULL DEFAULT 0,
			cache_status TEXT NOT NULL DEFAULT ''
		);
CREATE TABLE service_cookie_policy (
			service_id INTEGER PRIMARY KEY,
			exempt     TEXT NOT NULL
		);
CREATE TABLE service_csp (
			service_id INTEGER PRIMARY KEY,
			policy     TEXT NOT NULL
		);
CREATE TABLE service_csp_enforce (
			service_id INTEGER PRIMARY KEY
		);
CREATE TABLE service_gate (
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
		);
CREATE TABLE service_jwt (
			service_id INTEGER PRIMARY KEY,
			mode       VARCHAR(16) NOT NULL,
			jwks_url   TEXT NOT NULL,
			public_key TEXT NOT NULL,
			issuer     TEXT NOT NULL,
			audience   TEXT NOT NULL,
			algorithms TEXT NOT NULL,
			prefixes   TEXT NOT NULL
		);
CREATE TABLE service_mcp (
			service_id INTEGER PRIMARY KEY,
			mode       VARCHAR(16) NOT NULL,
			path       TEXT NOT NULL,
			origins    TEXT NOT NULL,
			methods    TEXT NOT NULL,
			tools      TEXT NOT NULL
		);
CREATE TABLE service_mtls (
			service_id INTEGER PRIMARY KEY,
			mode       VARCHAR(16) NOT NULL,
			ca_path    TEXT NOT NULL,
			allow_list TEXT NOT NULL
		);
CREATE TABLE service_openapi (
			service_id INTEGER PRIMARY KEY,
			spec       TEXT NOT NULL,
			mode       VARCHAR(16) NOT NULL
		);
CREATE TABLE service_rate_rules (
			service_id INTEGER PRIMARY KEY,
			rules      TEXT NOT NULL
		);
CREATE TABLE service_request_policy (
			service_id    INTEGER PRIMARY KEY,
			mode          TEXT NOT NULL,
			methods       TEXT NOT NULL,
			content_types TEXT NOT NULL,
			max_body_kib  INTEGER NOT NULL DEFAULT 0
		);
CREATE TABLE services (
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
		);
CREATE TABLE sessions (
			token          VARCHAR(64) PRIMARY KEY,
			user_id        INTEGER NOT NULL DEFAULT 0,
			created_at     TEXT NOT NULL,
			ip             TEXT NOT NULL DEFAULT '',
			user_agent     TEXT NOT NULL DEFAULT '',
			last_active_at TEXT NOT NULL DEFAULT '',
			revoked_at     TEXT NOT NULL DEFAULT '',
			device_id      TEXT NOT NULL DEFAULT ''
		);
CREATE TABLE threat_intel_ips (
			source_id INTEGER NOT NULL,
			ip        VARCHAR(45) NOT NULL,
			PRIMARY KEY (source_id, ip)
		);
CREATE TABLE threat_intel_sources (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			label          TEXT NOT NULL,
			url            VARCHAR(768) NOT NULL UNIQUE,
			interval_hours INTEGER NOT NULL DEFAULT 24,
			enabled        INTEGER NOT NULL DEFAULT 1,
			last_synced_at TEXT NOT NULL DEFAULT '',
			last_error     TEXT NOT NULL DEFAULT '',
			ip_count       INTEGER NOT NULL DEFAULT 0,
			created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
CREATE TABLE typesafe_calls (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			ts            DATETIME NOT NULL,
			asn           INTEGER NOT NULL,
			org           TEXT NOT NULL DEFAULT '',
			hosting       INTEGER NOT NULL DEFAULT 0,
			input_tokens  INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0,
			duration_ms   INTEGER NOT NULL DEFAULT 0,
			error         TEXT NOT NULL DEFAULT ''
		);
CREATE TABLE waf_custom_rules (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			service_name VARCHAR(255) NOT NULL DEFAULT '',
			rule         TEXT NOT NULL,
			note         TEXT NOT NULL DEFAULT '',
			enabled      INTEGER NOT NULL DEFAULT 1,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
CREATE TABLE waf_disabled_rules (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id    INTEGER NOT NULL UNIQUE,
			reason     TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
CREATE TABLE waf_rule_feedback (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			service_name   VARCHAR(255) NOT NULL,
			rule_id        INTEGER NOT NULL,
			false_positive INTEGER NOT NULL,
			created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
CREATE TABLE waf_service_rule_exceptions (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			service_name VARCHAR(255) NOT NULL,
			rule_id      INTEGER NOT NULL,
			reason       TEXT NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(service_name, rule_id)
		);
CREATE TABLE webauthn_credentials (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       INTEGER NOT NULL DEFAULT 0,
			credential_id VARCHAR(768) NOT NULL UNIQUE,
			data          TEXT NOT NULL,
			name          TEXT NOT NULL DEFAULT '',
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at  TEXT NOT NULL DEFAULT ''
		);
CREATE TABLE webhook_config (
			id               INTEGER PRIMARY KEY CHECK (id = 1),
			url              TEXT    NOT NULL DEFAULT '',
			secret           TEXT    NOT NULL DEFAULT '',
			enabled          INTEGER NOT NULL DEFAULT 0,
			events           TEXT    NOT NULL DEFAULT 'blocked,challenged',
			destination_type TEXT    NOT NULL DEFAULT 'generic'
		);
CREATE INDEX idx_audit_log_ts ON audit_log(ts);
CREATE INDEX idx_requests_app ON requests(app_name);
CREATE INDEX idx_requests_blocked ON requests(blocked);
CREATE INDEX idx_requests_blocked_ts ON requests(blocked, ts);
CREATE INDEX idx_requests_ip ON requests(real_ip);
CREATE INDEX idx_requests_ts ON requests(ts);
INSERT INTO admin_users VALUES(1,'owner@example.test','$2a$12$q0pHk1PnVlelB/Yr8vALq.qnalfRXZRH2oGymAoUS.360NagDK4Ly','owner',0,'','','','','','2026-11-12 14:49:47.872378465 +0000 GMT m=+0.219236291');
INSERT INTO ip_rules VALUES(1,'','203.0.113.9','block','fixture','2026-11-12 14:49:47');
INSERT INTO meta VALUES('sessions_hashed','1');
INSERT INTO meta VALUES('notifications_seen_at','2026-11-12T14:49:47.661929674Z');
INSERT INTO meta VALUES('typesafe_enabled','1');
INSERT INTO meta VALUES('typesafe_api_key','enc:v1:R7NBTTwYEifJQmFIX5V7BVplp6z46yK4LtmO2san6rVayG11+ctLhpn+');
INSERT INTO meta VALUES('db_conn_driver','postgres');
INSERT INTO meta VALUES('db_conn_mode','fields');
INSERT INTO meta VALUES('db_conn_host','db.internal');
INSERT INTO meta VALUES('db_conn_port','');
INSERT INTO meta VALUES('db_conn_username','waf');
INSERT INTO meta VALUES('db_conn_dbname','waf');
INSERT INTO meta VALUES('db_conn_sslmode','');
INSERT INTO meta VALUES('db_conn_extra','');
INSERT INTO meta VALUES('db_conn_password','enc:v1:8wtTHYBlia8sLFqtXR0Y4HBSyhCmm0IYAHVzN19tCs+qePxbP+g=');
INSERT INTO meta VALUES('db_conn_dsn','enc:v1:dRWRHPDgMOQlDUqop9BeJtNU9A4s0PynfvImhR3ih2PmrIUXyAWtol0pV/71QxzXVCllS1QjZ2aBHWB3B3F1tqr7cajY');
INSERT INTO requests VALUES(1,'2026-11-12 14:49:47.873320065 +0000 UTC','shop','198.51.100.7','','','GET','shop.example.test','/','',200,0,0,'','',0,'','','','','','',0,'','','','',0,'');
INSERT INTO services VALUES(1,'shop','shop.example.test','','http://127.0.0.1:9000','2026-11-12 14:49:47','none','','','',0.0,0,'inherit',0,0,0,'',0,0,0,0,0,'','off',0,0,'','round_robin','',0,'','','','','','','','');
INSERT INTO typesafe_calls VALUES(1,'2026-11-12 14:49:47.872872165 +0000 UTC',64500,'Example Hosting',1,10,2,40,'');
INSERT INTO webhook_config VALUES(1,'','',0,'blocked,challenged','generic');
