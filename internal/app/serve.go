package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"palisade/internal/config"
	"palisade/internal/notify/accesslog"
	"palisade/internal/notify/mailer"
	"palisade/internal/notify/metrics"
	"palisade/internal/notify/webhook"
	"palisade/internal/proxy"
	"palisade/internal/security/adaptive"
	"palisade/internal/security/asn"
	"palisade/internal/security/autoban"
	"palisade/internal/security/blocklist"
	"palisade/internal/security/bot"
	"palisade/internal/security/challenge"
	"palisade/internal/security/csp"
	"palisade/internal/security/geo"
	ja4pkg "palisade/internal/security/ja4"
	"palisade/internal/security/ratelimit"
	"palisade/internal/security/threatintel"
	"palisade/internal/security/threatscore"
	"palisade/internal/security/waf"
	"palisade/internal/services"
	"palisade/internal/storage"
	"palisade/internal/ui"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
)

// listening reports each bound listener ("http", "https", "redirect",
// "admin", "h3"); tests use it to learn the port behind ":0".
var listening = func(name string, addr net.Addr) {}

// serve is the server: bootstrap settings come from flags, every runtime knob
// from the DB (managed in the admin UI). It returns once ctx ends and the
// listeners have drained, or on a startup error.
func serve(ctx context.Context, args []string, version string, assets Assets) error {
	fs := flag.NewFlagSet("palisade", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "HTTP listen address")
	listenTLS := fs.String("listen-tls", "", "HTTPS listen address (empty = HTTP only)")
	listenH3 := fs.String("listen-h3", "", "HTTP/3 (QUIC) UDP listen address, e.g. :443; needs --listen-tls; services opt in individually (empty = off)")
	trustedProxies := fs.String("trusted-proxies", "", "comma-separated trusted proxy IPs or CIDRs for X-Forwarded-For/X-Real-IP")
	adminAllow := fs.String("admin-allow", "", "comma-separated client IPs or CIDRs that may reach the admin UI, API and metrics; everyone else gets a 404 (empty = any)")
	adminListen := fs.String("admin-listen", "", "serve the admin UI only on this plain-HTTP address, e.g. 127.0.0.1:9090, and remove it from the public listener (empty = public listener)")
	maxConns := fs.Int("max-conns-per-ip", 256, "concurrent TCP connections one client IP (IPv6 /64) may hold; trusted proxies, Cloudflare, loopback and trusted IPs are exempt (0 = no cap)")
	trustedCrawlers := fs.String("trusted-crawlers", "", "extra crawlers that skip the bot challenge, pinned by source: ua=cidr[,cidr];ua2=ip, or ua=https://host to verify Web Bot Auth signatures (empty = none)")
	dbPath, dbDriver := dbFlags(fs)
	certsDir := fs.String("certs", "./certs", "TLS certificate cache directory")
	wafRules := fs.String("waf-rules", "", "extra WAF rules directory (empty = OWASP CRS only)")
	geoDBPath := fs.String("geo-db", "", "GeoIP2 database path (empty = bundled)")
	retention := fs.Int("retention", 30, "request log retention in days (0 = keep forever)")
	pruneInterval := fs.Duration("prune-interval", 0, "prune request logs older than --retention in-process at this interval, e.g. 24h (0 = off; for deployments with no external scheduler, like Docker)")
	tlsCert := fs.String("tls-cert", "", "PEM certificate file for HTTPS fallback (self-signed)")
	tlsKey := fs.String("tls-key", "", "PEM private key file for HTTPS fallback (self-signed)")
	accessLogPath := fs.String("access-log", "", "nginx-style access log file path (empty = disabled)")
	accessLogMaxSizeMB := fs.Int("access-log-max-size-mb", 100, "rotate access log after this many MB")
	accessLogMaxBackups := fs.Int("access-log-max-backups", 5, "number of rotated access log files to keep")
	dbKeyFile := fs.String("db-key-file", "", "key file for AES-256-GCM encryption of stored secrets at rest (empty = plaintext)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 { // a removed or mistyped subcommand, e.g. build-dsn
		return fmt.Errorf("unknown command %q", fs.Arg(0))
	}

	cfg := config.Defaults()
	cfg.Version = version
	cfg.ListenAddr = *listen
	cfg.ListenAddrTLS = *listenTLS
	cfg.ListenAddrH3 = *listenH3
	if cfg.ListenAddrH3 != "" && cfg.ListenAddrTLS == "" {
		return errors.New("--listen-h3 needs --listen-tls: browsers only discover HTTP/3 from an HTTPS response")
	}
	cfg.TrustedProxies = splitCSV(*trustedProxies)
	cfg.Admin.Allow = splitCSV(*adminAllow)
	cfg.Admin.Listen = *adminListen
	// An entry that doesn't parse would be skipped, and an empty list means
	// "any client", so a typo must stop startup rather than open the UI.
	for _, a := range cfg.Admin.Allow {
		if _, err := netip.ParsePrefix(a); err != nil {
			if _, err := netip.ParseAddr(a); err != nil {
				return fmt.Errorf("--admin-allow: %q is not an IP or CIDR", a)
			}
		}
	}
	if err := bot.AddPinnedCrawlers(*trustedCrawlers); err != nil {
		return fmt.Errorf("--trusted-crawlers: %w", err)
	}
	cfg.DB.Path = *dbPath
	cfg.TLS.CacheDir = *certsDir
	cfg.TLS.FallbackCertFile = *tlsCert
	cfg.TLS.FallbackKeyFile = *tlsKey
	cfg.WAF.RulesDir = *wafRules
	cfg.Geo.DBPath = *geoDBPath
	cfg.DB.LogRetentionDays = *retention
	if *pruneInterval != 0 && *pruneInterval < time.Minute {
		return fmt.Errorf("--prune-interval must be 0 (off) or at least 1m, got %s", *pruneInterval)
	}

	if err := checkSQLite(*dbDriver, cfg.DB.Path); err != nil {
		return err
	}
	if err := checkWritable(filepath.Dir(cfg.DB.Path)); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.TLS.CacheDir); err == nil {
		if err := checkWritable(cfg.TLS.CacheDir); err != nil {
			return err
		}
	}
	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer db.Close()

	// Must happen before anything reads secret config (the challenge secret,
	// TOTP secrets, email/webhook credentials) — EnableSecretEncryption
	// also migrates any still-plaintext secrets, so first boot with a key
	// needs no manual step.
	if *dbKeyFile != "" {
		if err := enableDBEncryption(db, *dbKeyFile); err != nil {
			return fmt.Errorf("db-key-file: %w", err)
		}
		log.Printf("secrets-at-rest encryption enabled (key file %s)", *dbKeyFile)
	}

	engine, wafByService, err := buildWAFAll(db, cfg.WAF)
	if err != nil {
		return fmt.Errorf("waf init: %w", err)
	}

	// No default credentials are ever seeded — a publicly-known fallback
	// login would hand over the whole WAF on any deploy that skipped setup.
	// The WAF/proxy still runs without an admin (login rejects everything);
	// only the dashboard is unusable until credentials are created.
	if n, _ := db.CountAdminUsers(); n == 0 {
		log.Printf("no admin credentials configured — admin UI logins will be rejected until you run:")
		log.Printf("  palisade setup --db %s --admin-email you@example.com  (password read from stdin)", cfg.DB.Path)
	}

	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		return fmt.Errorf("ip blocklist: %w", err)
	}

	intelWorker := threatintel.New(db, func() {
		if err := ipbl.ReloadIntel(db); err != nil {
			log.Printf("threat-intel: blocklist reload: %v", err)
		}
	})
	defer intelWorker.Stop()

	geoBl, err := geo.New(cfg.Geo.DBPath, db)
	if err != nil {
		return fmt.Errorf("geo blocker: %w", err)
	}
	defer geoBl.Close()

	rl := buildRateLimit(db)

	asnLookup, err := asn.New()
	if err != nil {
		log.Printf("asn: failed to load ASN database, ASN/org lookup disabled: %v", err)
		asnLookup = nil
	} else {
		defer asnLookup.Close()
	}

	registry, err := services.New(db)
	if err != nil {
		return fmt.Errorf("services registry: %w", err)
	}

	// Cache-return listener: the single static backend the Varnish VCL points
	// at. Varnish fetches cache misses here and the registry routes them to
	// the right backend, so adding/editing services never touches the VCL.
	// Always started (even with the integration toggled off) so enabling
	// Varnish from the Settings page needs no restart. Closed only after the
	// main listeners drain: in-flight miss fetches are their children.
	if cr := startCacheReturn(db, registry); cr != nil {
		defer cr.Close()
	}

	if *pruneInterval > 0 {
		go runPruneLoop(ctx, db, *pruneInterval, *retention)
	}

	metrics.SetDB(db)
	metrics.SetRegistry(registry)
	metrics.SetLimiter(rl)

	broadcaster := ui.NewLogBroadcaster()
	// Wire broadcaster into the DB log worker so every insert is pushed to the
	// SSE stream with the real row ID, not a zero placeholder.
	db.SetBroadcastFn(broadcaster.Broadcast)

	// Webhook pusher: delivers security events to the configured endpoint
	// asynchronously so a slow webhook never blocks the log worker.
	webhookPusher := webhook.New(db.GetWebhookConfig)
	defer webhookPusher.Stop()
	db.SetWebhookFn(webhookPusher.Push)

	// Daily report email: crunches the previous day's blocked/403 counts just
	// after local midnight and mails them via the settings stored in the DB.
	emailReporter := mailer.NewReporter(db)
	defer emailReporter.Stop()

	// Automatic IP banning: scores blocked events per client IP from the log
	// stream and turns repeat offenders / severe attackers into permanent
	// global block rules, hot-reloading the blocklist and emailing the admin.
	banner := autoban.New(db, func() {
		if err := ipbl.Reload(db); err != nil {
			log.Printf("autoban: blocklist reload: %v", err)
		}
	}, func(ip, reason string) {
		if err := emailReporter.SendBanAlert(ip, reason); err != nil {
			log.Printf("autoban: ban alert email for %s: %v", ip, err)
		}
	})
	defer banner.Stop()
	banner.SetMemoryBan(ipbl.Hold, ipbl.Release)
	db.SetAutobanFn(banner.Record)

	// Unified per-IP threat score: a composite read model (issue #12)
	// combining autoban's history, bot score, ASN/hosting classification,
	// geo risk, and JA4 repeat-offender history.
	scorer := threatscore.New(db, banner.Score)
	defer scorer.Stop()
	if rules, err := db.ListGeoRules(); err != nil {
		log.Printf("threatscore: initial geo rules load: %v", err)
	} else {
		scorer.ReloadGeoRules(rules)
	}
	db.SetThreatScoreFn(scorer.Record)

	// Threat-score-driven adaptive enforcement (issue #16), off by default.
	adaptivePolicy := adaptive.New(db)

	// nginx-style access.log for tooling that expects one (fail2ban, log
	// shippers). Deferred after db.Close() (registered above), so LIFO
	// closes it *before* the DB while runLogWorker drains the queue.
	if *accessLogPath != "" {
		accessLogWriter, err := accesslog.New(*accessLogPath, *accessLogMaxSizeMB, *accessLogMaxBackups)
		if err != nil {
			return fmt.Errorf("access log: %w", err)
		}
		defer accessLogWriter.Close()
		db.SetAccessLogFn(accessLogWriter.Push)
	}

	// Bot protection settings come entirely from the DB (managed via Settings page).
	botEnabled, botThreshold, botTTL, _ := db.GetBotSettings()

	secret, err := db.GetOrCreateChallengeSecret()
	if err != nil {
		return fmt.Errorf("challenge secret: %w", err)
	}

	buildChallenger := func(enabled bool, threshold, ttl int) *challenge.Challenger {
		if !enabled {
			return nil
		}
		cc, err := db.GetCaptchaConfig()
		if err != nil {
			log.Printf("captcha config: %v", err)
		}
		return challenge.New(secret, ttl, threshold).WithCaptcha(cc.Provider, cc.SiteKey, cc.Secret)
	}

	var ch *challenge.Challenger
	if botEnabled {
		ch = buildChallenger(true, botThreshold, botTTL)
		log.Printf("bot protection enabled (threshold=%d, ttl=%ds)", botThreshold, botTTL)
	}

	e := echo.New()
	// Echo v5 is only a handler; the servers are ours.
	srv := &http.Server{Handler: e} //nolint:gosec // G112: hardenServer sets ReadHeaderTimeout on the next line
	hardenServer(srv)
	e.Use(middleware.Recover())
	e.Use(proxy.SecurityMiddleware())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		// Health probes arrive every few seconds; logging them buries real traffic.
		Skipper: func(c *echo.Context) bool {
			p := c.Request().URL.Path
			return p == "/_cz/healthz" || p == "/_cz/readyz"
		},
		LogURI:    true,
		LogStatus: true,
		LogMethod: true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			log.Printf("%s %s -> %d", v.Method, v.URI, v.Status)
			return nil
		},
	}))

	h := proxy.NewHandler(registry, engine, wafByService, db, ipbl, geoBl, rl, asnLookup, ch, scorer, adaptivePolicy, cfg.TrustedProxies...)
	// Stops whichever rate limiter is active at shutdown — not necessarily
	// rl, since ReloadRateLimit (Settings page) may have hot-swapped it.
	defer h.StopRateLimit()

	// reloadWAF rebuilds the default engine and every per-service engine
	// from the current DB state: the WAF Rules/Services pages and SIGHUP.
	reloadWAF := func() error {
		newEngine, newByService, err := buildWAFAll(db, cfg.WAF)
		if err != nil {
			return err
		}
		h.ReloadWAF(newEngine, newByService)
		return nil
	}

	uiHandler, err := ui.NewHandler(cfg, db, ipbl, geoBl, registry, broadcaster, assets.JS, assets.CSS, assets.Imgs,
		h.ReloadBotProtection, buildChallenger,
		func() { h.ReloadRateLimit(buildRateLimit(db)) },
		func() {
			if err := reloadWAF(); err != nil {
				log.Printf("waf reload: %v", err)
			}
		},
		intelWorker.SyncSource, emailReporter.SendNow, webhookPusher.SendTest, emailReporter.SendLoginCode, emailReporter.SendInvite,
		banner.ReloadConfig, scorer, adaptivePolicy.ReloadConfig, h.Handle)
	if err != nil {
		return fmt.Errorf("ui init: %w", err)
	}
	uiHandler.Register(e)
	uiHandler.RegisterAPI(e)

	// Challenge routes must be registered before the catch-all proxy route so
	// Echo routes them to the challenger, not the backend.
	e.GET("/_cz/challenge", func(c *echo.Context) error {
		h.ServeChallengePage(c.Response(), c.Request())
		return nil
	})
	e.POST("/_cz/verify", func(c *echo.Context) error {
		h.ServeChallengeVerify(c.Response(), c.Request())
		return nil
	})
	e.GET("/_cz/fp.js", func(c *echo.Context) error {
		h.ServeFingerprintJS(c.Response(), c.Request())
		return nil
	})
	// Logo for the challenge page. Served under /_cz/ (not the admin path)
	// because the challenge renders on every proxied domain.
	e.GET("/_cz/logo.svg", func(c *echo.Context) error {
		data, err := assets.Imgs.ReadFile("static/imgs/logo.svg")
		if err != nil {
			return echo.ErrNotFound
		}
		c.Response().Header().Set("Cache-Control", "public, max-age=86400")
		return c.Blob(http.StatusOK, "image/svg+xml", data)
	})

	// Report-only CSP reports (issue #235). Registered here, so they are
	// never challenged or proxied; the collector rate limits per client.
	proxyCIDRs := proxy.ParseTrustedProxyCIDRs(cfg.TrustedProxies)
	cspCollector := csp.New(db, registry.CSPService, func(r *http.Request) string { return proxy.ClientIP(r, proxyCIDRs) },
		func(service, source, page string) {
			webhookPusher.Push(storage.RequestLog{Timestamp: time.Now(), AppName: service, Host: source, Path: page, Action: webhook.ActionNewScript})
			if err := emailReporter.SendScriptAlert(service, source, page); err != nil {
				log.Printf("csp: script alert email: %v", err)
			}
		})
	e.POST(csp.ReportPath, echo.WrapHandler(cspCollector))

	proxy.RegisterProbes(e, db)

	e.Any("/*", h.Handle)

	// SIGHUP: rebuild the WAF engines (picks up changes to --waf-rules)
	// without restarting. Services hot-reload on every UI change.
	reloadOnHUP(ctx, reloadWAF)

	appCount := len(registry.List())
	connLimit := proxy.NewConnLimiter(*maxConns, proxyCIDRs, registry.Trusted)

	// --admin-listen: bound here so a taken port fails startup.
	var extra []shutdowner
	if cfg.Admin.Listen != "" {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Admin.Listen)
		if err != nil {
			return fmt.Errorf("--admin-listen: %w", err)
		}
		adminSrv := &http.Server{Handler: ui.AdminListener(cfg.Admin.Path, e)} //nolint:gosec // G112: hardenServer sets ReadHeaderTimeout on the next line
		hardenServer(adminSrv)
		go func() {
			if err := adminSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("admin listener: %v", err)
			}
		}()
		extra = append(extra, adminSrv)
		listening("admin", ln.Addr())
		log.Printf("admin UI on http://%s%s only (plain HTTP)", ln.Addr(), cfg.Admin.Path)
	}

	// TLS only starts when --listen-tls is provided. Certificate config
	// (ACME email, per-service certs) lives entirely in the DB.
	if cfg.ListenAddrTLS != "" {
		return startTLS(ctx, srv, e, cfg, registry, db, appCount, connLimit, extra...)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		closeAll(extra)
		return fmt.Errorf("server: %w", err)
	}
	listening("http", ln.Addr())
	log.Printf("palisade listening on %s (plain HTTP, waf=%v, apps=%d)", ln.Addr(), cfg.WAF.Enabled, appCount)
	return serveUntil(ctx, srv, connLimit.Listener(ln), append(extra, srv))
}

// serveUntil runs the main server on ln until ctx ends, then drains servers in
// order (the main one last) and returns only once that is done: Serve returns
// as soon as Shutdown starts, and the caller's deferred db.Close would
// otherwise close the log queue under requests still in flight.
func serveUntil(ctx context.Context, srv *http.Server, ln net.Listener, servers []shutdowner) error {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		log.Printf("shutting down gracefully...")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			if err := s.Shutdown(sctx); err != nil {
				log.Printf("http shutdown: %v", err)
				if closeErr := s.Close(); closeErr != nil {
					log.Printf("http close: %v", closeErr)
				}
			}
		}
	})
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		if stop() {
			closeAll(servers) // the drain never started: nothing else stops them
		}
		return err
	}
	<-done
	return nil
}

func closeAll(servers []shutdowner) {
	for _, s := range servers {
		_ = s.Close()
	}
}

// reloadOnHUP rebuilds the WAF on each SIGHUP until ctx ends, keeping the
// running engines when the rebuild fails. SIGHUP is caught from the moment
// it returns (its default action would kill the process).
func reloadOnHUP(ctx context.Context, reload func() error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		defer signal.Stop(sigCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				log.Printf("SIGHUP: reloading WAF engine...")
				if err := reload(); err != nil {
					log.Printf("SIGHUP: WAF reload failed, keeping existing engine: %v", err)
				}
			}
		}
	}()
}

// buildWAFAll constructs a fresh default engine plus one extra engine per
// service that needs its own: rule exceptions, large-JavaScript uploads, a
// request schema, an OpenAPI spec, an MCP guard or service-scoped custom
// rules. It reads the current DB state each time, so SIGHUP and the WAF
// Rules/Services pages pick up the latest toggles without a restart. Each
// engine holds the full compiled CRS, so this is deliberately lazy: a
// deployment that uses none of these pays for one engine.
func buildWAFAll(db *storage.DB, wafCfg config.WAFConfig) (*waf.Engine, map[string]*waf.Engine, error) {
	globalIDs, err := db.GetDisabledWAFRuleIDs()
	if err != nil {
		return nil, nil, err
	}
	customs, err := db.ListWAFCustomRules()
	if err != nil {
		return nil, nil, err
	}
	globalCustom, svcCustom := customRuleDirectives(customs)
	defaultEngine, err := waf.NewWithDirectives(wafCfg, globalIDs, globalCustom)
	if err != nil {
		return nil, nil, err
	}

	svcNames, err := db.ListWAFExceptionServiceNames()
	if err != nil {
		return nil, nil, err
	}
	// The per-service extras besides rule exceptions (tracked by svcNames).
	type wafServiceOpts struct {
		allowLargeJS bool
		schema       string
		schemaMode   string
		openapi      storage.ServiceOpenAPI
		mcp          storage.ServiceMCP
	}
	serviceSet := make(map[string]wafServiceOpts, len(svcNames))
	for _, name := range svcNames {
		serviceSet[name] = wafServiceOpts{}
	}
	svcs, err := db.ListServices()
	if err != nil {
		return nil, nil, err
	}
	specs, err := db.ListServiceOpenAPI()
	if err != nil {
		return nil, nil, err
	}
	mcps, err := db.ListServiceMCP()
	if err != nil {
		return nil, nil, err
	}
	for _, svc := range svcs {
		spec, mcp := specs[svc.ID], mcps[svc.ID]
		if svc.AllowLargeJSUploads || mcp.Mode != "" || (spec.Mode != "" && spec.Mode != "off") || (svc.SchemaMode != "" && svc.SchemaMode != "off" && svc.RequestSchema != "") {
			serviceSet[svc.Name] = wafServiceOpts{
				allowLargeJS: svc.AllowLargeJSUploads,
				schema:       svc.RequestSchema,
				schemaMode:   svc.SchemaMode,
				openapi:      spec,
				mcp:          mcp,
			}
		}
	}
	for name := range svcCustom {
		if _, ok := serviceSet[name]; !ok {
			serviceSet[name] = wafServiceOpts{}
		}
	}
	byService := make(map[string]*waf.Engine, len(serviceSet))
	for name, opts := range serviceSet {
		svcIDs, err := db.GetWAFRuleIDsForService(name)
		if err != nil {
			return nil, nil, err
		}
		merged := append(append([]int{}, globalIDs...), svcIDs...)
		// CRS 920420 rejects JavaScript media types and 911100 rejects PUT
		// before body inspection. The upload toggle deliberately permits
		// both parts of S3 PutObject; all other header rules stay enabled.
		if opts.allowLargeJS {
			merged = append(merged, 911100, 920420)
		}
		eng, err := waf.NewWithDirectives(wafCfg, merged, globalCustom+"\n"+svcCustom[name])
		if err != nil {
			return nil, nil, err
		}
		// A schema or spec that fails to compile was already rejected at save
		// time; this is defense in depth (a hand-edited row), so it logs and
		// leaves the service running without it rather than failing the build.
		if err := eng.SetRequestSchema(opts.schema, opts.schemaMode); err != nil {
			log.Printf("waf: service %q: invalid request schema, ignoring: %v", name, err)
		}
		if err := eng.SetOpenAPI(opts.openapi.Spec, opts.openapi.Mode); err != nil {
			log.Printf("waf: service %q: invalid OpenAPI spec, ignoring: %v", name, err)
		}
		eng.SetMCP(waf.MCPConfig{Mode: opts.mcp.Mode, Path: opts.mcp.Path,
			Origins: strings.Fields(opts.mcp.Origins), Methods: strings.Fields(opts.mcp.Methods), Tools: strings.Fields(opts.mcp.Tools)})
		byService[name] = eng
	}
	return defaultEngine, byService, nil
}

// customRuleDirectives splits the enabled custom WAF rules (issue #112) into
// the global directives and per-service ones. Rules were validated when
// saved; one that no longer validates (a hand-edited row) is logged and
// skipped so it can't stop the whole engine from building.
func customRuleDirectives(rules []storage.WAFCustomRule) (global string, byService map[string]string) {
	byService = map[string]string{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if _, err := waf.ValidateCustomRule(r.Rule); err != nil {
			log.Printf("waf: custom rule %d is invalid, skipping: %v", r.ID, err)
			continue
		}
		if r.ServiceName == "" {
			global += r.Rule + "\n"
		} else {
			byService[r.ServiceName] += r.Rule + "\n"
		}
	}
	return global, byService
}

// startTLS is the single entry point for HTTPS. It reads the ACME contact
// email from the DB, builds an autocert manager if present, then starts HTTP
// on cfg.ListenAddr (ACME challenge handler + HTTPS redirect) and HTTPS on
// cfg.ListenAddrTLS. Per-service custom certs take priority over autocert by
// SNI (see services.Registry.GetCertificateFunc).
func startTLS(ctx context.Context, s *http.Server, e *echo.Echo, cfg *config.Config, registry *services.Registry, db *storage.DB, appCount int, connLimit *proxy.ConnLimiter, extra ...shutdowner) error {
	servers := extra
	fail := func(err error) error {
		closeAll(servers)
		return err
	}
	email, _ := db.GetAcmeEmail()
	primaryDomain, _ := db.GetPrimaryDomain()
	primary := strings.ToLower(primaryDomain)

	var am *autocert.Manager
	if email != "" {
		if err := os.MkdirAll(cfg.TLS.CacheDir, 0o700); err != nil {
			return fail(fmt.Errorf("cannot create cert cache dir %s: %w", cfg.TLS.CacheDir, err))
		}
		// HostPolicy allows services with tls_mode="auto" AND the primary domain
		// (so the admin dashboard's domain gets a Let's Encrypt cert automatically).
		basePolicy := registry.HostPolicy()
		am = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				if primary != "" && strings.ToLower(host) == primary {
					return nil
				}
				return basePolicy(ctx, host)
			},
			Cache: autocert.DirCache(cfg.TLS.CacheDir),
			Email: email,
		}
	}

	// Self-signed fallback cert, used when no per-service/ACME cert matches
	// (access by IP address, or before ACME provisioning completes).
	var fallbackCert *tls.Certificate
	if cfg.TLS.FallbackCertFile != "" && cfg.TLS.FallbackKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.FallbackCertFile, cfg.TLS.FallbackKeyFile)
		if err != nil {
			return fail(fmt.Errorf("load fallback TLS cert: %w", err))
		}
		fallbackCert = &cert
		log.Printf("tls: loaded fallback cert from %s", cfg.TLS.FallbackCertFile)
	}

	// HTTP: ACME HTTP-01 challenge handler (if autocert active) + HTTPS redirect.
	var httpHandler http.Handler = http.HandlerFunc(httpsRedirect)
	if am != nil {
		httpHandler = am.HTTPHandler(httpHandler)
	}
	redirectServer := &http.Server{Handler: httpHandler} //nolint:gosec // G112: hardenServer sets ReadHeaderTimeout on the next line
	hardenServer(redirectServer)
	// Bind before serving so a taken port fails startup: without this
	// listener ACME HTTP-01 renewals fail silently until the certs expire.
	redirectLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		return fail(fmt.Errorf("http (ACME/redirect) listener: %w", err))
	}
	listening("redirect", redirectLn.Addr())
	servers = append([]shutdowner{redirectServer}, servers...)
	go func() {
		log.Printf("palisade HTTP (ACME/redirect) on %s", redirectLn.Addr())
		if err := redirectServer.Serve(connLimit.Listener(redirectLn)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http server: %v", err)
		}
	}()

	prevConnState := s.ConnState
	s.ConnState = func(conn net.Conn, state http.ConnState) {
		if prevConnState != nil {
			prevConnState(conn, state)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			forgetConn(conn.RemoteAddr().String())
		}
	}

	// Certificate resolution order:
	//   1. Per-service uploaded cert (by SNI)
	//   2. Per-service / primary-domain ACME cert (by SNI)
	//   3. Self-signed fallback (IP access or ACME not yet provisioned)
	getCertBase := registry.GetCertificateFunc(am)
	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCertBase(hello)
		if err == nil {
			return cert, nil
		}
		if am != nil && primary != "" && strings.ToLower(hello.ServerName) == primary {
			return am.GetCertificate(hello)
		}
		if fallbackCert != nil {
			return fallbackCert, nil
		}
		return nil, err
	}

	// http.Server only enables HTTP/2 on a non-nil TLSConfig that offers
	// "h2", and per-SNI configs (mTLS) are cloned from this one.
	base := &tls.Config{GetCertificate: getCert, NextProtos: []string{"h2", "http/1.1"}}
	// Capture the ClientHello for the connection's JA4 fingerprint, read
	// back by the proxy handler per request. SNI names with an mTLS policy
	// also get a config that asks for a client cert (issue #191); HTTP/3
	// clones this config, and quic-go re-applies its own ALPN to the result.
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		ja4pkg.Store(hello.Conn.RemoteAddr().String(), ja4pkg.Compute(hello))
		if cfg := registry.MTLSConfig(base, hello.ServerName); cfg != nil {
			return cfg, nil
		}
		return nil, nil
	}
	s.TLSConfig = base

	if cfg.ListenAddrH3 != "" {
		h3, err := startHTTP3(e, cfg.ListenAddrH3, s.TLSConfig, registry)
		if err != nil {
			return fail(err)
		}
		servers = append(servers, h3)
	}

	// Bound here, not by Echo, so the per-client cap sits below TLS: a
	// refused connection costs no handshake.
	tlsLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ListenAddrTLS)
	if err != nil {
		return fail(fmt.Errorf("https listener: %w", err))
	}
	listening("https", tlsLn.Addr())
	log.Printf("palisade TLS on %s (waf=%v, apps=%d)", tlsLn.Addr(), cfg.WAF.Enabled, appCount)
	return serveUntil(ctx, s, tls.NewListener(connLimit.Listener(tlsLn), s.TLSConfig), append(servers, s))
}

// forgetConn drops the per-connection JA4/geo/ASN entries once a connection ends.
func forgetConn(remote string) {
	ja4pkg.Delete(remote)
	geo.DeleteConn(remote)
	asn.DeleteConn(remote)
}

// startHTTP3 serves the same Echo app over QUIC on addr (UDP). Only services
// with HTTP/3 enabled are advertised (Alt-Svc on their TCP responses) or
// accepted; everything else, the admin UI included, stays on HTTP/1.1 and HTTP/2.
func startHTTP3(e *echo.Echo, addr string, tlsConf *tls.Config, registry *services.Registry) (*http3.Server, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("--listen-h3 %q: %w", addr, err)
	}
	// Bind here rather than in ListenAndServe so a taken port fails startup
	// instead of only being logged from a goroutine.
	conn, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("http3 listen %s: %w", addr, err)
	}
	listening("h3", conn.LocalAddr())

	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	altSvc := fmt.Sprintf(`h3=":%s"; ma=86400`, port)
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if registry.HTTP3Host(c.Request().Host) {
				c.Response().Header().Set("Alt-Svc", altSvc)
			}
			return next(c)
		}
	})

	srv := &http3.Server{
		TLSConfig: tlsConf.Clone(),
		// 0-RTT early data can be replayed by anyone who captured it, and a
		// WAF must not act on a request it can't tell apart from its replay.
		// quic-go enables it when QUICConfig is nil, so this must stay set.
		QUICConfig:     &quic.Config{Allow0RTT: false, MaxIncomingStreams: maxStreams},
		MaxHeaderBytes: 1 << 20,
		Handler:        http3Gate(registry, e),
		// QUIC has no ConnState hook, so clear the per-connection stores
		// (filled at handshake by GetConfigForClient) when the conn ends.
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			remote := c.RemoteAddr().String()
			context.AfterFunc(c.Context(), func() { forgetConn(remote) })
			return ctx
		},
	}
	go func() {
		log.Printf("palisade HTTP/3 on %s (udp)", conn.LocalAddr())
		if err := srv.Serve(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http3 server: %v", err)
		}
	}()
	return srv, nil
}

// http3Gate answers 421 for hosts that haven't opted into HTTP/3, so a client
// replaying a stale Alt-Svc (or trying QUIC on the admin host) retries the
// same request over TCP instead of bypassing the per-service choice.
func http3Gate(registry *services.Registry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !registry.HTTP3Host(r.Host) {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkWritable stops startup with a fix instead of a bare permission error
// later. The Docker image runs as uid 65532 since issue #274, so a volume an
// older image (root) created is the usual cause.
func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".palisade-write-check-*")
	if err == nil {
		f.Close()
		_ = os.Remove(f.Name())
		return nil
	}
	if !errors.Is(err, fs.ErrPermission) {
		return nil // missing dir etc.: the real open reports it better
	}
	return fmt.Errorf("%s is not writable by uid %d. In Docker, a volume created while the image still ran as root is owned by root; fix it once with:\n"+
		"  docker run --rm -v <volume>:/data alpine chown -R 65532:65532 /data", dir, os.Getuid())
}

// maxStreams caps concurrent requests per HTTP/2 or HTTP/3 connection.
const maxStreams = 100

// hardenServer bounds how long a client may take to send its headers and hold
// an idle keep-alive conn, so a Slowloris trickle can't pin connections below
// the rate limiter. ReadTimeout/WriteTimeout stay unset: uploads, SSE and
// WebSockets legitimately stream for longer than any fixed bound.
func hardenServer(s *http.Server) {
	s.ReadHeaderTimeout = 10 * time.Second
	s.IdleTimeout = 120 * time.Second
	s.MaxHeaderBytes = 1 << 20 // also HTTP/2's max header list size
	// Stated rather than left to the library default (#272): one connection
	// can't run more than this many requests at once.
	s.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: maxStreams}
}

// shutdowner is the graceful-stop surface *http.Server and *http3.Server share.
type shutdowner interface {
	Shutdown(context.Context) error
	Close() error
}

// startCacheReturn starts the loopback listener Varnish fetches cache misses
// from (services.Registry.CacheReturnHandler routes them to the right
// backend), or returns nil. It refuses non-loopback addresses outright: this
// port proxies straight to backends with no WAF pipeline in front, so it must
// never be reachable off-host.
func startCacheReturn(db *storage.DB, registry *services.Registry) *http.Server {
	vcfg, err := db.GetVarnishConfig()
	if err != nil {
		log.Printf("cache-return: read varnish config: %v", err)
		return nil
	}
	host, _, err := net.SplitHostPort(vcfg.ReturnAddr)
	if err != nil {
		log.Printf("cache-return: invalid return address %q: %v", vcfg.ReturnAddr, err)
		return nil
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Printf("cache-return: refusing to bind non-loopback address %q", vcfg.ReturnAddr)
		return nil
	}
	srv := &http.Server{Addr: vcfg.ReturnAddr, Handler: registry.CacheReturnHandler()} //nolint:gosec // G112: hardenServer sets ReadHeaderTimeout on the next line
	hardenServer(srv)
	go func() {
		log.Printf("cache-return listener on %s (Varnish miss path)", vcfg.ReturnAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("cache-return listener: %v", err)
		}
	}()
	return srv
}

func httpsRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently) //nolint:gosec // G710: redirects the client to its own Host, nothing else
}

// buildRateLimit creates the global limiter from the settings stored in the
// DB (enabled/rps/burst, managed via the Settings page). When global limiting
// is disabled it returns a no-op Limiter that allows everything; otherwise an
// in-process Limiter with DB write-back persistence, so token-bucket state
// survives restarts.
func buildRateLimit(db *storage.DB) *ratelimit.Limiter {
	enabled, rps, burst, _ := db.GetRateLimitSettings()
	if !enabled {
		log.Printf("rate limit: global limiter disabled (enable from the Settings page)")
		return ratelimit.New(config.RateLimitConfig{})
	}
	l := ratelimit.New(config.RateLimitConfig{Enabled: true, RequestsPerSecond: rps, Burst: burst})
	if states, err := db.LoadRateLimitState(); err == nil && len(states) > 0 {
		l.RestoreFrom(states)
		log.Printf("rate limit: restored %d buckets", len(states))
	}
	l.StartPersistence(db)
	log.Printf("rate limit: in-memory backend with DB persistence (%.2g rps, burst %d)", rps, burst)
	return l
}
