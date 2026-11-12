package storage

import (
	"strings"
	"testing"
	"time"

	"palisade/internal/security/ratelimit"
)

// TestClosedDBErrors: once the connection is gone, every query reports the
// failure instead of returning zero values the caller would take as "empty
// config" (no rules, no users, auth disabled).
func TestClosedDBErrors(t *testing.T) {
	db := openTestDB(t)
	db.Close()
	now := time.Now()
	e := func(_ any, err error) error { return err }
	e2 := func(_, _ any, err error) error { return err }

	calls := map[string]func() error{
		"AcceptSSOInvite":           func() error { return e(db.AcceptSSOInvite("a@example.com", "iss", "sub")) },
		"AcceptUserInvite":          func() error { return e(db.AcceptUserInvite("tok", "pw")) },
		"AddCSPScript":              func() error { return e(db.AddCSPScript(1, CSPScript{Origin: "inline", Page: "/", FirstSeen: now})) },
		"AddCrowdSecSource":         func() error { return db.AddCrowdSecSource("cs", "http://127.0.0.1:8080", "k") },
		"AddThreatIntelSource":      func() error { return db.AddThreatIntelSource("l", "https://example.com/l.txt", 24) },
		"AddWebAuthnCredential":     func() error { return db.AddWebAuthnCredential(1, "c", "n", []byte("{}")) },
		"CacheResultsSince":         func() error { return e(db.CacheResultsSince(now)) },
		"CheckAdminPassword":        func() error { return e(db.CheckAdminPassword(1, "pw")) },
		"ConsumeTOTPBackupCode":     func() error { return e(db.ConsumeTOTPBackupCode(1, "h")) },
		"CountIPRulesByType":        func() error { return e2(db.CountIPRulesByType()) },
		"CreateAPIKey":              func() error { return e(db.CreateAPIKey("k", "cwaf_x", "h", false)) },
		"CreateSSOInvite":           func() error { return db.CreateSSOInvite("a@example.com", RoleAdmin) },
		"CreateSession":             func() error { return e(db.CreateSession(1, "1.2.3.4", "ua", "d")) },
		"DeleteCertificate":         func() error { return db.DeleteCertificate(1) },
		"DeleteThreatIntelSource":   func() error { return db.DeleteThreatIntelSource(1) },
		"EnableTOTP":                func() error { return db.EnableTOTP(1, []string{"h"}) },
		"ExpireAutobans":            func() error { return e(db.ExpireAutobans(now)) },
		"GetAICrawlerPolicy":        func() error { return e(db.GetAICrawlerPolicy()) },
		"GetAdaptiveConfig":         func() error { return e(db.GetAdaptiveEnforcementConfig()) },
		"GetAutobanConfig":          func() error { return e(db.GetAutobanConfig()) },
		"GetCaptchaConfig":          func() error { return e(db.GetCaptchaConfig()) },
		"GetDBConnConfig":           func() error { return e(db.GetDBConnConfig()) },
		"GetHoneypotPaths":          func() error { return e(db.GetHoneypotPaths()) },
		"GetOrCreateWebAuthnHandle": func() error { return e(db.GetOrCreateWebAuthnHandle(1)) },
		"GetRuleHitCounts":          func() error { return e(db.GetRuleHitCounts(942000, 942999)) },
		"GetSSOConfig":              func() error { return e(db.GetSSOConfig()) },
		"GetStats":                  func() error { return e(db.GetStats()) },
		"GetTrustedIPs":             func() error { return e(db.GetTrustedIPs()) },
		"GetVarnishConfig":          func() error { return e(db.GetVarnishConfig()) },
		"GetWAFRuleFeedbackConfig":  func() error { return e(db.GetWAFRuleFeedbackConfig()) },
		"GetWebhookConfig":          func() error { return e(db.GetWebhookConfig()) },
		"InviteAdminUser":           func() error { _, _, err := db.InviteAdminUser("a@example.com", RoleViewer); return err },
		"ListAPIKeys":               func() error { return e(db.ListAPIKeys()) },
		"ListAdminUsers":            func() error { return e(db.ListAdminUsers()) },
		"ListAudit":                 func() error { return e2(db.ListAudit(10, 0)) },
		"ListCSPEnforcement":        func() error { return e(db.ListCSPEnforcement()) },
		"ListCrowdSecIPs":           func() error { return e(db.ListCrowdSecIPs()) },
		"ListIPRulesPaginated":      func() error { return e2(db.ListIPRulesPaginated(10, 0)) },
		"ListSSOInvites":            func() error { return e(db.ListSSOInvites()) },
		"ListServiceCookiePolicies": func() error { return e(db.ListServiceCookiePolicies()) },
		"ListServiceRequestPolicy":  func() error { return e(db.ListServiceRequestPolicies()) },
		"ListWAFCustomRules":        func() error { return e(db.ListWAFCustomRules()) },
		"NotificationsSeenAt":       func() error { return e(db.NotificationsSeenAt()) },
		"PruneAudit":                func() error { return e(db.PruneAudit(30)) },
		"ReplaceThreatIntelIPs":     func() error { return db.ReplaceThreatIntelIPs(1, []string{"1.1.1.1"}) },
		"ResetAdminUser2FA":         func() error { return db.ResetAdminUser2FA(1) },
		"RevokeOtherSessions":       func() error { return e(db.RevokeOtherSessions(1, "keep")) },
		"SSOUser":                   func() error { return e(db.SSOUser("iss", "sub")) },
		"SaveRateLimitState": func() error {
			return db.SaveRateLimitState([]ratelimit.BucketState{{IP: "1.2.3.4", Tokens: 1, LastRefill: now}})
		},
		"SaveWAFCustomRule":  func() error { return db.SaveWAFCustomRule(WAFCustomRule{Rule: `SecAction "id:1000001,pass"`}) },
		"SetAICrawlerPolicy": func() error { return db.SetAICrawlerPolicy("{}") },
		"SetAdaptiveConfig":  func() error { return db.SetAdaptiveEnforcementConfig(AdaptiveEnforcementConfig{}) },
		"SetAutobanConfig":   func() error { return db.SetAutobanConfig(AutobanConfig{}) },
		"SetBotSettings":     func() error { return db.SetBotSettings(true, 8, 3600) },
		"SetCSPEnforcement": func() error {
			return db.SetCSPEnforcement(1, CSPEnforcement{Enforce: true, Approved: []string{"inline"}})
		},
		"SetCaptchaConfig":         func() error { return db.SetCaptchaConfig(CaptchaConfig{}) },
		"SetDBConnConfig":          func() error { return db.SetDBConnConfig(DBConnConfig{Driver: "sqlite"}) },
		"SetHoneypotPaths":         func() error { return db.SetHoneypotPaths([]string{"/wp-admin"}) },
		"SetRateLimitSettings":     func() error { return db.SetRateLimitSettings(true, 1, 1) },
		"SetSSOConfig":             func() error { return db.SetSSOConfig(SSOConfig{}) },
		"SetServiceCSP":            func() error { return db.SetServiceCSP(1, "script-src 'self'") },
		"SetServiceCookiePolicy":   func() error { return db.SetServiceCookiePolicy(1, true, []string{"a"}) },
		"SetServiceMCP":            func() error { return db.SetServiceMCP(1, ServiceMCP{Mode: "enforce", Path: "/mcp"}) },
		"SetServiceMTLS":           func() error { return db.SetServiceMTLS(1, ServiceMTLS{Mode: "required", CAPath: "ca.pem"}) },
		"SetServiceOpenAPI":        func() error { return db.SetServiceOpenAPI(1, "openapi: 3.0.3", "log") },
		"SetServiceRequestPolicy":  func() error { return db.SetServiceRequestPolicy(1, RequestPolicy{Mode: "enforce"}) },
		"SetTrustedIPs":            func() error { return db.SetTrustedIPs([]string{"10.0.0.1"}) },
		"SetVarnishConfig":         func() error { return db.SetVarnishConfig(VarnishConfig{}) },
		"SetWAFCustomRuleEnabled":  func() error { return db.SetWAFCustomRuleEnabled(1, true) },
		"SetWAFRuleFeedbackConfig": func() error { return db.SetWAFRuleFeedbackConfig(WAFRuleFeedbackConfig{}) },
		"ThreatIntelRangeCounts":   func() error { return e(db.ThreatIntelRangeCounts()) },
		"UpdateAdminCredentials":   func() error { return db.UpdateAdminCredentials(1, "a@example.com", "new-password-123") },
		"ValidateSession":          func() error { return e(db.ValidateSession("tok")) },
		"ListRequests":             func() error { return e(db.ListRequests(false, "", 10, 0)) },
		"ListRequestsFiltered":     func() error { return e2(db.ListRequestsFiltered(LogFilter{Limit: 10})) },
		"GetRequestByID":           func() error { return e(db.GetRequestByID(1)) },
		"GetAtAGlanceStats":        func() error { return e(db.GetAtAGlanceStats()) },
		"GetHourlyTraffic":         func() error { return e(db.GetHourlyTraffic(24)) },
		"GetTopCountries":          func() error { return e(db.GetTopCountries(5, 24)) },
		"GetTopBlockedIPs":         func() error { return e(db.GetTopBlockedIPs(5, 24)) },
		"GetTopBlockedCountries":   func() error { return e(db.GetTopBlockedCountries(5, 24)) },
		"GetTopFiringRules":        func() error { return e(db.GetTopFiringRules(5)) },
		"ListRecentRequestLogs":    func() error { return e(db.ListRecentRequestLogs(now, 10)) },
		"ListReplayRequests":       func() error { return e(db.ListReplayRequests(10)) },
		"ExportRequests":           func() error { return db.ExportRequests(LogFilter{}, func(RequestLog) bool { return true }) },
		"PruneOldRequests":         func() error { return e(db.PruneOldRequests(1)) },
		"CountBlockedSince":        func() error { return e(db.CountBlockedSince(now)) },
		"GetDailyReport":           func() error { return e(db.GetDailyReport(now.Add(-time.Hour), now)) },
		"GetReportDetails":         func() error { return e(db.GetReportDetails(now.Add(-time.Hour), now, 5)) },
	}
	for name, call := range calls {
		if err := call(); err == nil || !strings.Contains(err.Error(), "closed") {
			t.Errorf("%s on a closed DB: err = %v, want database is closed", name, err)
		}
	}
}
