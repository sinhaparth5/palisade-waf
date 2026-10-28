package mailer

import (
	"cmp"
	"fmt"
	"html"
	"log"
	"strings"
	"sync"
	"time"

	"palisade/internal/storage"
)

// store is the slice of *storage.DB the reporter needs; an interface so tests
// can run without a real database.
type store interface {
	GetEmailConfig() (storage.EmailConfig, error)
	GetDailyReport(from, to time.Time) (storage.DailyReport, error)
	GetReportDetails(from, to time.Time, limit int) (storage.ReportDetails, error)
	GetEmailReportSentFor() (string, error)
	SetEmailReportSentFor(day string) error
}

// Reporter emails a summary of the previous day's traffic shortly after local
// midnight. Config is read from the DB on every run, so enabling or changing
// credentials in the admin UI takes effect without a restart. The
// "email_report_sent_for" meta key makes sends idempotent per day: a restart
// right after midnight (or downtime across midnight) neither duplicates nor
// permanently skips a report.
type Reporter struct {
	db   store
	stop chan struct{}
	once sync.Once
	now  func() time.Time                                        // injectable for tests
	send func(storage.EmailConfig, string, string, string) error // injectable for tests
}

// NewReporter starts the background scheduler goroutine.
func NewReporter(db *storage.DB) *Reporter {
	r := &Reporter{db: db, stop: make(chan struct{}), now: time.Now, send: Send}
	go r.run()
	return r
}

// Stop shuts down the scheduler goroutine.
func (r *Reporter) Stop() { r.once.Do(func() { close(r.stop) }) }

func (r *Reporter) run() {
	for {
		// Runs once at startup (catching up a report missed while the server
		// was down over midnight) and then once after each midnight.
		r.maybeSendDaily()
		select {
		case <-time.After(untilNextMidnight(r.now())):
		case <-r.stop:
			return
		}
	}
}

// untilNextMidnight returns the wait until just past the next local midnight;
// the one-minute pad keeps clock skew from firing inside the old day.
func untilNextMidnight(now time.Time) time.Duration {
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, 1)
	return next.Sub(now) + time.Minute
}

// maybeSendDaily sends the report for the most recently completed local day,
// unless alerts are disabled or that day's report already went out.
func (r *Reporter) maybeSendDaily() {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		log.Printf("mailer: read config: %v", err)
		return
	}
	if !cfg.Enabled || cfg.Token == "" || cfg.To == "" {
		return
	}

	now := r.now()
	dayEnd := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	dayStart := dayEnd.AddDate(0, 0, -1)
	day := dayStart.Format("2006-01-02")

	if sentFor, err := r.db.GetEmailReportSentFor(); err == nil && sentFor == day {
		return
	}
	subject, text, html, err := r.report(day, dayStart, dayEnd)
	if err != nil {
		log.Printf("mailer: daily report query: %v", err)
		return
	}
	if err := r.send(cfg, subject, text, html); err != nil {
		// Not marked as sent — the next midnight tick (or a restart) retries.
		log.Printf("mailer: daily report for %s failed: %v", day, err)
		return
	}
	if err := r.db.SetEmailReportSentFor(day); err != nil {
		log.Printf("mailer: mark report sent: %v", err)
	}
	log.Printf("mailer: daily report for %s sent to %s", day, cfg.To)
}

// SendNow emails a report covering the last 24 hours immediately, regardless
// of the enabled flag (so credentials can be verified before turning the
// schedule on). Used by the admin UI's "send test report" button.
func (r *Reporter) SendNow() error {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		return err
	}
	now := r.now()
	subject, text, html, err := r.report(now.Format("2006-01-02")+" (last 24 h)", now.Add(-24*time.Hour), now)
	if err != nil {
		return err
	}
	return r.send(cfg, subject, text, html)
}

// report gathers [from, to), the same-length window before it for the
// comparison figures, and the chart data, then renders the email.
func (r *Reporter) report(label string, from, to time.Time) (subject, text, html string, err error) {
	prev, err := r.db.GetDailyReport(from.Add(-to.Sub(from)), from)
	if err != nil {
		return
	}
	rep, err := r.db.GetDailyReport(from, to)
	if err != nil {
		return
	}
	det, err := r.db.GetReportDetails(from, to, 5)
	if err != nil {
		return
	}
	subject, text, html = composeReport(label, rep, prev, det)
	return
}

// SendBanAlert emails a notice that ip was automatically banned (autoban
// package). Silently skipped (nil) when email alerts are disabled or not
// fully configured — a ban must never depend on email being set up.
func (r *Reporter) SendBanAlert(ip, reason string) error {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		return err
	}
	if !cfg.Enabled || cfg.Token == "" || cfg.To == "" {
		return nil
	}
	subject, text, html := composeBanAlert(ip, reason, r.now())
	return r.send(cfg, subject, text, html)
}

// SendLoginCode emails a one-time 2FA recovery code to the configured
// recipients, for an admin who can't produce an authenticator code at login.
// Unlike SendBanAlert this is not silently skipped when cfg.Enabled is off:
// the admin explicitly clicked "email me a code", so an unconfigured mailer
// is an error the login page should surface, not swallow. It does require a
// token and recipient; the login UI only offers the option when both are set.
func (r *Reporter) SendLoginCode(code string) error {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		return err
	}
	if cfg.Token == "" || cfg.To == "" {
		return fmt.Errorf("email recovery is not configured")
	}
	subject, text, html := composeLoginCode(code, r.now())
	return r.send(cfg, subject, text, html)
}

// SendInvite emails a new user their set-password link (issue #229). It
// goes to that user's address, not the alert recipients, and only needs the
// API token: inviting doesn't depend on the daily report being switched on.
func (r *Reporter) SendInvite(to, inviter, role, link string) error {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		return err
	}
	if cfg.Token == "" {
		return fmt.Errorf("email is not set up")
	}
	cfg.To = to
	subject, text, html := composeInvite(inviter, role, link, r.now().Add(storage.UserInviteTTL))
	return r.send(cfg, subject, text, html)
}

// Email palette: hex versions of the admin UI's v3 "ledger" tokens
// (static/css/tailwind.css, light mode). Same meanings as the UI: success =
// allowed, warning = look here, danger = blocked.
const (
	cPaper2     = "#e2d8c5" // --fn-paper-2, page backdrop
	cPaper      = "#e8dfce" // --fn-paper
	cCard       = "#efe8da" // --fn-card
	cInk        = "#191816" // --fn-ink
	cInkSoft    = "#46423b" // slate-700
	cMuted      = "#5f594f" // --fn-muted (slate-500)
	cEdge       = "#2a2926" // --fn-edge, card borders
	cRule       = "#c4beb2" // --fn-rule over card
	cSide       = "#12130e" // --fn-side, the header band
	cSideInk    = "#e8e0d3" // --fn-side-active
	cSideMuted  = "#8c867a" // --fn-side-muted
	cSideLine   = "#252620" // --fn-side-line
	cHighlight  = "#d9a05b" // --fn-warning (--color-highlight)
	cLogoAccent = "#b8ed9c" // the lit stake in static/imgs/logo.svg
	cAccent     = "#3d6e42" // --fn-success-ink
	cAllowed    = "#6aac6f" // --fn-success
	cStamp      = "#c84b31" // --fn-danger
	cStampInk   = "#a63a24" // --fn-danger-ink
	cStampTint  = "#e5d3c1" // red-50
)

// Font stacks mirror the UI (Space Grotesk body, JetBrains Mono headings,
// labels and numbers). frame links the same Google Fonts; clients that drop
// the link (Gmail) fall back to the system stack.
const (
	fontStack = `'Space Grotesk',-apple-system,'Segoe UI',Arial,sans-serif`
	fontMono  = `'JetBrains Mono','SF Mono',Consolas,monospace`
	// labelStyle is the UI's .label-mono: small uppercase mono, muted.
	labelStyle = `font:500 10px ` + fontMono + `;text-transform:uppercase;letter-spacing:.08em`
)

// frame wraps body rows in the shared shell: page backdrop, a square card
// with a hard 1px edge, the nav rail's dark header band with the logo, and a
// footer note. Inline styles and nested tables only — email clients ignore
// stylesheets, and Gmail strips SVG, so the logo's four stakes
// (static/imgs/logo.svg) are rebuilt as divs.
func frame(kicker, body, note string) string {
	stake := func(h int, c string) string {
		return fmt.Sprintf(`<td valign="bottom" style="padding-right:2px"><div style="width:6px;height:%dpx;background:%s;font-size:0;line-height:0">&nbsp;</div></td>`, h, c)
	}
	return `<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:` + cPaper2 + `"><tr><td align="center" style="padding:32px 12px">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:` + cCard + `;border:1px solid ` + cEdge + `">` +
		`<tr><td style="background:` + cSide + `;padding:18px 28px"><table role="presentation" cellpadding="0" cellspacing="0"><tr>` +
		`<td valign="middle" style="padding-right:12px"><table role="presentation" cellpadding="0" cellspacing="0" style="border:1px solid ` + cSideLine + `"><tr><td style="padding:6px 5px 6px 7px"><table role="presentation" cellpadding="0" cellspacing="0"><tr>` +
		stake(18, cSideInk) + stake(23, cSideInk) + stake(23, cLogoAccent) + stake(18, cSideInk) +
		`</tr></table></td></tr></table></td>` +
		`<td valign="middle"><p style="margin:0;font:500 18px/1.1 ` + fontMono + `;color:` + cSideInk + `;text-transform:uppercase;letter-spacing:.04em">Palisade</p>` +
		`<p style="margin:4px 0 0;font:500 9px ` + fontMono + `;color:` + cSideMuted + `;text-transform:uppercase;letter-spacing:.12em">` + kicker + `</p></td>` +
		`</tr></table></td></tr>` +
		body +
		`<tr><td style="padding:16px 28px 22px;border-top:1px solid ` + cEdge + `;font:400 12px/1.6 ` + fontStack + `;color:` + cMuted + `">` +
		note + ` Sent by Palisade from ` + Sender + `.</td></tr>` +
		`</table></td></tr></table>`
}

// heading is the email's title, styled like the UI's h1: uppercase mono.
func heading(title string) string {
	return `<p style="margin:0;font:500 22px/1.2 ` + fontMono + `;color:` + cInk + `;text-transform:uppercase;letter-spacing:.02em">` + title + `</p>`
}

// section is one titled block of the card body.
func section(title, inner string) string {
	return `<tr><td style="padding:24px 28px 0">` +
		`<p style="margin:0 0 12px;font:500 11px ` + fontMono + `;color:` + cInk + `;text-transform:uppercase;letter-spacing:.08em">` + title + `</p>` +
		inner + `</td></tr>`
}

// bar is a horizontal meter: pct of the width filled with color.
func bar(pct int, color string) string {
	rest := ""
	if pct < 100 {
		rest = `<td style="background:` + cRule + `;font-size:0;line-height:0">&nbsp;</td>`
	}
	return fmt.Sprintf(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0"><tr>`+
		`<td width="%d%%" style="background:%s;height:5px;font-size:0;line-height:0">&nbsp;</td>%s</tr></table>`, max(pct, 1), color, rest)
}

// pct is n as a percentage of of, one decimal.
func pct(n, of int) string {
	if of == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", float64(n)*100/float64(of))
}

// delta describes cur against prev ("▲ 12% vs prior day"); up reports the
// direction so callers can color it. Empty when there is nothing to compare.
func delta(cur, prev int) (text string, up bool) {
	if prev == 0 {
		return "", false
	}
	d := float64(cur-prev) * 100 / float64(prev)
	switch {
	case d >= 0.5:
		return fmt.Sprintf("▲ %.0f%% vs prior day", d), true
	case d <= -0.5:
		return fmt.Sprintf("▼ %.0f%% vs prior day", -d), false
	}
	return "Same as prior day", false
}

// composeLoginCode renders the 2FA recovery-code email.
func composeLoginCode(code string, at time.Time) (subject, text, htm string) {
	subject = "WAF admin login code"
	when := at.Format("2006-01-02 15:04 MST")

	var t strings.Builder
	t.WriteString("Palisade — admin login code\n\n")
	fmt.Fprintf(&t, "Code:       %s\n", code)
	fmt.Fprintf(&t, "Requested:  %s\n", when)
	t.WriteString("\nThe code expires in 10 minutes and works once.\n")
	t.WriteString("If you didn't request it, someone knows your admin password — change it now.\n")

	body := `<tr><td style="padding:26px 28px 24px">` +
		heading("Your login code") +
		`<p style="margin:8px 0 18px;font:400 14px/1.5 ` + fontStack + `;color:` + cInkSoft + `">Enter it on the Palisade sign-in page to finish logging in.</p>` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:` + cPaper + `;border:1px dashed ` + cEdge + `"><tr><td align="center" style="padding:20px">` +
		`<p style="margin:0;font:500 32px ` + fontMono + `;letter-spacing:.3em;color:` + cInk + `">` + html.EscapeString(code) + `</p>` +
		`</td></tr></table></td></tr>`
	note := `Requested ` + when + `. The code expires in 10 minutes and works once. If you didn't request it, someone knows your admin password — change it now.`
	return subject, t.String(), frame("Admin login code", body, note)
}

// composeInvite renders the invite email: who added the user, their role,
// and the set-password link.
func composeInvite(inviter, role, link string, expires time.Time) (subject, text, htm string) {
	subject = "You've been added to Palisade"
	until := expires.Format("2006-01-02 15:04 MST")

	var t strings.Builder
	t.WriteString("Palisade — you've been added\n\n")
	fmt.Fprintf(&t, "%s added you to Palisade as %s.\n\n", inviter, role)
	t.WriteString("Set your password here:\n" + link + "\n\n")
	fmt.Fprintf(&t, "The link works once and expires %s.\n", until)
	t.WriteString("If you weren't expecting this, ignore this email.\n")

	body := `<tr><td style="padding:26px 28px 24px">` +
		heading("You've been added") +
		`<p style="margin:8px 0 18px;font:400 14px/1.5 ` + fontStack + `;color:` + cInkSoft + `"><b style="color:` + cInk + `">` + html.EscapeString(inviter) +
		`</b> added you to Palisade as <b style="color:` + cInk + `">` + html.EscapeString(role) + `</b>. Set a password to sign in.</p>` +
		`<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="background:` + cInk + `;border:1px solid ` + cInk + `">` +
		`<a href="` + html.EscapeString(link) + `" style="display:inline-block;padding:11px 20px;font:500 13px ` + fontMono + `;color:` + cPaper + `;text-decoration:none;text-transform:uppercase;letter-spacing:.04em">Set your password</a>` +
		`</td></tr></table>` +
		`<p style="margin:18px 0 0;font:400 12px/1.5 ` + fontStack + `;color:` + cMuted + `">Or paste this link into your browser:<br><span style="font-family:` + fontMono + `;color:` + cInkSoft + `;word-break:break-all">` + html.EscapeString(link) + `</span></p>` +
		`</td></tr>`
	note := `The link works once and expires ` + until + `. If you weren't expecting this, ignore this email.`
	return subject, t.String(), frame("Account invite", body, note)
}

// composeReport renders the plain-text and HTML bodies for one report window:
// headline tiles with a prior-day comparison, an hourly traffic chart, the
// block breakdown, and top blocked countries, IPs and WAF rules. Charts are
// table cells and divs, not images or SVG, so they survive every client.
func composeReport(day string, rep, prev storage.DailyReport, det storage.ReportDetails) (subject, text, htm string) {
	subject = fmt.Sprintf("WAF daily report %s — %d blocked, %d × 403, %d requests",
		day, rep.Blocked, rep.Status403, rep.Total)

	peak := storage.HourlyPoint{}
	for _, p := range det.Hourly {
		if p.Total > peak.Total {
			peak = p
		}
	}
	stages := []struct {
		label, color string
		n            int
	}{
		{"WAF rules", cStamp, rep.WAFBlocked},
		{"IP blocklist", cInk, rep.IPBlocked},
		{"Geo rules", cHighlight, rep.GeoBlocked},
		{"Rate limited", cSideMuted, rep.RateLimited},
	}

	// Plain text.
	var t strings.Builder
	fmt.Fprintf(&t, "Palisade — daily report for %s\n\n", day)
	for _, row := range []struct {
		label string
		value int
	}{
		{"Total requests", rep.Total}, {"Blocked requests", rep.Blocked}, {"403 responses", rep.Status403},
		{"Unique blocked IPs", rep.UniqueBlockedIPs}, {"WAF rule blocks", rep.WAFBlocked},
		{"IP blocklist blocks", rep.IPBlocked}, {"Geo blocks", rep.GeoBlocked},
		{"Rate limited", rep.RateLimited}, {"Bot challenges served", rep.BotChallenged},
	} {
		fmt.Fprintf(&t, "%-24s %d\n", row.label, row.value)
	}
	fmt.Fprintf(&t, "%-24s %s\n", "Block rate", pct(rep.Blocked, rep.Total))
	if d, _ := delta(rep.Total, prev.Total); d != "" {
		fmt.Fprintf(&t, "%-24s %s\n", "Requests", d)
	}
	if peak.Total > 0 {
		fmt.Fprintf(&t, "%-24s %s (%d requests)\n", "Busiest hour", peak.Hour.Format("15:04"), peak.Total)
	}
	for _, l := range []struct {
		title string
		items []storage.LabelCount
	}{{"Top blocked countries", det.TopCountries}, {"Top blocked IPs", det.TopIPs}, {"Top WAF rules", det.TopRules}} {
		if len(l.items) == 0 {
			continue
		}
		fmt.Fprintf(&t, "\n%s\n", l.title)
		for _, it := range l.items {
			fmt.Fprintf(&t, "  %-22s %d\n", it.Label, it.Count)
		}
	}
	t.WriteString("\nSent automatically by Palisade.\n")

	var h strings.Builder

	// Title and one-line summary, the key figure marked with the highlighter.
	h.WriteString(`<tr><td style="padding:26px 28px 0">`)
	h.WriteString(heading("Daily security report"))
	h.WriteString(`<p style="margin:4px 0 14px;font:500 12px ` + fontMono + `;color:` + cMuted + `">` + day + `</p>`)
	fmt.Fprintf(&h, `<p style="margin:0;font:400 15px/1.6 %s;color:%s">Palisade stopped <span style="background:%s;color:%s;padding:1px 5px;font-weight:700">%d of %d requests</span> (%s) from %d unique IPs, and served %d bot challenges.</p>`,
		fontStack, cInkSoft, cHighlight, cInk, rep.Blocked, rep.Total, pct(rep.Blocked, rep.Total), rep.UniqueBlockedIPs, rep.BotChallenged)
	h.WriteString(`</td></tr>`)

	// Headline tiles.
	tile := func(label string, value int, color, sub, subColor string) string {
		return fmt.Sprintf(`<td width="33%%" valign="top" style="padding:0 4px"><table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="border:1px solid %s;background:%s"><tr><td style="padding:12px 14px">`+
			`<p style="margin:0;%s;color:%s">%s</p>`+
			`<p style="margin:8px 0 4px;font:500 28px/1 %s;color:%s">%d</p>`+
			`<p style="margin:0;font:400 11px %s;color:%s">%s</p></td></tr></table></td>`,
			cEdge, cPaper, labelStyle, cMuted, label, fontMono, color, value, fontStack, subColor, sub)
	}
	totalDelta, _ := delta(rep.Total, prev.Total)
	blockedDelta, blockedUp := delta(rep.Blocked, prev.Blocked)
	blockedColor := cAccent
	if blockedUp {
		blockedColor = cStampInk
	}
	h.WriteString(`<tr><td style="padding:20px 24px 0"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>`)
	h.WriteString(tile("Requests", rep.Total, cInk, cmp.Or(totalDelta, "&nbsp;"), cMuted))
	h.WriteString(tile("Blocked", rep.Blocked, cStamp, cmp.Or(blockedDelta, pct(rep.Blocked, rep.Total)+" of traffic"), blockedColor))
	h.WriteString(tile("403 responses", rep.Status403, cInk, fmt.Sprintf("%d unique blocked IPs", rep.UniqueBlockedIPs), cMuted))
	h.WriteString(`</tr></table></td></tr>`)

	// Hourly chart: one column per hour, allowed stacked on blocked.
	if len(det.Hourly) > 0 {
		const chartH = 80
		var c strings.Builder
		c.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="table-layout:fixed;border-bottom:1px solid ` + cRule + `"><tr>`)
		for _, p := range det.Hourly {
			c.WriteString(`<td valign="bottom" height="` + fmt.Sprint(chartH) + `" style="padding:0 1px;height:` + fmt.Sprint(chartH) + `px">`)
			if p.Total > 0 {
				total := max(p.Total*chartH/peak.Total, 2)
				blocked := p.Blocked * total / p.Total
				if blocked == 0 && p.Blocked > 0 {
					blocked = 1
				}
				if a := total - blocked; a > 0 {
					fmt.Fprintf(&c, `<div style="height:%dpx;background:%s;font-size:0;line-height:0">&nbsp;</div>`, a, cAllowed)
				}
				if blocked > 0 {
					fmt.Fprintf(&c, `<div style="height:%dpx;background:%s;font-size:0;line-height:0">&nbsp;</div>`, blocked, cStamp)
				}
			}
			c.WriteString(`</td>`)
		}
		c.WriteString(`</tr><tr>`)
		for i, p := range det.Hourly {
			label, style := "&nbsp;", "color:"+cMuted
			if p.Total > 0 && p.Hour.Equal(peak.Hour) {
				label, style = p.Hour.Format("15"), "background:"+cHighlight+";color:"+cInk
			} else if i%6 == 0 {
				label = p.Hour.Format("15")
			}
			fmt.Fprintf(&c, `<td align="center" style="padding-top:5px;font:500 9px %s;%s">%s</td>`, fontMono, style, label)
		}
		c.WriteString(`</tr></table>`)
		legend := fmt.Sprintf(`<p style="margin:10px 0 0;font:400 12px %s;color:%s">`+
			`<span style="color:%s">&#9632;</span> Allowed &nbsp; <span style="color:%s">&#9632;</span> Blocked`, fontStack, cMuted, cAllowed, cStamp)
		if peak.Total > 0 {
			legend += fmt.Sprintf(` &nbsp;·&nbsp; Busiest hour <b style="color:%s">%s</b> with %d requests`, cInk, peak.Hour.Format("15:04"), peak.Total)
		}
		h.WriteString(section("Traffic by hour", c.String()+legend+`</p>`))
	}

	// Block breakdown: one stacked bar, then a legend with counts.
	if staged := rep.WAFBlocked + rep.IPBlocked + rep.GeoBlocked + rep.RateLimited; staged > 0 {
		var c strings.Builder
		c.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>`)
		for _, s := range stages {
			if s.n > 0 {
				fmt.Fprintf(&c, `<td width="%d%%" style="background:%s;height:12px;font-size:0;line-height:0">&nbsp;</td>`, max(s.n*100/staged, 1), s.color)
			}
		}
		c.WriteString(`</tr></table><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px">`)
		for _, s := range stages {
			fmt.Fprintf(&c, `<tr><td style="padding:5px 0;border-bottom:1px solid %s;font:400 13px %s;color:%s"><span style="color:%s">&#9632;</span>&nbsp; %s</td>`+
				`<td align="right" style="padding:5px 0;border-bottom:1px solid %s;font:500 13px %s;color:%s">%d</td>`+
				`<td align="right" width="60" style="padding:5px 0;border-bottom:1px solid %s;font:400 12px %s;color:%s">%s</td></tr>`,
				cRule, fontStack, cInkSoft, s.color, s.label, cRule, fontMono, cInk, s.n, cRule, fontMono, cMuted, pct(s.n, staged))
		}
		c.WriteString(`</table>`)
		h.WriteString(section("What stopped them", c.String()))
	}

	// Top-N lists: label, count, and a meter scaled to the list's leader.
	list := func(items []storage.LabelCount, empty string) string {
		if len(items) == 0 {
			return `<p style="margin:0;font:400 13px ` + fontStack + `;color:` + cMuted + `">` + empty + `</p>`
		}
		var c strings.Builder
		c.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0">`)
		for _, it := range items {
			fmt.Fprintf(&c, `<tr><td style="padding-top:6px;font:500 12px %s;color:%s">%s</td><td align="right" style="padding-top:6px;font:500 12px %s;color:%s">%d</td></tr>`+
				`<tr><td colspan="2" style="padding:4px 0 4px">%s</td></tr>`,
				fontMono, cInk, html.EscapeString(it.Label), fontMono, cInkSoft, it.Count, bar(it.Count*100/items[0].Count, cStamp))
		}
		c.WriteString(`</table>`)
		return c.String()
	}
	col := func(title, inner string) string {
		return `<td width="50%" valign="top" style="padding:0 4px"><p style="margin:0 0 4px;` + labelStyle + `;color:` + cMuted + `">` + title + `</p>` + inner + `</td>`
	}
	h.WriteString(section("Who got blocked",
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>`+
			col("Countries", list(det.TopCountries, "No country data."))+
			col("IP addresses", list(det.TopIPs, "Nothing blocked."))+
			`</tr></table>`))
	h.WriteString(section("Top WAF rules", list(det.TopRules, "No WAF rule fired.")))
	h.WriteString(`<tr><td style="padding:0 0 26px"></td></tr>`)

	return subject, t.String(), frame("Daily security report", h.String(), "Counts cover "+day+". Rule IDs are OWASP CRS; look them up on the WAF Rules page.")
}

// composeBanAlert renders the notice sent when the autoban package bans an IP.
func composeBanAlert(ip, reason string, at time.Time) (subject, text, htm string) {
	subject = fmt.Sprintf("WAF banned IP %s", ip)
	when := at.Format("2006-01-02 15:04 MST")

	var t strings.Builder
	fmt.Fprintf(&t, "Palisade — automatic IP ban\n\n")
	fmt.Fprintf(&t, "IP address:  %s\n", ip)
	fmt.Fprintf(&t, "Reason:      %s\n", reason)
	fmt.Fprintf(&t, "Banned at:   %s\n", when)
	fmt.Fprintf(&t, "Scope:       Global (all services)\n\n")
	t.WriteString("The IP now appears on the IP Rules page, where the ban can be lifted.\n")

	var h strings.Builder
	h.WriteString(`<tr><td style="padding:26px 28px 0">`)
	h.WriteString(heading("An IP was banned"))
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;background:` + cStampTint + `;border:1px solid ` + cEdge + `;border-left:4px solid ` + cStamp + `"><tr><td style="padding:14px 18px">`)
	h.WriteString(`<p style="margin:0;` + labelStyle + `;color:` + cStampInk + `">Blocked on every service</p>`)
	h.WriteString(`<p style="margin:6px 0 0;font:500 22px ` + fontMono + `;color:` + cInk + `">` + html.EscapeString(ip) + `</p>`)
	h.WriteString(`</td></tr></table></td></tr>`)

	var d strings.Builder
	d.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0">`)
	for _, row := range []struct{ label, value string }{
		{"Reason", reason}, {"Banned at", when}, {"Scope", "Global (all services)"}, {"Expires", "Never — remove the rule to lift it"},
	} {
		fmt.Fprintf(&d, `<tr><td width="110" style="padding:9px 0;border-bottom:1px solid %s;font:400 13px %s;color:%s">%s</td>`+
			`<td style="padding:9px 0;border-bottom:1px solid %s;font:500 13px %s;color:%s">%s</td></tr>`,
			cRule, fontStack, cMuted, row.label, cRule, fontStack, cInk, html.EscapeString(row.value))
	}
	d.WriteString(`</table>`)
	h.WriteString(section("Details", d.String()))
	h.WriteString(`<tr><td style="padding:0 0 24px"></td></tr>`)

	return subject, t.String(), frame("Automatic IP ban", h.String(), "The ban is a global block rule on the IP Rules page — remove it there to lift it.")
}
