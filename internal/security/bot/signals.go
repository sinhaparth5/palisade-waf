package bot

import (
	"net/http"
	"strings"
)

// knownScanners are attack/audit tools that always get a high score.
var knownScanners = []string{
	"nikto", "nuclei", "sqlmap", "nmap/", "masscan", "zgrab",
	"dirbuster", "gobuster", "wfuzz", "ffuf", "hydra", "burpsuite",
	"zap/", "nessus", "openvas",
}

// httpLibFragments are generic HTTP client libraries — suspicious but not
// necessarily malicious; scored lower so they can't cross the threshold alone.
var httpLibFragments = []string{
	"curl/", "python-requests/", "python-urllib", "python/",
	"go-http-client/", "wget/", "libwww-perl/", "scrapy/",
	"okhttp/", "restsharp", "apache-httpclient", "java/",
	"axios/", "node-fetch", "node.js", "phpunit",
}

// Analysis is the result of inspecting one HTTP request for bot-like signals.
type Analysis struct {
	Score            int
	Signals          []string
	IsBot            bool // true if a confirmed attack/scanner tool was detected
	IsTrustedCrawler bool // true if UA and source IP match a known-good SEO/social crawler
	// AICategory is set when the UA names an AI crawler, verified or not, so
	// "block" applies to spoofers too; AIVerified gates "allow".
	AICategory string
	AIVerified bool
}

// Analyze scores r for bot-like characteristics. It only reads headers
// already parsed by net/http, except when the UA claims to be a trusted
// crawler: that claim is checked against ip/asnNum (see verifyCrawler), which
// can cost one cached DNS round-trip.
func Analyze(r *http.Request, ip string, asnNum uint) Analysis {
	var a Analysis
	ua := r.Header.Get("User-Agent")
	uaLow := strings.ToLower(ua)

	// Verified crawlers bypass all scoring and are never challenged. They
	// still pass through the Coraza WAF for payload inspection. A UA that
	// claims to be one but fails verification is scored like anyone else.
	// An AI crawler is scored as usual: whether it skips the challenge is
	// up to the AI crawler policy (issue #187), not to verification alone.
	if c := matchCrawler(uaLow); c != nil && c.ai != "" {
		a.AICategory = c.ai
		a.AIVerified = verifyCrawler(c, ip, asnNum)
		if a.AIVerified {
			a.Signals = append(a.Signals, "ai_crawler")
		} else {
			a.Signals = append(a.Signals, "unverified_crawler")
		}
	} else if c != nil {
		if verifyCrawler(c, ip, asnNum) {
			a.IsTrustedCrawler = true
			a.Signals = append(a.Signals, "trusted_crawler")
			return a
		}
		a.Signals = append(a.Signals, "unverified_crawler")
	}

	switch ua {
	case "":
		a.add(5, "missing_ua")
	default:
		for _, s := range knownScanners {
			if strings.Contains(uaLow, s) {
				a.add(10, "scanner_ua")
				a.IsBot = true
				break
			}
		}
		if !a.IsBot {
			for _, s := range httpLibFragments {
				if strings.Contains(uaLow, s) {
					a.add(3, "http_lib_ua")
					break
				}
			}
		}
		if !a.IsBot && len(ua) < 10 {
			a.add(2, "short_ua")
		}
	}

	if r.Header.Get("Accept-Language") == "" {
		a.add(2, "no_accept_language")
	}
	if r.Header.Get("Accept") == "" {
		a.add(1, "no_accept")
	}
	if r.Header.Get("Accept-Encoding") == "" {
		a.add(1, "no_accept_encoding")
	}

	return a
}

func (a *Analysis) add(n int, signal string) {
	a.Score += n
	a.Signals = append(a.Signals, signal)
}
