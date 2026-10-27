package blocklist

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"

	"palisade/internal/storage"
)

func openDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCheckPriority(t *testing.T) {
	db := openDB(t)
	for _, r := range [][3]string{
		{"shop", "1.1.1.1", "block"},
		{"shop", "10.0.0.0/8", "allow"},
		{"", "2.2.2.2", "block"},
		{"", "10.0.0.0/8", "block"},
		{"", "192.168.0.0/16", "block"},
		{"", "9.9.9.9", "allow"},
	} {
		if err := db.AddIPRule(r[0], r[1], r[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddThreatIntelSource("feed", "http://example.invalid", 24); err != nil {
		t.Fatal(err)
	}
	srcs, _ := db.ListThreatIntelSources()
	if err := db.ReplaceThreatIntelIPs(srcs[0].ID, []string{"9.9.9.9", "3.3.3.3", "172.16.0.0/12", "2001:db8::/32"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCrowdSecSource("cs", "http://lapi.invalid", "key"); err != nil {
		t.Fatal(err)
	}
	srcs, _ = db.ListThreatIntelSources()
	if err := db.ReplaceThreatIntelIPs(srcs[1].ID, []string{"5.5.5.5", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}

	bl, err := NewIPBlocklist(db)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip, app    string
		wantBlock  bool
		wantReason string
	}{
		{"1.1.1.1", "shop", true, "ip_blocked"},
		{"1.1.1.1", "other", false, ""},
		{"10.1.2.3", "shop", false, ""}, // per-app allow beats global CIDR block
		{"10.1.2.3", "other", true, "ip_blocked_global"},
		{"2.2.2.2", "shop", true, "ip_blocked_global"},
		{"192.168.1.1", "", true, "ip_blocked_global"},
		{"9.9.9.9", "", false, ""}, // user allow beats intel
		{"3.3.3.3", "", true, "ip_blocked_intel"},
		{"172.16.5.5", "", true, "ip_blocked_intel"},
		{"172.32.0.0", "", false, ""}, // just past the /12
		{"2001:db8:ffff::1", "", true, "ip_blocked_intel"},
		{"2001:db9::1", "", false, ""},
		{"::ffff:3.3.3.3", "", true, "ip_blocked_intel"},
		{"5.5.5.5", "", true, "ip_blocked:crowdsec"},
		{"198.51.100.255", "", true, "ip_blocked:crowdsec"},
		{"8.8.8.8", "", false, ""},
		{"not-an-ip", "", false, ""},
	}
	for _, tt := range tests {
		blocked, reason := bl.Check(tt.ip, tt.app)
		if blocked != tt.wantBlock || reason != tt.wantReason {
			t.Errorf("Check(%q,%q) = %v,%q want %v,%q", tt.ip, tt.app, blocked, reason, tt.wantBlock, tt.wantReason)
		}
	}
}

func TestReloadPicksUpNewRules(t *testing.T) {
	db := openDB(t)
	bl, err := NewIPBlocklist(db)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := bl.Check("4.4.4.4", ""); blocked {
		t.Fatal("blocked before rule exists")
	}
	_ = db.AddIPRule("", "4.4.4.4", "block")
	if err := bl.Reload(db); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := bl.Check("4.4.4.4", ""); !blocked {
		t.Fatal("not blocked after Reload")
	}
}

func TestReloadErrorsOnClosedDB(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	bl, _ := NewIPBlocklist(db)
	db.Close()
	if err := bl.Reload(db); err == nil {
		t.Error("Reload on closed DB should error")
	}
	if err := bl.ReloadIntel(db); err == nil {
		t.Error("ReloadIntel on closed DB should error")
	}
	if _, err := NewIPBlocklist(db); err == nil {
		t.Error("NewIPBlocklist on closed DB should error")
	}
}

// TestRangeSetMerges pins the sorted range set behind intel lookups: nested
// and overlapping ranges merge, and IPv4 never matches an IPv6 range.
func TestRangeSetMerges(t *testing.T) {
	rs := buildRangeSet(appendRanges(nil, []string{"10.0.0.0/8", "10.1.0.0/16", "10.255.255.255", "11.0.0.0/9", "::/0", "bad"}, "x"))
	if len(rs) != 3 {
		t.Fatalf("ranges = %v, want 3 after merging", rs)
	}
	for ip, want := range map[string]string{
		"10.200.0.1": "x", "11.127.255.255": "x", "11.128.0.0": "", "9.255.255.255": "", "2001:db8::1": "x",
	} {
		if got := rs.lookup(netip.MustParseAddr(ip)); got != want {
			t.Errorf("lookup(%s) = %q, want %q", ip, got, want)
		}
	}
}

// BenchmarkIntelLookup checks issue #194's bound: a lookup against 100k
// ranges stays in the sub-microsecond range.
func BenchmarkIntelLookup(b *testing.B) {
	entries := make([]string, 0, 100000)
	for i := range 100000 {
		entries = append(entries, fmt.Sprintf("%d.%d.%d.0/25", 1+i/65536, (i/256)%256, i%256))
	}
	bl := &IPBlocklist{intel: buildRangeSet(appendRanges(nil, entries, "ip_blocked_intel"))}
	if len(bl.intel) != len(entries) {
		b.Fatalf("%d ranges, want %d unmerged", len(bl.intel), len(entries))
	}
	b.ResetTimer()
	for i := range b.N {
		bl.Check(fmt.Sprintf("1.%d.%d.7", (i/256)%256, i%256), "")
	}
}
