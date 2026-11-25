package threatscore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"palisade/internal/storage"

	"github.com/ip2location/ip2proxy-go/v4"
)

// binRange is one row of a synthetic IP2Proxy BIN. Rows are a partition:
// an address belongs to the row with the greatest start <= the address,
// and the last row is the end sentinel the reader uses as the final
// range's upper bound (ip2proxy-go v4.2.0 reads the next row's start as
// ipTo, and the header count is the last index, so the file has count+1
// rows plus the next address — 4 bytes for IPv4, 16 for IPv6 — past that
// sentinel).
type binRange struct {
	ip   netip.Addr
	kind string
}

// buildProxyBIN writes a minimal BIN the official reader accepts.
//
// Layout matches OpenDBWithReader and query in ip2proxy-go v4.2.0:
// a 64-byte little-endian header, then the rows, then a string heap.
// Header data addresses are 1-based (readRow subtracts 1). A string
// pointer is the 0-based offset of a length byte followed by that many
// bytes (readStr does not subtract 1). Country is stored as the 2-letter
// code plus the long name; the reader takes the long name at pointer+3.
// IPv4 starts are little-endian uint32. IPv6 starts are the network-order
// address reversed, which is what checkIP feeds to little-endian
// uint128.FromBytes. The column count is the caller's: PX1 is 2 (country
// only), PX2 is 3 (proxy type, country). A PX12 header with column count
// 3 is the panic fixture — the row is shorter than the fraud-score offset.
func buildProxyBIN(dbType, columns byte, v4, v6 []binRange) []byte {
	v4 = append([]binRange(nil), v4...)
	v6 = append([]binRange(nil), v6...)
	sort.Slice(v4, func(i, j int) bool { return v4[i].ip.Compare(v4[j].ip) < 0 })
	sort.Slice(v6, func(i, j int) bool { return v6[i].ip.Compare(v6[j].ip) < 0 })

	var blob []byte
	add := func(s string) int {
		at := len(blob)
		blob = append(blob, byte(len(s)))
		blob = append(blob, s...)
		return at
	}
	kindAt := map[string]int{}
	remember := func(kind string) {
		if kind == "" {
			kind = "-"
		}
		if _, ok := kindAt[kind]; ok {
			return
		}
		kindAt[kind] = add(kind)
	}
	remember("-")
	for _, r := range v4 {
		remember(r.kind)
	}
	for _, r := range v6 {
		remember(r.kind)
	}
	countryUS := len(blob)
	blob = append(blob, byte(len("US")))
	blob = append(blob, "US"...)
	blob = append(blob, byte(len("United States")))
	blob = append(blob, "United States"...)
	countryDash := len(blob)
	blob = append(blob, byte(len("-")))
	blob = append(blob, '-')
	blob = append(blob, byte(len("-")))
	blob = append(blob, '-')

	v4Row := int(columns) * 4
	v6Row := 16 + int(columns-1)*4
	// The search reads one row plus the next address (4 bytes IPv4, 16 IPv6)
	// past the sentinel. Those pad bytes are the sentinel's ipTo; leaving
	// them zero makes every address at or above the sentinel a clean miss
	// instead of a read of the string heap.
	v4Size, v6Size := 0, 0
	if len(v4) > 0 {
		v4Size = len(v4)*v4Row + 4
	}
	if len(v6) > 0 {
		v6Size = len(v6)*v6Row + 16
	}
	stringBase := 64 + v4Size + v6Size
	abs := func(rel int) uint32 { return uint32(stringBase + rel) }

	out := make([]byte, stringBase+len(blob))
	out[0] = dbType
	out[1] = columns
	out[2] = 26 // 2026
	out[3] = 1
	out[4] = 1
	if len(v4) > 0 {
		binary.LittleEndian.PutUint32(out[5:], uint32(len(v4)-1))
		binary.LittleEndian.PutUint32(out[9:], 65) // 1-based offset of byte 64
	}
	if len(v6) > 0 {
		binary.LittleEndian.PutUint32(out[13:], uint32(len(v6)-1))
		binary.LittleEndian.PutUint32(out[17:], uint32(64+v4Size+1))
	}
	out[29] = 2 // IP2Proxy product code; required when the year byte is >= 21
	out[30] = 1
	binary.LittleEndian.PutUint32(out[31:], uint32(len(out)))

	ptrs := func(kind string) []uint32 {
		n := int(columns) - 1
		p := make([]uint32, n)
		country := abs(countryUS)
		// PX1's only field is the country. A "-" row is the "not a proxy"
		// marker (IsProxy becomes 0); any other kind is a listed proxy.
		if dbType == 1 && kind == "-" {
			country = abs(countryDash)
		}
		if dbType == 1 {
			if n > 0 {
				p[0] = country
			}
			return p
		}
		if n > 0 {
			p[0] = abs(kindAt[kind])
		}
		if n > 1 {
			p[1] = country
		}
		return p
	}
	for i, r := range v4 {
		putV4(out[64+i*v4Row:], r.ip, ptrs(r.kind))
	}
	v6Base := 64 + v4Size
	for i, r := range v6 {
		putV6(out[v6Base+i*v6Row:], r.ip, ptrs(r.kind))
	}
	copy(out[stringBase:], blob)
	return out
}

func putV4(dst []byte, ip netip.Addr, ptrs []uint32) {
	b := ip.As4()
	dst[0], dst[1], dst[2], dst[3] = b[3], b[2], b[1], b[0]
	for i, p := range ptrs {
		binary.LittleEndian.PutUint32(dst[4+i*4:], p)
	}
}

func putV6(dst []byte, ip netip.Addr, ptrs []uint32) {
	b := ip.As16()
	for i := 0; i < 16; i++ {
		dst[i] = b[15-i]
	}
	for i, p := range ptrs {
		binary.LittleEndian.PutUint32(dst[16+i*4:], p)
	}
}

func writeProxyFile(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.bin")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func openProxyFile(t *testing.T, raw []byte) *ip2proxy.DB {
	t.Helper()
	db, err := OpenProxyDB(writeProxyFile(t, raw))
	if err != nil {
		t.Fatalf("OpenProxyDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// px2Sample is a PX2 BIN: proxy type plus country, the smallest package
// that carries a type string. 203.0.113.0/24 and 2001:db8::/32 hold the
// cases; everything else in the covered span is an explicit "-".
func px2Sample() []byte {
	v4 := []binRange{
		{netip.MustParseAddr("0.0.0.0"), "-"},
		{netip.MustParseAddr("203.0.113.1"), "VPN"},
		{netip.MustParseAddr("203.0.113.2"), "TOR"},
		{netip.MustParseAddr("203.0.113.3"), "DCH"},
		{netip.MustParseAddr("203.0.113.4"), "PUB"},
		{netip.MustParseAddr("203.0.113.5"), "WEB"},
		{netip.MustParseAddr("203.0.113.6"), "RES"},
		{netip.MustParseAddr("203.0.113.7"), "SES"},
		{netip.MustParseAddr("203.0.113.8"), "AIC"},
		{netip.MustParseAddr("203.0.113.9"), "CPN"},
		{netip.MustParseAddr("203.0.113.10"), "EPN"},
		{netip.MustParseAddr("203.0.113.11"), "-"},
		{netip.MustParseAddr("203.0.113.12"), "-"}, // sentinel: .11 is one address, .50 is absent
	}
	v6 := []binRange{
		{netip.MustParseAddr("::"), "-"},
		{netip.MustParseAddr("2001:db8::1"), "PUB"},
		{netip.MustParseAddr("2001:db8::2"), "SES"},
		{netip.MustParseAddr("2001:db8::3"), "-"},
	}
	return buildProxyBIN(2, 3, v4, v6)
}

// px1Sample is a PX1 BIN, the LITE IP-Country package: no proxy-type
// column. A row with a real country is a public proxy; "-" is not.
func px1Sample() []byte {
	v4 := []binRange{
		{netip.MustParseAddr("0.0.0.0"), "-"},
		{netip.MustParseAddr("203.0.113.20"), "PUB"},
		{netip.MustParseAddr("203.0.113.21"), "-"},
	}
	v6 := []binRange{
		{netip.MustParseAddr("::"), "-"},
		{netip.MustParseAddr("2001:db8::20"), "PUB"},
		{netip.MustParseAddr("2001:db8::21"), "-"},
	}
	return buildProxyBIN(1, 2, v4, v6)
}

func TestGeneratedBINProxyTypes(t *testing.T) {
	db := openProxyFile(t, px2Sample())
	if db.PackageVersion() != "2" {
		t.Fatalf("package = %s, want 2", db.PackageVersion())
	}
	// IsProxy is what the reader reports, not what we score. 2 covers both
	// DCH (scored) and SES/AIC (not), which is why the type string decides.
	cases := []struct {
		ip       string
		wantType string
		wantIs   int8
	}{
		{"203.0.113.1", "VPN", 1},
		{"203.0.113.2", "TOR", 1},
		{"203.0.113.3", "DCH", 2},
		{"203.0.113.4", "PUB", 1},
		{"203.0.113.5", "WEB", 1},
		{"203.0.113.6", "RES", 1},
		{"203.0.113.7", "SES", 2},
		{"203.0.113.8", "AIC", 2},
		{"203.0.113.9", "CPN", 1},
		{"203.0.113.10", "EPN", 1},
		{"203.0.113.11", "-", 0},
		{"8.8.8.8", "-", 0},
		{"203.0.113.50", "NOT SUPPORTED", -1},
		{"2001:db8::1", "PUB", 1},
		{"2001:db8::2", "SES", 2},
		{"2001:db8::9", "NOT SUPPORTED", -1},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			rec, err := db.GetAll(tc.ip)
			if err != nil {
				t.Fatalf("GetAll: %v", err)
			}
			if rec.ProxyType != tc.wantType || rec.IsProxy != tc.wantIs {
				t.Fatalf("type %q IsProxy %d, want type %q IsProxy %d", rec.ProxyType, rec.IsProxy, tc.wantType, tc.wantIs)
			}
		})
	}
}

func TestProxyScoreORsHeuristic(t *testing.T) {
	db := openProxyFile(t, px2Sample())
	const residential = "Comcast Cable Communications"
	cases := []struct {
		name string
		ip   string
		asn  uint
		org  string
		want int
	}{
		{"vpn", "203.0.113.1", 7922, residential, asnScore},
		{"tor", "203.0.113.2", 7922, residential, asnScore},
		{"dch", "203.0.113.3", 7922, residential, asnScore},
		{"pub", "203.0.113.4", 7922, residential, asnScore},
		{"web", "203.0.113.5", 7922, residential, asnScore},
		{"res", "203.0.113.6", 7922, residential, asnScore},
		{"ses skipped", "203.0.113.7", 7922, residential, 0},
		{"aic skipped", "203.0.113.8", 7922, residential, 0},
		{"cpn skipped", "203.0.113.9", 7922, residential, 0},
		{"epn skipped", "203.0.113.10", 7922, residential, 0},
		{"dash row", "203.0.113.11", 7922, residential, 0},
		{"miss", "203.0.113.50", 7922, residential, 0},
		{"ses still uses heuristic", "203.0.113.7", 16509, "Amazon.com, Inc.", asnScore},
		{"hit and heuristic stay flat", "203.0.113.1", 16509, "Amazon.com, Inc.", asnScore},
		{"miss still uses heuristic", "203.0.113.50", 16509, "Amazon.com, Inc.", asnScore},
		{"ipv6 hit", "2001:db8::1", 7922, residential, asnScore},
		{"ipv6 skipped", "2001:db8::2", 7922, residential, 0},
		{"ipv6 miss", "2001:db8::9", 7922, residential, 0},
		{"ipv6 hit and heuristic stay flat", "2001:db8::1", 16509, "Amazon.com, Inc.", asnScore},
		{"garbage ip", "not-an-ip", 7922, residential, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			s := testScorer(store, nil)
			s.setProxy(db)
			s.Record(storage.RequestLog{RealIP: tc.ip, ASN: tc.asn, Org: tc.org})
			got := store.scores[tc.ip]
			if got.ASNScore != tc.want || got.Total != tc.want {
				t.Fatalf("ASNScore %d Total %d, want %d (flat, not doubled)", got.ASNScore, got.Total, tc.want)
			}
		})
	}
}

func TestNoProxyDBKeepsHeuristicOnly(t *testing.T) {
	store := newFakeStore()
	s := testScorer(store, nil)
	// 203.0.113.1 would be VPN in px2Sample. With no BIN it is only the heuristic.
	s.Record(storage.RequestLog{RealIP: "203.0.113.1", ASN: 7922, Org: "Comcast Cable Communications"})
	if got := store.scores["203.0.113.1"].ASNScore; got != 0 {
		t.Fatalf("ASNScore without a BIN = %d, want 0", got)
	}
	s.Record(storage.RequestLog{RealIP: "203.0.113.99", ASN: 16509, Org: "Amazon.com, Inc."})
	if got := store.scores["203.0.113.99"].ASNScore; got != asnScore {
		t.Fatalf("hosting ASN without a BIN = %d, want %d", got, asnScore)
	}
}

func TestPX1LITEScoresListedAddresses(t *testing.T) {
	db := openProxyFile(t, px1Sample())
	if db.PackageVersion() != "1" {
		t.Fatalf("package = %s, want 1", db.PackageVersion())
	}
	hit, err := db.GetAll("203.0.113.20")
	if err != nil {
		t.Fatal(err)
	}
	// PX1 does not return "PUB". The address is in the file (IsProxy 1)
	// and the type column is absent, which LITE defines as a public proxy.
	if hit.ProxyType != "NOT SUPPORTED" || hit.IsProxy != 1 || hit.CountryShort != "US" {
		t.Fatalf("PX1 hit = type %q IsProxy %d country %q", hit.ProxyType, hit.IsProxy, hit.CountryShort)
	}
	miss, err := db.GetAll("203.0.113.50")
	if err != nil {
		t.Fatal(err)
	}
	if miss.IsProxy != -1 {
		t.Fatalf("PX1 miss IsProxy = %d, want -1", miss.IsProxy)
	}

	const residential = "Comcast Cable Communications"
	cases := []struct {
		name string
		ip   string
		asn  uint
		want int
	}{
		{"listed", "203.0.113.20", 7922, asnScore},
		{"dash country", "8.8.8.8", 7922, 0},
		{"absent", "203.0.113.50", 7922, 0},
		{"absent still uses heuristic", "203.0.113.50", 16509, asnScore},
		{"ipv6 listed", "2001:db8::20", 7922, asnScore},
		{"ipv6 absent", "2001:db8::50", 7922, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			s := testScorer(store, nil)
			s.setProxy(db)
			org := residential
			if tc.asn == 16509 {
				org = "Amazon.com, Inc."
			}
			s.Record(storage.RequestLog{RealIP: tc.ip, ASN: tc.asn, Org: org})
			if got := store.scores[tc.ip].ASNScore; got != tc.want {
				t.Fatalf("ASNScore = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestProxyLookupPanicIsAMiss(t *testing.T) {
	// PX12's fraud-score column sits past a 3-column row, so GetAll panics
	// once a row matches. OpenDB itself succeeds; OpenProxyDB must not.
	raw := buildProxyBIN(12, 3, []binRange{
		{netip.MustParseAddr("203.0.113.1"), "VPN"},
		{netip.MustParseAddr("203.0.113.2"), "DCH"},
		{netip.MustParseAddr("203.0.113.3"), "-"},
	}, nil)
	path := writeProxyFile(t, raw)

	db, err := ip2proxy.OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	store := newFakeStore()
	s := testScorer(store, nil)
	s.setProxy(db)
	s.Record(storage.RequestLog{RealIP: "203.0.113.1", ASN: 7922, Org: "Comcast Cable Communications"})
	s.Record(storage.RequestLog{RealIP: "203.0.113.2", ASN: 16509, Org: "Amazon.com, Inc."})

	if got := store.scores["203.0.113.1"].ASNScore; got != 0 {
		t.Fatalf("panicking lookup scored %d, want 0", got)
	}
	if got := store.scores["203.0.113.2"].ASNScore; got != asnScore {
		t.Fatalf("heuristic after a panic = %d, want %d", got, asnScore)
	}
	if n := strings.Count(buf.String(), "panicked"); n != 1 {
		t.Fatalf("panic log count = %d, want 1\n%s", n, buf.String())
	}
}

func TestOpenProxyDBRejectsBadFiles(t *testing.T) {
	good := writeProxyFile(t, px2Sample())
	db, err := OpenProxyDB(good)
	if err != nil {
		t.Fatalf("valid BIN: %v", err)
	}
	_ = db.Close()

	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.bin")
	if _, err := OpenProxyDB(missing); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}

	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	zeros := make([]byte, 64)
	zip := make([]byte, 64)
	copy(zip, "PK")
	weird := make([]byte, 64)
	weird[0] = 99
	weird[2] = 26
	weird[29] = 2
	truncated := make([]byte, 64)
	truncated[0] = 2
	truncated[1] = 3
	truncated[2] = 26
	truncated[29] = 2
	binary.LittleEndian.PutUint32(truncated[5:], 1)
	binary.LittleEndian.PutUint32(truncated[9:], 65)

	cases := []struct {
		name string
		path string
		want string
	}{
		{"empty", write("empty.bin", nil), "empty.bin"},
		{"text", write("text.bin", []byte("this is not a database")), "text.bin"},
		{"zip", write("zip.bin", zip), "Incorrect IP2Proxy"},
		{"zero header", write("zero.bin", zeros), "database type"},
		{"type 99", write("type99.bin", weird), "invalid IP2Proxy BIN"},
		{"truncated", write("trunc.bin", truncated), "invalid IP2Proxy BIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OpenProxyDB(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenProxyDB = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	if _, err := OpenProxyDB(""); err == nil {
		t.Fatal("empty path opened")
	}
}
