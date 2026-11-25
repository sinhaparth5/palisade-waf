package threatscore

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strconv"

	"github.com/ip2location/ip2proxy-go/v4"
)

// OpenProxyDB opens an IP2Proxy BIN at path for the hosting/VPN threat
// signal. Call it once from startup and pass the DB to New; close it only
// after the log worker has drained. A missing file, a file that is not a
// PX1–PX12 BIN, or a lookup that panics or errors is returned so startup
// can fail before traffic is accepted. An empty path is an error: the
// caller skips the call when --proxy-db is unset.
func OpenProxyDB(path string) (*ip2proxy.DB, error) {
	if path == "" {
		return nil, errors.New("empty IP2Proxy BIN path")
	}
	db, err := openProxyDB(path)
	if err != nil {
		return nil, err
	}
	ver, convErr := strconv.Atoi(db.PackageVersion())
	// ip2proxy-go indexes its column tables by the type byte and only
	// defines PX1–PX12. Anything else is not a BIN this reader can use;
	// a later lookup would panic on the table.
	if convErr != nil || ver < 1 || ver > 12 {
		_ = db.Close()
		return nil, fmt.Errorf("invalid IP2Proxy BIN %q: database type %s", path, db.PackageVersion())
	}
	if err := probeProxyDB(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("invalid IP2Proxy BIN %q: %w", path, err)
	}
	return db, nil
}

// openProxyDB is OpenDB with a panic turned into an error. A type byte
// past the reader's column tables panics inside OpenDB instead of
// returning the format error.
func openProxyDB(path string) (db *ip2proxy.DB, err error) {
	defer func() {
		if r := recover(); r != nil {
			if db != nil {
				_ = db.Close()
				db = nil
			}
			err = fmt.Errorf("invalid IP2Proxy BIN %q: %v", path, r)
		}
	}()
	opened, openErr := ip2proxy.OpenDB(path)
	if openErr != nil {
		return nil, fmt.Errorf("IP2Proxy BIN %q: %w", path, openErr)
	}
	return opened, nil
}

// probeProxyDB fails startup on a header that opens but cannot answer a
// lookup (truncated row data, a column count too small for the package).
// A well-formed BIN returns a record or the reader's "not found" message
// with a nil error for every address, including an IPv4-only file. The
// highest address of each family walks the search to the last row of its
// table, so a file cut short inside the rows fails here, not on traffic.
func probeProxyDB(db *ip2proxy.DB) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("lookup panicked: %v", r)
		}
	}()
	for _, ip := range []string{"8.8.8.8", "255.255.255.255", "2001:4860:4860::8888", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if _, err = db.GetAll(ip); err != nil {
			return fmt.Errorf("lookup %s: %w", ip, err)
		}
	}
	return nil
}

// proxyKind is an IP2Proxy record's proxy type, "" when the address isn't
// listed. IsProxy is 2 for DCH, SES and AIC alike, so the type string is
// what tells them apart.
//
// PX1 has no proxy-type column — the reader's position table stores 0 for
// that package — so GetAll leaves ProxyType as its placeholder and sets
// IsProxy to 1 when the address is in the file. LITE PX1 is a list of
// public proxies, so a PX1 listing is PUB. A miss stays IsProxy -1 with
// the same placeholder, and a "-" country is IsProxy 0.
func proxyKind(rec ip2proxy.IP2ProxyRecord, px1 bool) string {
	switch rec.ProxyType {
	case "VPN", "TOR", "DCH", "PUB", "WEB", "RES", "SES", "AIC", "CPN", "EPN":
		return rec.ProxyType
	}
	if px1 && rec.IsProxy == 1 {
		return "PUB"
	}
	return ""
}

// scoredKinds are the proxy types that count as the hosting/VPN signal.
// SES and AIC are crawlers, which have their own handling; CPN and EPN are
// consumer privacy networks (iCloud Private Relay) and enterprise networks,
// whose users shouldn't be scored for them.
var scoredKinds = map[string]bool{"VPN": true, "TOR": true, "DCH": true, "PUB": true, "WEB": true, "RES": true}

// proxyHit reports whether ip's proxy type counts as the hosting signal.
func (s *Scorer) proxyHit(ip string) bool { return scoredKinds[s.ProxyType(ip)] }

// ProxyType is ip's IP2Proxy type (VPN, TOR, DCH, PUB, WEB, RES, SES, AIC,
// CPN or EPN), or "" without --proxy-db, for an address the file doesn't
// list, or for anything that isn't a single address (a CIDR rule). Safe
// from any goroutine: the reader only reads the file.
func (s *Scorer) ProxyType(ip string) string {
	if s == nil || s.proxy == nil {
		return ""
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return ""
	}
	// The file never changes while it is open, so an address's answer
	// doesn't either. A lookup is ~20 file reads; most requests come from
	// an address seen moments ago.
	s.proxyMu.Lock()
	kind, ok := s.proxySeen[ip]
	s.proxyMu.Unlock()
	if ok {
		return kind
	}
	kind = s.lookupProxy(ip)
	s.proxyMu.Lock()
	// ponytail: dropped whole when full; an LRU only if a busy server
	// keeps refilling it.
	if len(s.proxySeen) >= proxyCacheMax {
		clear(s.proxySeen)
	}
	s.proxySeen[ip] = kind
	s.proxyMu.Unlock()
	return kind
}

// proxyCacheMax bounds ProxyType's per-address answers.
const proxyCacheMax = 65536

// lookupProxy reads ip from the BIN. Record runs on the log-worker
// goroutine, and a corrupt row panics inside the reader (a short row
// sliced at a column offset); that panic is a miss, logged once, so one
// bad address cannot kill the worker.
func (s *Scorer) lookupProxy(ip string) (kind string) {
	defer func() {
		if r := recover(); r != nil {
			s.noteProxyFailure(fmt.Sprintf("panicked: %v", r))
			kind = ""
		}
	}()
	rec, err := s.proxy.GetAll(ip)
	if err != nil {
		s.noteProxyFailure(err.Error())
		return ""
	}
	return proxyKind(rec, s.proxyPX1)
}

func (s *Scorer) noteProxyFailure(detail string) {
	s.proxyFail.Do(func() {
		log.Printf("threatscore: ip2proxy lookup failed (%s); treating the address as not a proxy", detail)
	})
}

func (s *Scorer) setProxy(db *ip2proxy.DB) {
	s.proxy = db
	s.proxySeen = map[string]string{}
	s.proxyPX1 = db != nil && db.PackageVersion() == "1"
}
