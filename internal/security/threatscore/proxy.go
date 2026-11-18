package threatscore

import (
	"errors"
	"fmt"
	"log"
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
// with a nil error for both addresses, including an IPv4-only file.
func probeProxyDB(db *ip2proxy.DB) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("lookup panicked: %v", r)
		}
	}()
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if _, err = db.GetAll(ip); err != nil {
			return fmt.Errorf("lookup %s: %w", ip, err)
		}
	}
	return nil
}

// proxyScores reports whether an IP2Proxy record counts as the hosting/VPN
// signal. The type string is what decides: IsProxy is 2 for DCH, which
// counts, and for SES and AIC, which do not. CPN and EPN are consumer
// privacy networks (iCloud Private Relay) and enterprise networks.
//
// PX1 has no proxy-type column — the reader's position table stores 0 for
// that package — so GetAll leaves ProxyType as its placeholder and sets
// IsProxy to 1 when the address is in the file. LITE PX1 is a list of
// public proxies, which is the PUB signal the free file can give. A miss
// stays IsProxy -1 with the same placeholder, and a "-" country is IsProxy 0.
func proxyScores(rec ip2proxy.IP2ProxyRecord, px1 bool) bool {
	switch rec.ProxyType {
	case "VPN", "TOR", "DCH", "PUB", "WEB", "RES":
		return true
	case "SES", "AIC", "CPN", "EPN", "-":
		return false
	default:
		return px1 && rec.IsProxy == 1
	}
}

// proxyHit looks ip up in the optional BIN. A nil DB is "no flag": the
// caller keeps the ASN heuristic alone. Record runs on the log-worker
// goroutine, and a corrupt row panics inside the reader (a short row
// sliced at a column offset); that panic is a miss, logged once, so one
// bad address cannot kill the worker.
func (s *Scorer) proxyHit(ip string) (hit bool) {
	if s.proxy == nil || ip == "" {
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			s.noteProxyFailure(fmt.Sprintf("panicked: %v", r))
			hit = false
		}
	}()
	rec, err := s.proxy.GetAll(ip)
	if err != nil {
		s.noteProxyFailure(err.Error())
		return false
	}
	return proxyScores(rec, s.proxyPX1)
}

func (s *Scorer) noteProxyFailure(detail string) {
	s.proxyFail.Do(func() {
		log.Printf("threatscore: ip2proxy lookup failed (%s); treating the address as not a proxy", detail)
	})
}

func (s *Scorer) setProxy(db *ip2proxy.DB) {
	s.proxy = db
	s.proxyPX1 = db != nil && db.PackageVersion() == "1"
}
