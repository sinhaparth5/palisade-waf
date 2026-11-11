// Package egress guards every outbound connection Palisade makes (issue
// #270): cloud metadata endpoints are refused on the IP actually dialed, so
// a DNS answer that changes after a URL was saved, or a redirect, can't reach
// them. Private and loopback addresses stay allowed; real backends, SIEM
// webhooks and intel mirrors live there.
package egress

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlocked is returned by the dial for a metadata address.
var ErrBlocked = errors.New("connection to a cloud metadata address refused")

var (
	awsIMDSv6 = netip.MustParseAddr("fd00:ec2::254")
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
)

// Blocked reports whether ip is a metadata address: all of link-local
// (169.254.0.0/16 covers every cloud's IMDS and the ECS task endpoint,
// fe80::/10) plus the AWS IPv6 IMDS address.
func Blocked(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if nat64.Contains(ip) { // NAT64 form of an IPv4 address
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte(b[12:]))
	}
	return ip.IsLinkLocalUnicast() || ip == awsIMDSv6
}

// Control is a net.Dialer Control hook. It sees the resolved address of each
// connection attempt, after DNS and for every redirect hop.
func Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err // not an IP:port, so nothing we can vouch for
	}
	if Blocked(ap.Addr()) {
		return ErrBlocked
	}
	return nil
}

// Dialer returns a dialer that refuses metadata addresses.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: Control}
}

// Transport is http.DefaultTransport with the guarded dialer, shared by
// every outbound client that isn't the backend proxy.
// ponytail: with HTTP(S)_PROXY set the dialed IP is the proxy's, so the
// target is unchecked; refuse CONNECT targets by name if that setup matters.
var Transport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = Dialer(10 * time.Second).DialContext
	return t
}()

// Client returns an http.Client on Transport.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: Transport}
}
