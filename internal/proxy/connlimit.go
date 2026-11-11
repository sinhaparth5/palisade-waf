package proxy

import (
	"net"
	"sync"

	"palisade/internal/notify/metrics"
	"palisade/internal/security/ratelimit"
)

// ConnLimiter caps concurrent TCP connections per ratelimit.ClientKey (issue
// #272). The rate limiter counts requests; this counts open connections, so
// one client can't hold thousands of idle or trickling ones. Peers that
// carry many clients are exempt: trusted proxies, Cloudflare, loopback (a
// local proxy), and operator-trusted IPs.
// ponytail: TCP only. QUIC has no accept hook that pairs with a close; cap
// HTTP/3 connections per client if that listener is ever abused.
type ConnLimiter struct {
	max       int
	proxies   []*net.IPNet
	trustedIP func(string) bool

	mu sync.Mutex
	n  map[string]int
}

// NewConnLimiter returns nil when max <= 0; a nil limiter limits nothing.
func NewConnLimiter(max int, trustedProxies []*net.IPNet, trustedIP func(string) bool) *ConnLimiter {
	if max <= 0 {
		return nil
	}
	return &ConnLimiter{max: max, proxies: trustedProxies, trustedIP: trustedIP, n: map[string]int{}}
}

// Listener wraps ln so Accept closes connections over the cap.
func (l *ConnLimiter) Listener(ln net.Listener) net.Listener {
	if l == nil {
		return ln
	}
	return &limitListener{Listener: ln, l: l}
}

func (l *ConnLimiter) exempt(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() {
		return true
	}
	for _, n := range l.proxies {
		if n.Contains(ip) {
			return true
		}
	}
	s := ip.String()
	return isCloudflareIP(s) || (l.trustedIP != nil && l.trustedIP(s))
}

type limitListener struct {
	net.Listener
	l *ConnLimiter
}

func (ll *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := ll.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr, _ := c.RemoteAddr().(*net.TCPAddr)
		if addr == nil || ll.l.exempt(addr.IP) {
			return c, nil
		}
		key := ratelimit.ClientKey(addr.IP.String())
		l := ll.l
		l.mu.Lock()
		over := l.n[key] >= l.max
		if !over {
			l.n[key]++
		}
		l.mu.Unlock()
		if over {
			_ = c.Close()
			metrics.ConnsRefused.Inc()
			continue
		}
		release := sync.OnceFunc(func() {
			l.mu.Lock()
			if l.n[key]--; l.n[key] <= 0 {
				delete(l.n, key)
			}
			l.mu.Unlock()
		})
		// Keep the concrete *net.TCPConn embedded so net/http still finds
		// its ReadFrom (sendfile/splice) on plain-HTTP responses.
		if tc, ok := c.(*net.TCPConn); ok {
			return &limitedTCPConn{TCPConn: tc, release: release}, nil
		}
		return &limitedConn{Conn: c, release: release}, nil
	}
}

type limitedTCPConn struct {
	*net.TCPConn
	release func()
}

func (c *limitedTCPConn) Close() error { c.release(); return c.TCPConn.Close() }

type limitedConn struct {
	net.Conn
	release func()
}

func (c *limitedConn) Close() error { c.release(); return c.Conn.Close() }
