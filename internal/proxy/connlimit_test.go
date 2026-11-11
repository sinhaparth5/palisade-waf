package proxy

import (
	"net"
	"testing"
	"time"
)

// TestConnLimiter pins issue #272 with a non-loopback source: 127.0.0.2 is
// loopback and exempt, so the limiter's exemption is narrowed for the test.
func TestConnLimiter(t *testing.T) {
	if l := NewConnLimiter(0, nil, nil); l != nil {
		t.Fatal("max 0 must disable the limiter")
	}
	var nilLimiter *ConnLimiter
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	if nilLimiter.Listener(base) != base {
		t.Fatal("nil limiter must return the listener unchanged")
	}

	l := NewConnLimiter(2, ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"}), func(ip string) bool { return ip == "198.51.100.1" })
	for ip, want := range map[string]bool{
		"127.0.0.1":    true,  // loopback
		"10.1.2.3":     true,  // trusted proxy
		"198.51.100.1": true,  // operator-trusted IP
		"173.245.48.1": true,  // Cloudflare edge
		"203.0.113.9":  false, // an ordinary client
		"2001:db8::1":  false,
	} {
		if got := l.exempt(net.ParseIP(ip)); got != want {
			t.Errorf("exempt(%s) = %v, want %v", ip, got, want)
		}
	}

	// Count real connections; fakeAddr makes the loopback dialer look remote.
	ln := l.Listener(&fakeAddrListener{Listener: base, ip: net.ParseIP("203.0.113.9")})
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	next := func() net.Conn {
		select {
		case c := <-accepted:
			return c
		case <-time.After(300 * time.Millisecond):
			return nil
		}
	}

	dial()
	dial()
	first, second := next(), next()
	if first == nil || second == nil {
		t.Fatal("connections under the cap were not accepted")
	}
	third := dial()
	if next() != nil {
		t.Fatal("third connection accepted over a cap of 2")
	}
	// The refused connection was closed by the server.
	_ = third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Error("refused connection still open")
	}

	// Closing one (twice: release must be idempotent) frees exactly one slot.
	first.Close()
	first.Close()
	dial()
	if next() == nil {
		t.Fatal("slot not freed after close")
	}
	dial()
	if next() != nil {
		t.Fatal("double close freed two slots")
	}
	second.Close()
}

// fakeAddrListener reports every accepted connection as coming from ip.
type fakeAddrListener struct {
	net.Listener
	ip net.IP
}

func (f *fakeAddrListener) Accept() (net.Conn, error) {
	c, err := f.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fakeAddrConn{Conn: c, ip: f.ip}, nil
}

type fakeAddrConn struct {
	net.Conn
	ip net.IP
}

func (c *fakeAddrConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: c.ip, Port: 1234} }
