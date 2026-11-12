package proxy

import "testing"

// FuzzWaitTicket (issue #306): a waiting room cookie yields a ticket only
// for the service and client key it was signed for, and only verbatim.
func FuzzWaitTicket(f *testing.F) {
	h := &Handler{} // no DB: random signing key
	const svc, key, ticket = "shop", "203.0.113.9", "t-123"
	valid := ticket + "." + h.ticketSig(svc, ticket, key)
	f.Add(valid, svc, key)
	f.Add(valid, "shop2", key)
	f.Add(valid, svc, "203.0.113.10")
	f.Add("t-123|203.0.113.9."+h.ticketSig(svc, ticket, key), "shop", "")
	f.Add("."+h.ticketSig(svc, "", key), svc, key)
	f.Add("x", svc, key)
	if h.ticketFromCookie(valid, svc, key) != ticket {
		f.Fatal("issued ticket refused")
	}

	f.Fuzz(func(t *testing.T, value, service, clientKey string) {
		got := h.ticketFromCookie(value, service, clientKey)
		if got != "" && (value != valid || service != svc || clientKey != key || got != ticket) {
			t.Fatalf("ticket %q from %q for service %q key %q", got, value, service, clientKey)
		}
	})
}
