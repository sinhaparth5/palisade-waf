package waitroom

import (
	"strconv"
	"testing"
	"time"
)

const idle = 10 * time.Minute

func TestAdmitsAtMostMaxThenFIFO(t *testing.T) {
	r := New()
	now := time.Unix(1_700_000_000, 0)
	var admitted []string
	for i := range 3 {
		res := r.Visit("", "k"+strconv.Itoa(i), 3, idle, now)
		if !res.Admitted {
			t.Fatalf("visitor %d queued with free slots", i)
		}
		admitted = append(admitted, res.Ticket)
	}
	var queued []string
	for i := range 3 {
		res := r.Visit("", "q"+strconv.Itoa(i), 3, idle, now)
		if res.Admitted || res.Position != i+1 {
			t.Fatalf("over capacity: visitor %d = %+v, want queued at %d", i, res, i+1)
		}
		queued = append(queued, res.Ticket)
	}
	if a, q := r.Stats(); a != 3 || q != 3 {
		t.Fatalf("stats = %d active, %d queued", a, q)
	}
	// An admitted visitor keeps their slot on return.
	if res := r.Visit(admitted[0], "k0", 3, idle, now); !res.Admitted {
		t.Error("admitted visitor lost their slot")
	}

	// Two slots free (idle): the first two in line get them, in order.
	r.active[admitted[1]] = now.Add(-time.Second)
	r.active[admitted[2]] = now.Add(-time.Second)
	later := now.Add(2 * time.Second)
	if res := r.Visit(queued[2], "q2", 3, idle, later); res.Admitted || res.Position != 1 {
		t.Errorf("third in line = %+v, want still queued, now first", res)
	}
	for i := range 2 {
		if res := r.Visit(queued[i], "q"+strconv.Itoa(i), 3, idle, later); !res.Admitted {
			t.Errorf("visitor %d in line not admitted after slots freed: %+v", i, res)
		}
	}
	if a, _ := r.Stats(); a > 3 {
		t.Errorf("%d admitted, max 3", a)
	}
}

// TestTicketBoundToKey: a queued ticket presented from another client key
// is a stranger, not a skip to the front of the line.
func TestTicketBoundToKey(t *testing.T) {
	r := New()
	now := time.Unix(1_700_000_000, 0)
	r.Visit("", "a", 1, idle, now)
	q := r.Visit("", "b", 1, idle, now)
	if res := r.Visit(q.Ticket, "c", 1, idle, now); res.Ticket == q.Ticket || res.Position != 2 {
		t.Errorf("shared ticket = %+v, want a new ticket behind it", res)
	}
}

func TestAbandonedQueueEntriesAndSlotsExpire(t *testing.T) {
	r := New()
	now := time.Unix(1_700_000_000, 0)
	first := r.Visit("", "a", 1, idle, now)
	gone := r.Visit("", "b", 1, idle, now) // closes the tab
	waiting := r.Visit("", "c", 1, idle, now)

	// b stops polling; c keeps polling. When a's slot idles out, c is next.
	for s := 10 * time.Second; s <= idle+QueueTTL; s += 10 * time.Second {
		r.Visit(waiting.Ticket, "c", 1, idle, now.Add(s))
	}
	res := r.Visit(waiting.Ticket, "c", 1, idle, now.Add(idle+QueueTTL+10*time.Second))
	if !res.Admitted {
		t.Fatalf("c not admitted after a idled out and b left: %+v", res)
	}
	if res := r.Visit(gone.Ticket, "b", 1, idle, now.Add(idle+2*QueueTTL)); res.Admitted || res.Ticket == gone.Ticket {
		t.Errorf("abandoned ticket came back admitted: %+v", res)
	}
	if res := r.Visit(first.Ticket, "a", 1, idle, now.Add(idle+2*QueueTTL)); res.Admitted {
		t.Error("idle slot still admitted")
	}
}

// TestFloodIsBounded: unique clients past MaxQueue get "full", and one
// client can't hold more than MaxPerKey places.
func TestFloodIsBounded(t *testing.T) {
	r := New()
	now := time.Unix(1_700_000_000, 0)
	r.Visit("", "first", 1, idle, now)
	full := 0
	for i := range MaxQueue + 1000 {
		if r.Visit("", "flood-"+strconv.Itoa(i), 1, idle, now).Full {
			full++
		}
	}
	if _, q := r.Stats(); q != MaxQueue || full != 1000 {
		t.Errorf("queued %d (max %d), refused %d (want 1000)", q, MaxQueue, full)
	}

	r = New()
	r.Visit("", "first", 1, idle, now)
	for range MaxPerKey + 5 {
		r.Visit("", "one-client", 1, idle, now)
	}
	if _, q := r.Stats(); q != MaxPerKey {
		t.Errorf("one key queued %d tickets, max %d", q, MaxPerKey)
	}
}

// TestPromotedSlotNeedsArrival: a slot handed to someone in line is held
// briefly, not for the full idle time, if they never come back.
func TestPromotedSlotNeedsArrival(t *testing.T) {
	r := New()
	now := time.Unix(1_700_000_000, 0)
	a := r.Visit("", "a", 1, idle, now)
	r.Visit("", "b", 1, idle, now)
	c := r.Visit("", "c", 1, idle, now)
	r.active[a.Ticket] = now // a idles out
	// c's poll promotes b, who never returns; c gets in after arriveGrace.
	r.Visit(c.Ticket, "c", 1, idle, now.Add(2*time.Second))
	for s := 10 * time.Second; s < arriveGrace; s += 10 * time.Second {
		if r.Visit(c.Ticket, "c", 1, idle, now.Add(s)).Admitted {
			t.Fatal("c admitted while b's promoted slot was still held")
		}
	}
	if res := r.Visit(c.Ticket, "c", 1, idle, now.Add(arriveGrace+5*time.Second)); !res.Admitted {
		t.Errorf("c not admitted after b's grace ran out: %+v", res)
	}
}
