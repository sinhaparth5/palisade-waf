// Package waitroom is the per-service waiting room (issue #198): at most
// max visitors admitted at once, the rest queued first-in, first-out.
//
// State is in-process, like the rate limiter: one Palisade is one node, so
// several instances would each keep their own queue. Visitors are tickets
// (random IDs the proxy hands out in a signed cookie); every map here is
// bounded and expires idle entries, since each queued visitor is state an
// unauthenticated client created.
package waitroom

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	// MaxQueue caps the queue; past it new visitors get "full" instead of
	// a ticket, so a flood of unique clients can't grow memory without bound.
	MaxQueue = 50000
	// MaxPerKey caps the tickets one client key (IPv6 /64) holds in the
	// queue: cookie-less clients get a new ticket per request.
	MaxPerKey = 8
	// QueueTTL drops a queued visitor who stopped polling (closed the tab).
	// The queue page refreshes every PollSecs.
	QueueTTL = time.Minute
	PollSecs = 10
	// arriveGrace is how long a promoted visitor's slot is held for them to
	// come back from the queue page; after that it frees like an idle one.
	arriveGrace = time.Minute
	sweepEvery  = time.Second
)

// Result is the outcome of one visit.
type Result struct {
	Admitted bool
	Ticket   string // the visitor's ticket; differs from the one passed in when a new one was issued
	Position int    // 1-based place in the queue (an upper bound) when not admitted
	Full     bool   // queue full: no ticket was issued
}

type entry struct {
	seq  uint64
	key  string
	seen time.Time
}

// Room is one service's waiting room.
type Room struct {
	mu        sync.Mutex
	active    map[string]time.Time // ticket -> slot expiry
	queued    map[string]*entry
	perKey    map[string]int // client key -> tickets queued
	queue     []string       // tickets in arrival order; queue[head:] still waiting
	head      int
	base      uint64 // seq of queue[0]
	nextSeq   uint64
	lastSweep time.Time
}

func New() *Room {
	return &Room{active: map[string]time.Time{}, queued: map[string]*entry{}, perKey: map[string]int{}}
}

// Visit admits or queues one request. ticket is the visitor's verified
// ticket, "" if they have none; key is their ratelimit.ClientKey.
func (r *Room) Visit(ticket, key string, max int, idle time.Duration, now time.Time) Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep(now)
	r.promote(max, now)

	if ticket != "" {
		if _, ok := r.active[ticket]; ok {
			r.active[ticket] = now.Add(idle)
			return Result{Admitted: true, Ticket: ticket}
		}
		if e, ok := r.queued[ticket]; ok && e.key == key {
			e.seen = now
			return Result{Ticket: ticket, Position: int(e.seq-r.base) - r.head + 1}
		}
		// Unknown: expired, or issued before a restart. Start over.
	}
	if len(r.active) < max && r.head == len(r.queue) {
		t := newTicket()
		r.active[t] = now.Add(idle)
		return Result{Admitted: true, Ticket: t}
	}
	if len(r.queued) >= MaxQueue || r.perKey[key] >= MaxPerKey {
		return Result{Full: true}
	}
	t := newTicket()
	e := &entry{seq: r.nextSeq, key: key, seen: now}
	r.nextSeq++
	r.queue = append(r.queue, t)
	r.queued[t] = e
	r.perKey[key]++
	return Result{Ticket: t, Position: int(e.seq-r.base) - r.head + 1}
}

// promote moves queue heads into free slots, oldest first.
func (r *Room) promote(max int, now time.Time) {
	for len(r.active) < max && r.head < len(r.queue) {
		t := r.queue[r.head]
		r.head++
		if r.drop(t) {
			r.active[t] = now.Add(arriveGrace)
		}
	}
	if r.head > 1024 && r.head > len(r.queue)/2 {
		r.base += uint64(r.head)
		r.queue = append([]string(nil), r.queue[r.head:]...)
		r.head = 0
	}
}

// drop removes a ticket from the queue maps, reporting whether it was there.
func (r *Room) drop(t string) bool {
	e, ok := r.queued[t]
	if !ok {
		return false
	}
	delete(r.queued, t)
	if r.perKey[e.key]--; r.perKey[e.key] <= 0 {
		delete(r.perKey, e.key)
	}
	return true
}

// sweep expires idle slots and abandoned queue entries, at most once per
// sweepEvery. A dropped entry's queue slot is skipped when it reaches the head.
func (r *Room) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < sweepEvery {
		return
	}
	r.lastSweep = now
	for t, exp := range r.active {
		if now.After(exp) {
			delete(r.active, t)
		}
	}
	for t, e := range r.queued {
		if now.Sub(e.seen) > QueueTTL {
			r.drop(t)
		}
	}
}

// Stats returns how many visitors are admitted and queued.
func (r *Room) Stats() (active, queued int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active), len(r.queued)
}

func newTicket() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint — never errors on modern platforms
	return hex.EncodeToString(b)
}
