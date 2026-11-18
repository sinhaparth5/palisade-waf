package storage

import (
	"testing"
	"time"
)

// TestPruneFloor: rows at or after the floor survive the prune; lifting
// the floor lets them go.
func TestPruneFloor(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	for _, age := range []int{10, 5} {
		if _, err := db.InsertRequest(RequestLog{Timestamp: now.AddDate(0, 0, -age), Method: "GET", Path: "/", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	mustNoErr(t, db.SetPruneFloor(now.AddDate(0, 0, -7)))
	if f, _ := db.PruneFloor(); !f.Equal(now.AddDate(0, 0, -7).Truncate(time.Second)) {
		t.Fatalf("floor %v", f)
	}
	if n, err := db.PruneOldRequests(1); err != nil || n != 1 {
		t.Fatalf("pruned %d, %v; want the 10-day-old row only", n, err)
	}
	mustNoErr(t, db.SetPruneFloor(time.Time{}))
	if n, _ := db.PruneOldRequests(1); n != 1 {
		t.Fatalf("pruned %d after lifting the floor", n)
	}
}
