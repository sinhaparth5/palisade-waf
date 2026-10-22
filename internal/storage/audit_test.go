package storage

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestAuditLog(t *testing.T) {
	db := openTestDB(t)
	for _, a := range []string{"POST /ip-rules", "DELETE /ip-rules/:id"} {
		if err := db.InsertAudit(AuditEntry{Actor: "admin", IP: "192.0.2.1", Action: a, Target: "id=1"}); err != nil {
			t.Fatal(err)
		}
	}
	got, total, err := db.ListAudit(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(got) != 2 || got[0].Action != "DELETE /ip-rules/:id" || got[0].IP != "192.0.2.1" || time.Since(got[0].TS) > time.Minute {
		t.Fatalf("ListAudit = %+v", got)
	}

	if _, err := db.exec(`UPDATE audit_log SET ts = ? WHERE action = ?`, time.Now().UTC().AddDate(0, 0, -400), "POST /ip-rules"); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneAudit(AuditRetentionDays); err != nil || n != 1 {
		t.Fatalf("PruneAudit = %d, %v; want 1", n, err)
	}
	if got, _, _ := db.ListAudit(10, 0); len(got) != 1 {
		t.Fatalf("after prune: %+v", got)
	}
}

func TestListAuditPages(t *testing.T) {
	db := openTestDB(t)
	for i := range 5 {
		if err := db.InsertAudit(AuditEntry{Actor: "admin", Action: "POST /x", Target: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		limit, offset int
		want          []string
	}{
		{2, 0, []string{"4", "3"}},
		{2, 2, []string{"2", "1"}},
		{2, 4, []string{"0"}},
		{2, 6, nil},
	} {
		got, total, err := db.ListAudit(tc.limit, tc.offset)
		if err != nil {
			t.Fatal(err)
		}
		var targets []string
		for _, e := range got {
			targets = append(targets, e.Target)
		}
		if total != 5 || !slices.Equal(targets, tc.want) {
			t.Errorf("ListAudit(%d, %d) = %v, total %d; want %v, total 5", tc.limit, tc.offset, targets, total, tc.want)
		}
	}
}
