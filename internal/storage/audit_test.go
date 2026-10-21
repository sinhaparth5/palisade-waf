package storage

import (
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
	got, err := db.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Action != "DELETE /ip-rules/:id" || got[0].IP != "192.0.2.1" || time.Since(got[0].TS) > time.Minute {
		t.Fatalf("ListAudit = %+v", got)
	}

	if _, err := db.exec(`UPDATE audit_log SET ts = ? WHERE action = ?`, time.Now().UTC().AddDate(0, 0, -400), "POST /ip-rules"); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneAudit(AuditRetentionDays); err != nil || n != 1 {
		t.Fatalf("PruneAudit = %d, %v; want 1", n, err)
	}
	if got, _ := db.ListAudit(10); len(got) != 1 {
		t.Fatalf("after prune: %+v", got)
	}
}
