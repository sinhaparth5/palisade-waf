package storage

import "testing"

// TestServiceRateRules: round trip, empty removes the row, and removing the
// service removes it too (issue #280).
func TestServiceRateRules(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.AddService("api", "api.example.com", "", "http://127.0.0.1:3000", 0, 0))
	svcs, err := db.ListServices()
	mustNoErr(t, err)
	id := svcs[0].ID

	mustNoErr(t, db.SetServiceRateRules(id, "POST /reset 5/h 3"))
	mustNoErr(t, db.SetServiceRateRules(id, "* /search 2/s 10")) // upsert
	if got, _ := db.ListServiceRateRules(); got[id] != "* /search 2/s 10" {
		t.Fatalf("got %q", got[id])
	}
	mustNoErr(t, db.SetServiceRateRules(id, ""))
	if got, _ := db.ListServiceRateRules(); len(got) != 0 {
		t.Fatalf("empty kept %v", got)
	}
	mustNoErr(t, db.SetServiceRateRules(id, "POST /reset 5/h 3"))
	mustNoErr(t, db.RemoveService(id))
	if got, _ := db.ListServiceRateRules(); len(got) != 0 {
		t.Fatalf("RemoveService kept %v", got)
	}
}
