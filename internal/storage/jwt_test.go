package storage

import "testing"

// TestServiceJWT: round trip, "off" removes the row, and removing the
// service removes it too (issue #279).
func TestServiceJWT(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.AddService("api", "api.example.com", "", "http://127.0.0.1:3000", 0, 0))
	svcs, err := db.ListServices()
	mustNoErr(t, err)
	id := svcs[0].ID

	want := ServiceJWT{Mode: "enforce", JWKSURL: "https://idp.example/.well-known/jwks.json", Issuer: "https://idp.example",
		Audience: "api", Algorithms: "RS256\nES256", Prefixes: "/api\n/v2"}
	mustNoErr(t, db.SetServiceJWT(id, want))
	want.Mode = "log"
	mustNoErr(t, db.SetServiceJWT(id, want)) // upsert
	got, err := db.ListServiceJWT()
	mustNoErr(t, err)
	if got[id] != want {
		t.Fatalf("got %+v, want %+v", got[id], want)
	}

	mustNoErr(t, db.SetServiceJWT(id, ServiceJWT{Mode: "off"}))
	if got, _ := db.ListServiceJWT(); len(got) != 0 {
		t.Fatalf("off kept %+v", got)
	}
	mustNoErr(t, db.SetServiceJWT(id, want))
	mustNoErr(t, db.RemoveService(id))
	if got, _ := db.ListServiceJWT(); len(got) != 0 {
		t.Fatalf("RemoveService kept %+v", got)
	}
}
