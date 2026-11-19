package storage

import "testing"

// SetDockerService (issue #341) clears a redirect target the labels no
// longer list, and fails loudly on a closed DB.
func TestSetDockerServiceCanonical(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.SetDockerService("app", []string{"a.test", "www.a.test"}, "", []string{"http://172.20.0.2:80"}); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListServices()
	if err := db.SetServiceHosts(list[0].ID, []string{"www.a.test"}, "www.a.test"); err != nil {
		t.Fatal(err)
	}
	if changed, err := db.SetDockerService("app", []string{"a.test"}, "", []string{"http://172.20.0.2:80"}); !changed || err != nil {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if s, _ := db.GetService(list[0].ID); s.CanonicalHost != "" || s.HostAliases != nil {
		t.Errorf("service = %+v", s)
	}
	db.Close()
	if _, err := db.SetDockerService("app", nil, "/", nil); err == nil {
		t.Error("closed DB passed")
	}
}
