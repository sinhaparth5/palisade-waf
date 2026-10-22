package services

import (
	"testing"

	"palisade/internal/storage"
)

func TestIsLoginPath(t *testing.T) {
	svc := &storage.Service{LoginPaths: []string{"/login", "/wp-login.php"}}
	cases := []struct {
		path string
		want bool
	}{
		{"/login", true},
		{"/Login/", true},
		{"//login", true},
		{"/login;jsessionid=abc", true},
		{"/login;a=1/submit", true},
		{"/login/submit", true},
		{"/api/login", true},
		{"/blog/../login", true},
		{"/WP-LOGIN.PHP", true},
		{"/wp-login.php;x", true},
		{"/login2", false},
		{"/mylogin", false},
		{"/logout", false},
		{"/", false},
		{"/loginx/submit", false},
	}
	for _, tc := range cases {
		if got := IsLoginPath(svc, tc.path); got != tc.want {
			t.Errorf("IsLoginPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	if IsLoginPath(nil, "/login") || IsLoginPath(&storage.Service{}, "/login") {
		t.Error("no login paths should match nothing")
	}
	if root := (&storage.Service{LoginPaths: []string{"/"}}); !IsLoginPath(root, "/") || IsLoginPath(root, "/x") {
		t.Error(`login path "/" should match only "/"`)
	}
}
