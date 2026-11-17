package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCertFileReload: a renewed pair is served after the next check, and a
// half-written one leaves the previous cert in place.
func TestCertFileReload(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	gen := func(host string, at time.Time) {
		t.Helper()
		if err := runGencert([]string{"--cert", crt, "--key", key, "--hosts", host}); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{crt, key} {
			if err := os.Chtimes(p, at, at); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := time.Now()
	gen("a.example.com", now.Add(-time.Hour))
	f, err := loadCertFile(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	first := f.get().Certificate[0]

	old := certRecheck
	t.Cleanup(func() { certRecheck = old })
	certRecheck = time.Hour
	gen("b.example.com", now.Add(-time.Minute))
	if !bytes.Equal(f.get().Certificate[0], first) {
		t.Fatal("reloaded before the recheck interval")
	}

	certRecheck = 0
	second := f.get().Certificate[0]
	if bytes.Equal(second, first) {
		t.Fatal("renewed cert not picked up")
	}

	if err := os.WriteFile(key, []byte("half-written"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(key, now, now); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.get().Certificate[0], second) {
		t.Fatal("a broken pair replaced the working cert")
	}
}
