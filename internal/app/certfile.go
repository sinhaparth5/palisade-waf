package app

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// certRecheck is how often certFile looks at the files again.
var certRecheck = time.Minute

// certFile serves the --tls-cert/--tls-key pair and rereads it once either
// file changes (issue #332): cert-manager renews a Kubernetes Secret in
// place and the kubelet swaps the mounted files under the running pod. A
// pair that fails to load (a key copied before its cert) keeps the old one
// and is tried again at the next check.
type certFile struct {
	cert, key string

	mu      sync.Mutex
	current *tls.Certificate
	mod     time.Time
	checked time.Time
}

func loadCertFile(cert, key string) (*certFile, error) {
	f := &certFile{cert: cert, key: key, checked: time.Now()}
	return f, f.load()
}

func (f *certFile) get() *tls.Certificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.checked) >= certRecheck {
		f.checked = time.Now()
		if mod, err := f.modTime(); err == nil && !mod.Equal(f.mod) {
			if err := f.load(); err != nil {
				log.Printf("tls: reload %s: %v (still serving the previous cert)", f.cert, err)
			} else {
				log.Printf("tls: reloaded %s", f.cert)
			}
		}
	}
	return f.current
}

func (f *certFile) load() error {
	mod, err := f.modTime()
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		return err
	}
	f.current, f.mod = &c, mod
	return nil
}

// modTime is the newer of the two files' times. Stat follows the kubelet's
// ..data symlink, so a swapped Secret shows up as a new time.
func (f *certFile) modTime() (time.Time, error) {
	var newest time.Time
	for _, p := range []string{f.cert, f.key} {
		st, err := os.Stat(p)
		if err != nil {
			return time.Time{}, err
		}
		if st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	return newest, nil
}
