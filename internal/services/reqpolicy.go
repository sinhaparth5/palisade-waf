package services

import (
	"mime"
	"net/http"
	"slices"
	"strings"

	"palisade/internal/storage"
)

// CheckRequestPolicy returns the status a request outside the service's
// policy gets (issue #282): 405 method, 413 body size, 415 Content-Type;
// 0 when it fits. Only a declared Content-Length is checked here; the
// caller caps a body of unknown length while it streams.
func CheckRequestPolicy(p storage.RequestPolicy, r *http.Request) int {
	if len(p.Methods) > 0 && !slices.Contains(p.Methods, r.Method) &&
		(r.Method != http.MethodHead || !slices.Contains(p.Methods, http.MethodGet)) {
		return http.StatusMethodNotAllowed
	}
	if r.ContentLength == 0 {
		return 0 // no body
	}
	if p.MaxBodyKiB > 0 && r.ContentLength > int64(p.MaxBodyKiB)<<10 {
		return http.StatusRequestEntityTooLarge
	}
	if len(p.ContentTypes) == 0 {
		return 0
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return http.StatusUnsupportedMediaType
	}
	for _, want := range p.ContentTypes {
		if mt == want || (strings.HasSuffix(want, "/*") && strings.HasPrefix(mt, want[:len(want)-1])) {
			return 0
		}
	}
	return http.StatusUnsupportedMediaType
}
