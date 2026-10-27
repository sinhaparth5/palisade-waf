package services

import (
	"context"
	"errors"
	"net/http"
)

// ErrResponseBlocked is what a response hook returns to replace the
// backend's response with a 502 (issue #192). The proxies' error handlers
// answer it without logging it or marking the backend down.
var ErrResponseBlocked = errors.New("response blocked by inspection")

type responseHookKey struct{}

type responseHook struct {
	fn             func(*http.Response) error
	acceptEncoding string
}

// WithResponseHook returns r carrying fn, which the service's proxy calls
// on the backend's response before anything reaches the client. It also
// asks the backend for an uncompressed body, so fn can read it; Palisade's
// own compression still answers the client's original Accept-Encoding.
func WithResponseHook(r *http.Request, fn func(*http.Response) error) *http.Request {
	h := &responseHook{fn: fn, acceptEncoding: r.Header.Get("Accept-Encoding")}
	r.Header.Del("Accept-Encoding")
	return r.WithContext(context.WithValue(r.Context(), responseHookKey{}, h))
}

func runResponseHook(resp *http.Response) error {
	if resp.Request == nil {
		return nil
	}
	if h, ok := resp.Request.Context().Value(responseHookKey{}).(*responseHook); ok {
		return h.fn(resp)
	}
	return nil
}

// clientAcceptEncoding is the client's Accept-Encoding, including when
// WithResponseHook took it off the backend request.
func clientAcceptEncoding(r *http.Request) string {
	if h, ok := r.Context().Value(responseHookKey{}).(*responseHook); ok {
		return h.acceptEncoding
	}
	return r.Header.Get("Accept-Encoding")
}
