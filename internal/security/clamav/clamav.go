// Package clamav scans uploaded files with a clamd the operator runs (issue
// #340), over its zINSTREAM protocol. Scans fail open: any error means the
// caller lets the request through and counts the error.
package clamav

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"runtime"
	"strings"
	"time"
)

const (
	chunkSize = 32 << 10
	// timeout bounds one file's scan: 2s plus the time to move it at
	// minRate, so a large upload on a healthy clamd isn't cut off.
	timeout = 2 * time.Second
	minRate = 16 << 20 // bytes per second
)

// ErrBusy is returned when every scan slot stayed taken until the deadline.
var ErrBusy = errors.New("clamd: all scan slots busy")

// Scanner talks to one clamd. A nil *Scanner is valid and scans nothing.
type Scanner struct {
	network, addr string
	slots         chan struct{} // bounds concurrent scans
}

// New parses tcp://host:port or unix:///path; "" returns nil (scanning off).
func New(raw string) (*Scanner, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("clamd address: %w", err)
	}
	s := &Scanner{network: u.Scheme, slots: make(chan struct{}, max(4, runtime.GOMAXPROCS(0)))}
	switch {
	case u.Scheme == "tcp" && u.Host != "":
		s.addr = u.Host
	case u.Scheme == "unix" && u.Path != "":
		s.addr = u.Path
	default:
		return nil, fmt.Errorf("clamd address %q: want tcp://host:port or unix:///path", raw)
	}
	return s, nil
}

// ScanMultipart scans every file part of a multipart/form-data body held
// in memory and returns the first signature found ("" = clean).
// ponytail: a body the multipart reader can't parse is an error (fail
// open); a backend parsing it more leniently would get unscanned files.
func (s *Scanner) ScanMultipart(ctx context.Context, contentType string, body []byte) (string, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return "", fmt.Errorf("multipart content type: %q", contentType)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("multipart: %w", err)
		}
		if p.FileName() == "" {
			continue
		}
		// The part can't be larger than the body it came from.
		sig, err := s.Scan(ctx, p, len(body))
		if sig != "" || err != nil {
			return sig, err
		}
	}
}

// Scan streams r (at most size bytes, for the deadline) to clamd and
// returns the signature it found, or "" when clean.
func (s *Scanner) Scan(ctx context.Context, r io.Reader, size int) (string, error) {
	deadline := time.Now().Add(timeout + time.Duration(size/minRate)*time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return "", ErrBusy
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, s.network, s.addr)
	if err != nil {
		return "", fmt.Errorf("clamd: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", fmt.Errorf("clamd: %w", err)
	}
	buf := make([]byte, 4+chunkSize)
	for {
		n, rerr := io.ReadFull(r, buf[4:])
		if n > 0 {
			binary.BigEndian.PutUint32(buf, uint32(n)) //nolint:gosec // G115: n <= chunkSize
			if _, err := conn.Write(buf[:4+n]); err != nil {
				// clamd closes the stream once it passes StreamMaxLength;
				// its reply says so.
				break
			}
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			_, _ = conn.Write([]byte{0, 0, 0, 0})
			break
		}
		if rerr != nil {
			return "", fmt.Errorf("read upload: %w", rerr)
		}
	}
	reply, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil && len(reply) == 0 {
		return "", fmt.Errorf("clamd: %w", err)
	}
	return ParseReply(reply)
}

// ParseReply reads one zINSTREAM reply: "stream: OK", "stream: <sig>
// FOUND", or an error such as "INSTREAM size limit exceeded. ERROR".
func ParseReply(reply []byte) (string, error) {
	line, _, _ := bytes.Cut(reply, []byte{0})
	s := strings.TrimSpace(string(line))
	s = strings.TrimPrefix(s, "stream: ")
	switch {
	case s == "OK":
		return "", nil
	case strings.HasSuffix(s, " FOUND"):
		sig := strings.TrimSpace(strings.TrimSuffix(s, " FOUND"))
		if sig == "" {
			break
		}
		return clean(sig), nil
	}
	return "", fmt.Errorf("clamd replied %q", clean(s))
}

// clean keeps a clamd-supplied name printable and short, since it lands in
// the request log.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return strings.ToValidUTF8(s, "")
}
