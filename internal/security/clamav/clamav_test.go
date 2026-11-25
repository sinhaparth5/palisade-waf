package clamav

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"strings"
	"testing"
)

// eicar is the standard antivirus test file.
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// FakeClamd answers zINSTREAM like clamd: FOUND for EICAR, a size error
// past limit bytes, OK otherwise. It returns the tcp:// address.
func fakeClamd(t *testing.T, limit int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				cmd := make([]byte, len("zINSTREAM\x00"))
				if _, err := io.ReadFull(c, cmd); err != nil || string(cmd) != "zINSTREAM\x00" {
					return
				}
				var got []byte
				for {
					var n uint32
					if binary.Read(c, binary.BigEndian, &n) != nil {
						return
					}
					if n == 0 {
						break
					}
					chunk := make([]byte, n)
					if _, err := io.ReadFull(c, chunk); err != nil {
						return
					}
					if got = append(got, chunk...); len(got) > limit {
						_, _ = c.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
						return
					}
				}
				reply := "stream: OK\x00"
				if bytes.Contains(got, []byte(eicar)) {
					reply = "stream: Eicar-Test-Signature FOUND\x00"
				}
				_, _ = c.Write([]byte(reply))
			}()
		}
	}()
	return "tcp://" + ln.Addr().String()
}

func multipartBody(t *testing.T, files map[string]string) (string, []byte) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("title", eicar) // a plain field is never scanned
	for name, content := range files {
		f, err := w.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	return w.FormDataContentType(), b.Bytes()
}

func TestScanMultipart(t *testing.T) {
	s, err := New(fakeClamd(t, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("a", 2<<20)
	for _, tc := range []struct {
		name    string
		files   map[string]string
		sig     string
		wantErr bool
	}{
		{"clean", map[string]string{"a.txt": "hello"}, "", false},
		{"no files", nil, "", false},
		{"eicar", map[string]string{"eicar.com": eicar}, "Eicar-Test-Signature", false},
		{"eicar across chunks", map[string]string{"x.bin": strings.Repeat("b", chunkSize-10) + eicar}, "Eicar-Test-Signature", false},
		{"over clamd's limit", map[string]string{"big.bin": big}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct, body := multipartBody(t, tc.files)
			sig, err := s.ScanMultipart(context.Background(), ct, body)
			if sig != tc.sig || (err != nil) != tc.wantErr {
				t.Fatalf("ScanMultipart = %q, %v; want %q, err=%v", sig, err, tc.sig, tc.wantErr)
			}
		})
	}
	if _, err := s.ScanMultipart(context.Background(), "multipart/form-data", nil); err == nil {
		t.Error("missing boundary passed")
	}
}

func TestScanClamdDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	s, _ := New("tcp://" + addr)
	ct, body := multipartBody(t, map[string]string{"eicar.com": eicar})
	if sig, err := s.ScanMultipart(context.Background(), ct, body); sig != "" || err == nil {
		t.Fatalf("clamd down = %q, %v; want an error", sig, err)
	}
}

func TestBusy(t *testing.T) {
	s, _ := New(fakeClamd(t, 1<<20))
	for range cap(s.slots) {
		s.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, strings.NewReader("x"), 1); !errors.Is(err, ErrBusy) {
		t.Fatalf("Scan with no free slot = %v, want ErrBusy", err)
	}
}

func TestNew(t *testing.T) {
	for raw, ok := range map[string]bool{
		"":                             true,
		"tcp://127.0.0.1:3310":         true,
		"unix:///run/clamav/clamd.ctl": true,
		"127.0.0.1:3310":               false,
		"tcp://":                       false,
		"http://clamd:3310":            false,
	} {
		if _, err := New(raw); (err == nil) != ok {
			t.Errorf("New(%q) = %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestParseReply(t *testing.T) {
	for reply, want := range map[string]string{
		"stream: OK\x00":                         "",
		"stream: Win.Test.EICAR_HDB-1 FOUND\x00": "Win.Test.EICAR_HDB-1",
		"stream: bad\x1bname FOUND":              "badname",
	} {
		if sig, err := ParseReply([]byte(reply)); sig != want || err != nil {
			t.Errorf("ParseReply(%q) = %q, %v; want %q", reply, sig, err, want)
		}
	}
	for _, reply := range []string{"", "INSTREAM size limit exceeded. ERROR\x00", "stream:  FOUND", "stream: OKAY"} {
		if sig, err := ParseReply([]byte(reply)); err == nil {
			t.Errorf("ParseReply(%q) = %q, want an error", reply, sig)
		}
	}
}

// FuzzParseReply: any clamd reply parses to a printable, short signature or
// an error, never both and never a panic.
func FuzzParseReply(f *testing.F) {
	for _, s := range []string{"stream: OK\x00", "stream: Eicar-Test-Signature FOUND\x00", "INSTREAM size limit exceeded. ERROR\x00", "stream: \xff FOUND"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, reply []byte) {
		sig, err := ParseReply(reply)
		if sig != "" && err != nil {
			t.Fatalf("both a signature and an error: %q %v", sig, err)
		}
		if len(sig) > 128 || strings.ContainsFunc(sig, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			t.Fatalf("unsafe signature %q", sig)
		}
	})
}
