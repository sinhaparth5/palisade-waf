package mailer

import (
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
)

// fakeSMTP answers one session on srv, replying fail[verb] instead of the
// normal reply for that verb. It returns what it saw.
type fakeSMTP struct {
	auth, from string
	rcpts      []string
	data       string
}

func runFake(conn net.Conn, fail map[string]string, got *fakeSMTP, done chan<- struct{}) {
	defer close(done)
	defer conn.Close()
	tp := textproto.NewConn(conn)
	reply := func(verb, ok string) bool {
		if f, bad := fail[verb]; bad {
			_ = tp.PrintfLine("%s", f)
			return false
		}
		_ = tp.PrintfLine("%s", ok)
		return true
	}
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			_ = tp.PrintfLine("250-fake\r\n250 AUTH PLAIN")
		case "AUTH":
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(arg, "PLAIN "))
			got.auth = string(raw)
			reply("AUTH", "235 ok")
		case "MAIL":
			got.from = arg
			reply("MAIL", "250 ok")
		case "RCPT":
			got.rcpts = append(got.rcpts, arg)
			reply("RCPT", "250 ok")
		case "DATA":
			if !reply("DATA", "354 go") {
				continue
			}
			b, _ := tp.ReadDotBytes()
			got.data = string(b)
			reply("END", "250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 unknown")
		}
	}
}

func TestSession(t *testing.T) {
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS()
	defer cert.Close()

	cases := []struct {
		name    string
		fail    map[string]string
		wantErr string
	}{
		{"delivered", nil, ""},
		{"bad token", map[string]string{"AUTH": "535 bad credentials"}, "smtp auth"},
		{"sender refused", map[string]string{"MAIL": "550 no"}, "MAIL FROM"},
		{"recipient refused", map[string]string{"RCPT": "550 no such user"}, "RCPT TO a@example.com"},
		{"data refused", map[string]string{"DATA": "554 no"}, "smtp DATA"},
		{"message rejected", map[string]string{"END": "554 spam"}, "end of data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var got fakeSMTP
			done := make(chan struct{})
			go func() {
				server, err := ln.Accept()
				if err != nil {
					close(done)
					return
				}
				runFake(tls.Server(server, cert.TLS), tc.fail, &got, done)
			}()
			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}

			msg := buildMessage(fromHeader(), []string{"a@example.com", "b@example.com"}, "Daily", "text", "<p>html</p>")
			err = session(tls.Client(client, &tls.Config{InsecureSkipVerify: true}), "tok-123", //nolint:gosec // test peer
				[]string{"a@example.com", "b@example.com"}, msg)
			client.Close()
			<-done
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.auth != "\x00api_token\x00tok-123" || got.from != "FROM:<"+Sender+">" || len(got.rcpts) != 2 {
				t.Errorf("session = %+v", got)
			}
			if !strings.Contains(got.data, "Subject: Daily") || !strings.Contains(got.data, "<p>html</p>") {
				t.Errorf("message = %q", got.data)
			}
		})
	}
}

// A server that closes before its greeting fails cleanly.
func TestSessionNoGreeting(t *testing.T) {
	client, server := net.Pipe()
	server.Close()
	if err := session(client, "t", []string{"a@example.com"}, nil); err == nil || !strings.Contains(err.Error(), "greeting") {
		t.Fatalf("err = %v", err)
	}
}
