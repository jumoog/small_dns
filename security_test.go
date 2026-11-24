package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAPIRejectsCrossOriginWrites checks that a page on another origin cannot
// use a browser on the trusted network to change records: the CORS-simple
// request shapes a browser sends without a preflight are refused, while the
// UI's own same-origin request and a plain API client still work.
func TestAPIRejectsCrossOriginWrites(t *testing.T) {
	store := testStore(t, map[string]string{"*.example.io": "100.101.102.103"})
	web := &webServer{store: store}
	srv := httptest.NewServer(web.routes())
	defer srv.Close()

	post := func(contentType string, headers map[string]string, body string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/records", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	attack := `{"domain":"app.example.io","ip":"203.0.113.66"}`

	for _, tc := range []struct {
		name        string
		contentType string
		headers     map[string]string
		want        int
	}{
		{"cross-site no-cors fetch", "text/plain;charset=UTF-8", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://attacker.example"}, http.StatusForbidden},
		{"cross-origin, Origin only", "text/plain", map[string]string{"Origin": "https://attacker.example"}, http.StatusForbidden},
		{"cross-site form post", "application/x-www-form-urlencoded", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"text/plain without browser headers", "text/plain", nil, http.StatusUnsupportedMediaType},
	} {
		if got := post(tc.contentType, tc.headers, attack); got != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, got, tc.want)
		}
	}
	if addr, _ := store.lookup("app.example.io"); addr.String() != "100.101.102.103" {
		t.Fatalf("a refused request changed the record: app.example.io -> %v", addr)
	}

	if got := post("application/json", map[string]string{"Sec-Fetch-Site": "same-origin"}, attack); got != http.StatusOK {
		t.Errorf("same-origin UI request: status = %d, want 200", got)
	}
	if got := post("application/json", nil, `{"domain":"cli.example.io","ip":"10.0.0.7"}`); got != http.StatusOK {
		t.Errorf("API client without browser headers: status = %d, want 200", got)
	}
}

// TestResponsesAreNotAnswered checks that a message which is already a
// response is dropped rather than answered or forwarded, so two servers can
// never be made to answer each other in a loop.
func TestResponsesAreNotAnswered(t *testing.T) {
	store := testStore(t, map[string]string{"home.jumoog.io": "10.0.0.1"})
	s := &dnsServer{store: store, upstream: "127.0.0.1:1", ttl: 60, timeout: 200 * time.Millisecond}

	for _, name := range []string{"home.jumoog.io", "example.com"} {
		query := buildQuery(t, name, typeA)
		query[2] |= 0x80 // QR
		if resp := s.handle(query, false); resp != nil {
			t.Errorf("%s: a response (QR=1) was answered", name)
		}
	}

	// Our own answer fed back in must not be answered again.
	answer := s.handle(buildQuery(t, "home.jumoog.io", typeA), false)
	if resp := s.handle(answer, false); resp != nil {
		t.Error("our own reply was answered as if it were a query")
	}
}

// TestOtherOpcodesGetNotImp checks that only standard queries are answered;
// UPDATE, NOTIFY and the like get NOTIMP instead of an authoritative answer.
func TestOtherOpcodesGetNotImp(t *testing.T) {
	store := testStore(t, map[string]string{"home.jumoog.io": "10.0.0.1"})
	s := &dnsServer{store: store, upstream: "127.0.0.1:1", ttl: 60, timeout: 200 * time.Millisecond}

	query := buildQuery(t, "home.jumoog.io", typeA)
	query[2] |= 5 << 3 // opcode UPDATE
	resp := s.handle(query, false)
	if resp == nil {
		t.Fatal("no reply to an UPDATE")
	}
	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F; rcode != rcodeNotImp {
		t.Errorf("rcode = %d, want NOTIMP", rcode)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
		t.Errorf("ANCOUNT = %d, want 0", got)
	}
}

// flakyListener fails Accept with a temporary error a few times, then hands
// out one connection, then reports that it was closed.
type flakyListener struct {
	failures int
	conn     net.Conn
	accepted bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.failures > 0 {
		l.failures--
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", syscall.EMFILE)}
	}
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	return nil, net.ErrClosed
}

func (l *flakyListener) Close() error   { return nil }
func (l *flakyListener) Addr() net.Addr { return &net.TCPAddr{} }

// TestAcceptErrorIsNotFatal checks that running out of file descriptors does
// not end the TCP listener (and with it the process): it keeps accepting once
// the error clears, and stops only when the listener is closed.
func TestAcceptErrorIsNotFatal(t *testing.T) {
	s := &dnsServer{store: testStore(t, nil), upstream: "127.0.0.1:1", ttl: 60, timeout: 200 * time.Millisecond}
	client, server := net.Pipe()
	defer client.Close()
	ln := &flakyListener{failures: 3, conn: server}

	err := s.acceptTCP(ln)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("acceptTCP returned %v, want net.ErrClosed", err)
	}
	if !ln.accepted {
		t.Fatal("listener gave up before the temporary errors cleared")
	}
}

// TestZonedAddressIsRejected checks that an IPv6 zone is refused on the way
// in, so free text after "%" never reaches the file or the log, and that a
// file written by an older version with a zone still loads.
func TestZonedAddressIsRejected(t *testing.T) {
	s := testStore(t, nil)
	for _, ip := range []string{"fe80::1%eth0", "fe80::1%x\nweb: deleted bank.example.io"} {
		var bad invalidError
		if err := s.set("z.example.io", ip); !errors.As(err, &bad) {
			t.Errorf("set(%q) = %v, want an invalid-input error", ip, err)
		}
	}

	path := filepath.Join(t.TempDir(), "records.json")
	if err := os.WriteFile(path, []byte(`[{"domain":"z.example.io","ip":"fe80::1%eth0"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := newStore(path)
	if err != nil {
		t.Fatalf("loading a file with a zoned address: %v", err)
	}
	if addr, ok := loaded.lookup("z.example.io"); !ok || addr.String() != "fe80::1" {
		t.Errorf("lookup = %v, %v; want fe80::1 without zone", addr, ok)
	}
}
