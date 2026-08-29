package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// encodeName writes name in label form, as a client would put it on the wire.
func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// buildQuery makes a minimal query for name/qtype, as a client would send.
func buildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, encodeName(name)...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	return binary.BigEndian.AppendUint16(msg, classINET)
}

func testStore(t *testing.T, records map[string]string) *store {
	t.Helper()
	s, err := newStore(filepath.Join(t.TempDir(), "records.json"))
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	for domain, ip := range records {
		if err := s.set(domain, ip); err != nil {
			t.Fatalf("set %s: %v", domain, err)
		}
	}
	return s
}

func TestParseQuestion(t *testing.T) {
	q, err := parseQuestion(buildQuery(t, "Home.Jumoog.io", typeA))
	if err != nil {
		t.Fatalf("parseQuestion: %v", err)
	}
	if q.name != "home.jumoog.io" || q.qtype != typeA || q.class != classINET {
		t.Fatalf("got %+v", q)
	}
}

func TestParseQuestionRejectsMalformed(t *testing.T) {
	query := buildQuery(t, "example.com", typeA)

	noQuestion := append([]byte{}, query...)
	binary.BigEndian.PutUint16(noQuestion[4:6], 0)

	cases := map[string][]byte{
		"short header":   query[:8],
		"truncated name": query[:headerLen+4],
		"pointer":        append(append([]byte{}, query[:headerLen]...), 0xC0, 0x0C),
		"no question":    noQuestion,
	}
	for name, msg := range cases {
		if _, err := parseQuestion(msg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestStoreLookup(t *testing.T) {
	s := testStore(t, map[string]string{
		"home.jumoog.io":  "100.110.251.125",
		"*.jumoog.io":     "10.0.0.1",
		"*.dev.jumoog.io": "10.0.0.2",
		"v6.jumoog.io":    "2001:db8::1",
	})

	for _, tc := range []struct{ name, want string }{
		{"home.jumoog.io", "100.110.251.125"}, // exact beats wildcard
		{"HOME.jumoog.io", "100.110.251.125"}, // names are case-folded
		{"other.jumoog.io", "10.0.0.1"},
		{"api.dev.jumoog.io", "10.0.0.2"}, // most specific wildcard wins
		{"v6.jumoog.io", "2001:db8::1"},
	} {
		addr, ok := s.lookup(normalize(tc.name))
		if !ok || addr.String() != tc.want {
			t.Errorf("lookup(%q) = %v/%v, want %s", tc.name, addr, ok, tc.want)
		}
	}
	if _, ok := s.lookup("example.com"); ok {
		t.Error("example.com should not resolve locally")
	}
}

func TestStoreSetRejectsBadInput(t *testing.T) {
	s := testStore(t, nil)
	if err := s.set("", "1.2.3.4"); err == nil {
		t.Error("empty domain should be rejected")
	}
	if err := s.set("example.com", "not-an-ip"); err == nil {
		t.Error("invalid IP should be rejected")
	}
}

func TestStoreDeleteAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.json")
	s, err := newStore(path)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	if err := s.set("home.jumoog.io", "100.110.251.125"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := s.set("*.jumoog.io", "10.0.0.1"); err != nil {
		t.Fatalf("set: %v", err)
	}
	reloaded, err := newStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.list(); len(got) != 2 || got[0].Domain != "*.jumoog.io" {
		t.Fatalf("reloaded %+v", got)
	}
	if deleted, err := reloaded.delete("HOME.jumoog.io."); !deleted || err != nil {
		t.Errorf("delete should normalize the domain: %v/%v", deleted, err)
	}
	if deleted, err := reloaded.delete("home.jumoog.io"); deleted || err != nil {
		t.Errorf("second delete should report nothing removed: %v/%v", deleted, err)
	}
	if deleted, err := reloaded.delete("*.jumoog.io"); !deleted || err != nil {
		t.Errorf("wildcard should be deletable: %v/%v", deleted, err)
	}
}

func TestHandleLocalRecord(t *testing.T) {
	s := &dnsServer{
		store:   testStore(t, map[string]string{"home.jumoog.io": "100.110.251.125"}),
		ttl:     60,
		timeout: time.Second,
	}
	resp := s.handle(buildQuery(t, "home.jumoog.io", typeA), false)

	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Errorf("ID = %#x, want 0x1234", got)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 || flags&0x0400 == 0 || flags&0x0080 == 0 || flags&0x000F != rcodeNoError {
		t.Errorf("flags = %#x, want QR+AA+RA and NOERROR", flags)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", got)
	}

	q, err := parseQuestion(resp)
	if err != nil {
		t.Fatalf("response question: %v", err)
	}
	rr := resp[q.end:]
	fields := rr[len(encodeName(q.name)):]
	if ttl := binary.BigEndian.Uint32(fields[4:8]); ttl != 60 {
		t.Errorf("TTL = %d, want 60", ttl)
	}
	if rdlen := binary.BigEndian.Uint16(fields[8:10]); rdlen != 4 {
		t.Fatalf("RDLENGTH = %d, want 4", rdlen)
	}
	if ip := net.IP(fields[10:14]).String(); ip != "100.110.251.125" {
		t.Errorf("rdata = %s", ip)
	}
}

func TestHandleWrongFamilyIsEmptyNoError(t *testing.T) {
	s := &dnsServer{
		store:   testStore(t, map[string]string{"home.jumoog.io": "100.110.251.125"}),
		ttl:     60,
		timeout: time.Second,
	}
	resp := s.handle(buildQuery(t, "home.jumoog.io", typeAAAA), false)

	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F; rcode != rcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", rcode)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
		t.Errorf("ANCOUNT = %d, want 0", got)
	}
}

// TestHandleForwardsUnknownNames points the server at a stub resolver and
// checks the upstream answer comes back untouched.
func TestHandleForwardsUnknownNames(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstream.Close()

	go func() {
		buf := make([]byte, 4096)
		n, client, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		query := buf[:n]
		q, err := parseQuestion(query)
		if err != nil {
			return
		}
		rr := answerRecord(q.nameBytes(query), typeA, 30, []byte{93, 184, 216, 34})
		upstream.WriteTo(reply(query, q, rcodeNoError, rr, 1, edns{}), client)
	}()

	s := &dnsServer{
		store:    testStore(t, nil),
		upstream: upstream.LocalAddr().String(),
		ttl:      60,
		timeout:  2 * time.Second,
	}
	resp := s.handle(buildQuery(t, "example.com", typeA), false)

	if got := binary.BigEndian.Uint16(resp[6:8]); got != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", got)
	}
	q, err := parseQuestion(resp)
	if err != nil {
		t.Fatalf("response question: %v", err)
	}
	rdata := resp[q.end:][len(encodeName(q.name))+10:]
	if ip := net.IP(rdata).String(); ip != "93.184.216.34" {
		t.Errorf("rdata = %s, want the upstream answer", ip)
	}
}

func TestHandleUnreachableUpstreamIsServfail(t *testing.T) {
	s := &dnsServer{
		store:    testStore(t, nil),
		upstream: "127.0.0.1:1",
		ttl:      60,
		timeout:  200 * time.Millisecond,
	}
	resp := s.handle(buildQuery(t, "example.com", typeA), false)
	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F; rcode != rcodeServFail {
		t.Errorf("rcode = %d, want SERVFAIL", rcode)
	}
}

func TestAPIAddListDelete(t *testing.T) {
	web := &webServer{store: testStore(t, nil)}
	srv := httptest.NewServer(web.routes())
	defer srv.Close()

	post := func(body string) *http.Response {
		t.Helper()
		res, err := http.Post(srv.URL+"/api/records", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		t.Cleanup(func() { res.Body.Close() })
		return res
	}

	if res := post(`{"domain":"Home.Jumoog.io","ip":"100.110.251.125"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("add status = %d, want 200", res.StatusCode)
	}
	if res := post(`{"domain":"home.jumoog.io","ip":"nope"}`); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid IP status = %d, want 400", res.StatusCode)
	}

	res, err := http.Get(srv.URL + "/api/records")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	var records []record
	if err := json.NewDecoder(res.Body).Decode(&records); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(records) != 1 || records[0].Domain != "home.jumoog.io" {
		t.Fatalf("records = %+v", records)
	}

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/records/home.jumoog.io", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	del, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", del.StatusCode)
	}

	again, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete again: %v", err)
	}
	again.Body.Close()
	if again.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", again.StatusCode)
	}
}

func TestIndexIsServed(t *testing.T) {
	web := &webServer{store: testStore(t, nil)}
	srv := httptest.NewServer(web.routes())
	defer srv.Close()

	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}
