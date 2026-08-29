package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// withEDNS appends an OPT record advertising size, as an EDNS0 client would.
func withEDNS(query []byte, size uint16) []byte {
	binary.BigEndian.PutUint16(query[10:12], 1) // ARCOUNT
	opt := []byte{0}
	opt = binary.BigEndian.AppendUint16(opt, typeOPT)
	opt = binary.BigEndian.AppendUint16(opt, size)
	opt = binary.BigEndian.AppendUint32(opt, 0)
	opt = binary.BigEndian.AppendUint16(opt, 0)
	return append(query, opt...)
}

// stubUpstream answers every query with a response padded past size bytes, and
// returns the address plus the exact response it hands out.
func stubUpstream(t *testing.T, size int) (addr string, response []byte) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	build := func(query []byte, q question) []byte {
		var answers []byte
		count := 0
		for len(answers) < size {
			answers = append(answers, answerRecord(q.nameBytes(query), typeA, 30, []byte{93, 184, 216, 34})...)
			count++
		}
		return reply(query, q, rcodeNoError, answers, count, edns{})
	}

	go func() {
		buf := make([]byte, maxEDNSLen)
		for {
			n, client, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query := buf[:n]
			q, err := parseQuestion(query)
			if err != nil {
				continue
			}
			conn.WriteTo(build(query, q), client)
		}
	}()

	probe := buildQuery(t, "example.com", typeA)
	q, err := parseQuestion(probe)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return conn.LocalAddr().String(), build(probe, q)
}

func TestParseQuestionRejectsOversizedName(t *testing.T) {
	name := strings.TrimSuffix(strings.Repeat("label.", 50), ".") // ~300 bytes encoded
	if _, err := parseQuestion(buildQuery(t, name, typeA)); err == nil {
		t.Error("a name longer than 255 bytes should be rejected")
	}
}

func TestEDNSPayloadSizeIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query []byte
		want  int
	}{
		{"no EDNS", buildQuery(t, "example.com", typeA), maxUDPLen},
		{"EDNS 1232", withEDNS(buildQuery(t, "example.com", typeA), 1232), 1232},
		{"EDNS below 512", withEDNS(buildQuery(t, "example.com", typeA), 300), maxUDPLen},
		{"EDNS above cap", withEDNS(buildQuery(t, "example.com", typeA), 60000), maxEDNSLen},
	} {
		q, err := parseQuestion(tc.query)
		if err != nil {
			t.Fatalf("%s: parseQuestion: %v", tc.name, err)
		}
		if got := parseEDNS(tc.query, q).udpLimit(); got != tc.want {
			t.Errorf("%s: udpLimit = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestLargeAnswerFitsEDNSBuffer is the regression test for truncating at 512
// bytes even though the client said it could take more.
func TestLargeAnswerFitsEDNSBuffer(t *testing.T) {
	upstream, big := stubUpstream(t, 800)
	s := &dnsServer{store: testStore(t, nil), upstream: upstream, ttl: 60, timeout: 2 * time.Second}

	resp := s.handle(withEDNS(buildQuery(t, "example.com", typeA), 1232), false)
	if len(resp) != len(big) {
		t.Errorf("EDNS client got %d bytes, want the full %d", len(resp), len(big))
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0x0200 != 0 {
		t.Error("EDNS client should not have been told to retry over TCP")
	}

	plain := s.handle(buildQuery(t, "example.com", typeA), false)
	if flags := binary.BigEndian.Uint16(plain[2:4]); flags&0x0200 == 0 {
		t.Error("client without EDNS should get TC=1 for an 800 byte answer")
	}
	if len(plain) > maxUDPLen {
		t.Errorf("truncated response is %d bytes, want at most %d", len(plain), maxUDPLen)
	}
}

// TestUpstreamMismatchIsIgnored covers a stale or spoofed datagram arriving
// from the upstream address ahead of the real answer.
func TestUpstreamMismatchIsIgnored(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, maxEDNSLen)
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte{}, buf[:n]...)
		q, err := parseQuestion(query)
		if err != nil {
			return
		}
		wrong := reply(query, q, rcodeNoError, answerRecord(q.nameBytes(query), typeA, 30, []byte{6, 6, 6, 6}), 1, edns{})
		binary.BigEndian.PutUint16(wrong[0:2], 0x9999)
		conn.WriteTo(wrong, client)
		conn.WriteTo(reply(query, q, rcodeNoError, answerRecord(q.nameBytes(query), typeA, 30, []byte{93, 184, 216, 34}), 1, edns{}), client)
	}()

	s := &dnsServer{store: testStore(t, nil), upstream: conn.LocalAddr().String(), ttl: 60, timeout: 2 * time.Second}
	resp := s.handle(buildQuery(t, "example.com", typeA), false)

	if ip := net.IP(resp[len(resp)-4:]).String(); ip != "93.184.216.34" {
		t.Errorf("client got %s, want the answer matching its query ID", ip)
	}
}

func TestFormErrCarriesNoQuestion(t *testing.T) {
	query := buildQuery(t, "example.com", typeA)
	bad := append(append([]byte{}, query[:headerLen]...), 0xC0, 0x0C) // compression pointer

	s := &dnsServer{store: testStore(t, nil), ttl: 60, timeout: time.Second}
	resp := s.handle(bad, false)

	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F; rcode != rcodeFormErr {
		t.Errorf("rcode = %d, want FORMERR", rcode)
	}
	if qd := binary.BigEndian.Uint16(resp[4:6]); qd != 0 {
		t.Errorf("QDCOUNT = %d, want 0 when no question is echoed", qd)
	}
	if len(resp) != headerLen {
		t.Errorf("response is %d bytes, want just the header", len(resp))
	}
}

func TestLocalAnswerEchoesOPT(t *testing.T) {
	s := &dnsServer{
		store:   testStore(t, map[string]string{"home.jumoog.io": "100.110.251.125"}),
		ttl:     60,
		timeout: time.Second,
	}
	resp := s.handle(withEDNS(buildQuery(t, "home.jumoog.io", typeA), 1232), false)

	if ar := binary.BigEndian.Uint16(resp[10:12]); ar != 1 {
		t.Fatalf("ARCOUNT = %d, want one OPT record", ar)
	}
	opt := resp[len(resp)-11:]
	if opt[0] != 0 || binary.BigEndian.Uint16(opt[1:3]) != typeOPT {
		t.Errorf("last record is not an OPT: %v", opt)
	}
	if size := binary.BigEndian.Uint16(opt[3:5]); size != ourUDPSize {
		t.Errorf("advertised size = %d, want %d", size, ourUDPSize)
	}
}

func TestServeTCPHandlesSeveralQueries(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	s := &dnsServer{
		store:   testStore(t, map[string]string{"home.jumoog.io": "100.110.251.125"}),
		ttl:     60,
		timeout: 2 * time.Second,
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.serveTCP(conn)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	for i := range 3 {
		if _, err := conn.Write(frame(buildQuery(t, "home.jumoog.io", typeA))); err != nil {
			t.Fatalf("query %d: write: %v", i, err)
		}
		resp, err := readTCPMessage(conn)
		if err != nil {
			t.Fatalf("query %d on the same connection: %v", i, err)
		}
		if ip := net.IP(resp[len(resp)-4:]).String(); ip != "100.110.251.125" {
			t.Errorf("query %d: rdata = %s", i, ip)
		}
	}
}

func TestStoreRejectsUnaddressableDomain(t *testing.T) {
	s := testStore(t, nil)
	for _, domain := range []string{
		"10.0.0.5/24",
		"has space.jumoog.io",
		strings.Repeat("x", 64) + ".jumoog.io",
		"*.",
		"..jumoog.io",
	} {
		if err := s.set(domain, "10.0.0.1"); err == nil {
			t.Errorf("%q should have been rejected", domain)
		}
	}
	if got := s.list(); len(got) != 0 {
		t.Errorf("store holds %+v, want nothing", got)
	}
}

// TestSetRollsBackWhenSaveFails checks that a record which could not be
// persisted does not stay live in memory.
func TestSetRollsBackWhenSaveFails(t *testing.T) {
	dir := t.TempDir()
	s, err := newStore(filepath.Join(dir, "missing", "records.json"))
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}

	err = s.set("home.jumoog.io", "100.110.251.125")
	if err == nil {
		t.Fatal("set should have failed to write the record file")
	}
	var bad invalidError
	if errors.As(err, &bad) {
		t.Errorf("a failed write is not the caller's mistake: %v", err)
	}
	if _, ok := s.lookup("home.jumoog.io"); ok {
		t.Error("record must not resolve after its save failed")
	}
}

func TestAPIRejectsBadDomainWith400(t *testing.T) {
	web := &webServer{store: testStore(t, nil)}
	srv := httptest.NewServer(web.routes())
	defer srv.Close()

	res, err := http.Post(srv.URL+"/api/records", "application/json", strings.NewReader(`{"domain":"10.0.0.5/24","ip":"10.0.0.1"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", res.StatusCode)
	}
}

// TestConcurrentWritersKeepFileAndMemoryInSync hammers the store from several
// goroutines while queries read it, and checks that what survives on disk is
// exactly what memory believes. This is the case that used to lose a record
// when two writers interleaved their save.
func TestConcurrentWritersKeepFileAndMemoryInSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.json")
	s, err := newStore(path)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	if err := s.set("fixed.jumoog.io", "100.110.251.125"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := &dnsServer{store: s, ttl: 60, timeout: time.Second}
	query := buildQuery(t, "fixed.jumoog.io", typeA)

	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				domain := fmt.Sprintf("host%d-%d.jumoog.io", w, i)
				if err := s.set(domain, "10.0.0.1"); err != nil {
					t.Errorf("set %s: %v", domain, err)
					return
				}
				if _, ok := s.lookup(domain); !ok {
					t.Errorf("%s did not resolve right after it was set", domain)
					return
				}
				s.list()
				if i%3 == 0 {
					if _, err := s.delete(domain); err != nil {
						t.Errorf("delete %s: %v", domain, err)
						return
					}
				}
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if resp := srv.handle(query, false); binary.BigEndian.Uint16(resp[6:8]) != 1 {
					t.Error("concurrent query missed the seeded record")
					return
				}
			}
		}()
	}
	wg.Wait()

	reloaded, err := newStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if want, got := s.list(), reloaded.list(); !slices.Equal(want, got) {
		t.Errorf("disk holds %d records, memory holds %d", len(got), len(want))
	}
}
