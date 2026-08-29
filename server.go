package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"time"
)

// tcpIdleTimeout is how long a TCP connection may sit between queries. RFC 7766
// wants connections reused, so this outlives a single exchange.
const tcpIdleTimeout = 30 * time.Second

var errMismatch = errors.New("upstream response does not answer our query")

type dnsServer struct {
	store    *store
	upstream string
	ttl      uint32
	timeout  time.Duration
}

// safeHandle keeps one bad message from taking the whole server down: a panic
// in a query goroutine would otherwise end the process and the network's DNS
// with it.
func (s *dnsServer) safeHandle(query []byte, tcp bool) (resp []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("dns: recovered while handling a query: %v", r)
			resp = nil
		}
	}()
	return s.handle(query, tcp)
}

// handle answers a query from the local records, or forwards it upstream.
// tcp reports whether the caller can carry responses larger than 512 bytes.
func (s *dnsServer) handle(query []byte, tcp bool) []byte {
	q, err := parseQuestion(query)
	if err != nil {
		if len(query) < headerLen {
			return nil
		}
		return reply(query, question{end: headerLen}, rcodeFormErr, nil, 0, edns{})
	}
	client := parseEDNS(query, q)

	if q.class == classINET && (q.qtype == typeA || q.qtype == typeAAAA) {
		if addr, ok := s.store.lookup(q.name); ok {
			return s.localAnswer(query, q, client, addr)
		}
	}

	resp, err := s.forward(query, q, tcp)
	if err != nil {
		log.Printf("dns: forwarding %q to %s: %v", q.name, s.upstream, err)
		return reply(query, q, rcodeServFail, nil, 0, client)
	}
	if !tcp && len(resp) > client.udpLimit() {
		return truncate(query, q, int(binary.BigEndian.Uint16(resp[2:4])&0x000F), client)
	}
	return resp
}

// localAnswer serves a stored record. A record of the other family answers
// NOERROR with no data, which is what a name that exists but has no address of
// that type is supposed to return.
func (s *dnsServer) localAnswer(query []byte, q question, client edns, addr netip.Addr) []byte {
	if addr.Is4() != (q.qtype == typeA) {
		return reply(query, q, rcodeNoError, nil, 0, client)
	}
	rr := answerRecord(q.nameBytes(query), q.qtype, s.ttl, addr.AsSlice())
	return reply(query, q, rcodeNoError, rr, 1, client)
}

// forward relays the query verbatim to the upstream resolver. UDP queries are
// forwarded over UDP so that upstream can size its own response; a truncated
// answer is retried over TCP.
func (s *dnsServer) forward(query []byte, q question, tcp bool) ([]byte, error) {
	if tcp {
		return s.forwardTCP(query, q)
	}

	resp, err := s.forwardUDP(query, q)
	if err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(resp[2:4])&0x0200 == 0 {
		return resp, nil
	}
	if tcpResp, err := s.forwardTCP(query, q); err == nil {
		return tcpResp, nil
	}
	return resp, nil
}

func (s *dnsServer) forwardUDP(query []byte, q question) ([]byte, error) {
	conn, err := net.DialTimeout("udp", s.upstream, s.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// Keep reading until the deadline: a stale or spoofed datagram must not
	// become the client's answer just because it arrived first.
	buf := make([]byte, maxEDNSLen)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if answers(buf[:n], query, q) {
			return buf[:n], nil
		}
	}
}

func (s *dnsServer) forwardTCP(query []byte, q question) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", s.upstream, s.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(frame(query)); err != nil {
		return nil, err
	}
	resp, err := readTCPMessage(conn)
	if err != nil {
		return nil, err
	}
	if !answers(resp, query, q) {
		return nil, errMismatch
	}
	return resp, nil
}

// answers reports whether resp is a reply to query: same transaction ID and the
// same question. Without this check any datagram from the upstream address
// would be passed on to the client as its answer.
func answers(resp, query []byte, q question) bool {
	if len(resp) < q.end {
		return false
	}
	if !bytes.Equal(resp[:2], query[:2]) {
		return false
	}
	if !equalName(resp[headerLen:q.end-4], query[headerLen:q.end-4]) {
		return false
	}
	return bytes.Equal(resp[q.end-4:q.end], query[q.end-4:q.end])
}

// frame prefixes a message with its length for transport over TCP
// (RFC 1035 section 4.2.2).
func frame(msg []byte) []byte {
	out := binary.BigEndian.AppendUint16(make([]byte, 0, len(msg)+2), uint16(len(msg)))
	return append(out, msg...)
}

// readTCPMessage reads one length-prefixed DNS message.
func readTCPMessage(conn net.Conn) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *dnsServer) listenUDP(addr string) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("dns: listening on %s (udp)", conn.LocalAddr())

	buf := make([]byte, maxEDNSLen)
	for {
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func() {
			if resp := s.safeHandle(query, false); resp != nil {
				if _, err := conn.WriteTo(resp, client); err != nil {
					log.Printf("dns: replying to %s: %v", client, err)
				}
			}
		}()
	}
}

func (s *dnsServer) listenTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("dns: listening on %s (tcp)", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serveTCP(conn)
	}
}

// serveTCP answers queries until the client closes the connection or goes
// quiet, since a client may send several down one connection.
func (s *dnsServer) serveTCP(conn net.Conn) {
	defer conn.Close()
	for {
		if err := conn.SetDeadline(time.Now().Add(tcpIdleTimeout)); err != nil {
			return
		}
		query, err := readTCPMessage(conn)
		if err != nil {
			return
		}
		resp := s.safeHandle(query, true)
		if resp == nil {
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
			return
		}
		if _, err := conn.Write(frame(resp)); err != nil {
			log.Printf("dns: replying to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}
