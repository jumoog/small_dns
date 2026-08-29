package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Minimal DNS wire-format helpers (RFC 1035). We only parse as much of a
// message as we need to decide whether we can answer it locally; anything we
// cannot answer is proxied upstream verbatim, so unknown record types never
// need a decoder here.

const (
	typeA    = 1
	typeAAAA = 28
	typeOPT  = 41

	classINET = 1

	rcodeNoError  = 0
	rcodeFormErr  = 1
	rcodeServFail = 2
	rcodeNXDomain = 3

	headerLen = 12
	// maxUDPLen is what a client that did not announce EDNS0 can receive;
	// maxEDNSLen caps what we believe from one that did.
	maxUDPLen  = 512
	maxEDNSLen = 4096
	// ourUDPSize is the payload size we announce in our own OPT records.
	ourUDPSize = 1232
	// maxNameLen is the longest encoded name (RFC 1035 section 2.3.4). Without
	// this limit a query could push the question offset past the length of any
	// response built from it.
	maxNameLen = 255
)

var errMalformed = errors.New("malformed dns message")

type question struct {
	name  string // lower-case, no trailing dot
	qtype uint16
	class uint16
	end   int // offset just past the question section
}

// nameBytes returns the question's name still in wire form, which is what an
// answer's owner name has to repeat.
func (q question) nameBytes(msg []byte) []byte {
	return msg[headerLen : q.end-4]
}

// parseQuestion reads the question of a query. Compression pointers are not
// legal in a question, and messages carrying more than one question are
// rejected rather than half-understood.
func parseQuestion(msg []byte) (question, error) {
	var q question
	if len(msg) < headerLen {
		return q, errMalformed
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return q, errMalformed
	}

	var labels []string
	off := headerLen
	for {
		if off >= len(msg) {
			return q, errMalformed
		}
		n := int(msg[off])
		if n&0xC0 != 0 {
			return q, errMalformed
		}
		off++
		if n == 0 {
			break
		}
		if off+n > len(msg) {
			return q, errMalformed
		}
		labels = append(labels, string(msg[off:off+n]))
		off += n
		if off-headerLen > maxNameLen {
			return q, errMalformed
		}
	}
	if off+4 > len(msg) {
		return q, errMalformed
	}

	q.name = strings.ToLower(strings.Join(labels, "."))
	q.qtype = binary.BigEndian.Uint16(msg[off : off+2])
	q.class = binary.BigEndian.Uint16(msg[off+2 : off+4])
	q.end = off + 4
	return q, nil
}

// edns is what a client's OPT pseudo-record told us (RFC 6891).
type edns struct {
	present bool
	udpSize int
}

// udpLimit is the largest response this client can take over UDP.
func (e edns) udpLimit() int {
	if !e.present || e.udpSize < maxUDPLen {
		return maxUDPLen
	}
	return min(e.udpSize, maxEDNSLen)
}

// parseEDNS looks for an OPT record in the query's additional section. Anything
// it cannot follow is reported as "no EDNS0", which only costs us the smaller
// response size.
func parseEDNS(msg []byte, q question) edns {
	var e edns
	skip := int(binary.BigEndian.Uint16(msg[6:8])) + int(binary.BigEndian.Uint16(msg[8:10]))
	extra := int(binary.BigEndian.Uint16(msg[10:12]))

	off := q.end
	for i := range skip + extra {
		nameEnd, ok := skipName(msg, off)
		if !ok || nameEnd+10 > len(msg) {
			return e
		}
		if i >= skip && binary.BigEndian.Uint16(msg[nameEnd:nameEnd+2]) == typeOPT {
			e.present = true
			e.udpSize = int(binary.BigEndian.Uint16(msg[nameEnd+2 : nameEnd+4]))
			return e
		}
		off = nameEnd + 10 + int(binary.BigEndian.Uint16(msg[nameEnd+8:nameEnd+10]))
		if off > len(msg) {
			return e
		}
	}
	return e
}

// skipName returns the offset just past the name at off, following at most one
// compression pointer.
func skipName(msg []byte, off int) (int, bool) {
	for {
		if off >= len(msg) {
			return 0, false
		}
		n := int(msg[off])
		switch {
		case n == 0:
			return off + 1, true
		case n&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case n&0xC0 != 0:
			return 0, false
		}
		off += 1 + n
	}
}

// optRecord is the OPT pseudo-record we send back to an EDNS0 client: root
// name, our payload size in the class field, no options.
func optRecord() []byte {
	rr := []byte{0}
	rr = binary.BigEndian.AppendUint16(rr, typeOPT)
	rr = binary.BigEndian.AppendUint16(rr, ourUDPSize)
	rr = binary.BigEndian.AppendUint32(rr, 0) // extended rcode 0, version 0, no flags
	return binary.BigEndian.AppendUint16(rr, 0)
}

// reply builds a response that echoes the query's header and question section.
// answers is the already-encoded answer section and count is how many records
// it holds; an OPT record is added back when the client used EDNS0.
func reply(query []byte, q question, rcode int, answers []byte, count int, client edns) []byte {
	asked := query[headerLen:q.end] // empty when the question could not be parsed
	questions := 1
	if len(asked) == 0 {
		questions = 0
	}
	var opt []byte
	var additional int
	if client.present {
		opt = optRecord()
		additional = 1
	}

	out := make([]byte, headerLen, headerLen+len(asked)+len(answers)+len(opt))
	copy(out, query[:headerLen])

	flags := binary.BigEndian.Uint16(query[2:4])
	rd := flags & 0x0100                           // preserve recursion-desired
	opcode := flags & 0x7800                       // preserve opcode
	flags = 0x8000 | opcode | 0x0400 | rd | 0x0080 // QR, AA, RD, RA
	flags |= uint16(rcode)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], uint16(questions))
	binary.BigEndian.PutUint16(out[6:8], uint16(count))
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], uint16(additional))

	out = append(out, asked...)
	out = append(out, answers...)
	return append(out, opt...)
}

// answerRecord encodes one A or AAAA resource record. owner is the name in wire
// form, copied from the question so it matches byte for byte.
func answerRecord(owner []byte, qtype uint16, ttl uint32, rdata []byte) []byte {
	rr := make([]byte, 0, len(owner)+10+len(rdata))
	rr = append(rr, owner...)
	rr = binary.BigEndian.AppendUint16(rr, qtype)
	rr = binary.BigEndian.AppendUint16(rr, classINET)
	rr = binary.BigEndian.AppendUint32(rr, ttl)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
	return append(rr, rdata...)
}

// truncate builds an empty TC=1 answer so a UDP client knows to retry over TCP.
// It is built from the client's own query rather than from the oversized
// response, whose layout beyond the header we have not parsed.
func truncate(query []byte, q question, rcode int, client edns) []byte {
	out := reply(query, q, rcode, nil, 0, client)
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|0x0200)
	return out
}

// equalName compares two encoded names, ignoring ASCII case the way DNS does.
func equalName(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
