package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// maxDomainLen is the longest name in presentation form, one byte shorter than
// the encoded form it has to fit into.
const maxDomainLen = 253

// record is one domain -> IP mapping as shown in the web UI.
type record struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

// invalidError is a caller's mistake rather than ours, which the API answers
// with 400 instead of 500.
type invalidError struct{ msg string }

func (e invalidError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return invalidError{msg: fmt.Sprintf(format, args...)}
}

// store keeps the records in memory and mirrors them to a JSON file. Exact
// names and wildcards ("*.example.com", matching one or more leading labels)
// are supported; the most specific match wins.
type store struct {
	mu    sync.RWMutex
	path  string
	exact map[string]netip.Addr
	wild  map[string]netip.Addr // key is the suffix without "*."
}

func newStore(path string) (*store, error) {
	s := &store{
		path:  path,
		exact: map[string]netip.Addr{},
		wild:  map[string]netip.Addr{},
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var records []record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	for _, r := range records {
		name, addr, err := parseRecord(r.Domain, r.IP)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Domain, err)
		}
		key, table := s.tableFor(name)
		table[key] = addr
	}
	return s, nil
}

// normalize lower-cases a name and strips the root dot so lookups and the UI
// agree on what a record is called.
func normalize(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// parseRecord validates one domain/IP pair. Domains are checked here rather
// than at query time so a name that cannot go on the wire — or cannot be
// addressed through /api/records/{domain} — never enters the store.
func parseRecord(domain, ip string) (string, netip.Addr, error) {
	name := normalize(domain)
	if name == "" {
		return "", netip.Addr{}, invalid("domain must not be empty")
	}
	labels, isWildcard := strings.CutPrefix(name, "*.")
	if isWildcard && labels == "" {
		return "", netip.Addr{}, invalid("wildcard needs a suffix")
	}
	if len(labels) > maxDomainLen {
		return "", netip.Addr{}, invalid("domain is longer than %d characters", maxDomainLen)
	}
	for _, label := range strings.Split(labels, ".") {
		if label == "" || len(label) > 63 {
			return "", netip.Addr{}, invalid("every label must be 1 to 63 characters")
		}
		for i := range len(label) {
			switch c := label[i]; {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return "", netip.Addr{}, invalid("%q is not a valid domain", name)
			}
		}
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", netip.Addr{}, invalid("invalid IP address")
	}
	return name, addr.Unmap(), nil
}

// tableFor picks the map a name belongs in and the key it is stored under.
func (s *store) tableFor(name string) (string, map[string]netip.Addr) {
	if suffix, ok := strings.CutPrefix(name, "*."); ok {
		return suffix, s.wild
	}
	return name, s.exact
}

// set adds or replaces a record. The write to disk happens under the same lock
// as the change in memory, and is rolled back if it fails, so the two can never
// drift apart.
func (s *store) set(domain, ip string) error {
	name, addr, err := parseRecord(domain, ip)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key, table := s.tableFor(name)
	previous, existed := table[key]
	table[key] = addr
	if err := s.saveLocked(); err != nil {
		if existed {
			table[key] = previous
		} else {
			delete(table, key)
		}
		return err
	}
	return nil
}

// delete removes a record, reporting whether there was one. Like set, the file
// is rewritten under the lock and the change is undone if that fails.
func (s *store) delete(domain string) (bool, error) {
	name := normalize(domain)

	s.mu.Lock()
	defer s.mu.Unlock()
	key, table := s.tableFor(name)
	previous, existed := table[key]
	if !existed {
		return false, nil
	}
	delete(table, key)
	if err := s.saveLocked(); err != nil {
		table[key] = previous
		return false, err
	}
	return true, nil
}

// lookup resolves name, preferring an exact record and otherwise walking up the
// labels to find the longest matching wildcard.
func (s *store) lookup(name string) (netip.Addr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if addr, ok := s.exact[name]; ok {
		return addr, true
	}
	for rest := name; rest != ""; {
		_, after, found := strings.Cut(rest, ".")
		if !found {
			break
		}
		if addr, ok := s.wild[after]; ok {
			return addr, true
		}
		rest = after
	}
	return netip.Addr{}, false
}

// list returns every record sorted by domain, as the UI displays them.
func (s *store) list() []record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listLocked()
}

func (s *store) listLocked() []record {
	records := make([]record, 0, len(s.exact)+len(s.wild))
	for name, addr := range s.exact {
		records = append(records, record{Domain: name, IP: addr.String()})
	}
	for suffix, addr := range s.wild {
		records = append(records, record{Domain: "*." + suffix, IP: addr.String()})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Domain < records[j].Domain })
	return records
}

// saveLocked writes the records atomically so a crash mid-write cannot truncate
// the existing file. The caller must hold the write lock.
func (s *store) saveLocked() error {
	data, err := json.MarshalIndent(s.listLocked(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".records-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
