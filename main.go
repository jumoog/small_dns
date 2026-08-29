package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	dnsAddr := flag.String("dns", ":53", "address for the DNS listener (UDP and TCP)")
	httpAddr := flag.String("http", ":8080", "address for the web UI")
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream resolver for names we do not own")
	dbPath := flag.String("records", "records.json", "path to the records file")
	ttl := flag.Uint("ttl", 60, "TTL in seconds for locally served records")
	timeout := flag.Duration("timeout", 3*time.Second, "upstream query timeout")
	flag.Parse()

	records, err := newStore(*dbPath)
	if err != nil {
		log.Fatalf("loading %s: %v", *dbPath, err)
	}
	log.Printf("loaded %d records from %s", len(records.list()), *dbPath)

	dns := &dnsServer{
		store:    records,
		upstream: *upstream,
		ttl:      uint32(*ttl),
		timeout:  *timeout,
	}

	errs := make(chan error, 3)
	go func() { errs <- dns.listenUDP(*dnsAddr) }()
	go func() { errs <- dns.listenTCP(*dnsAddr) }()
	go func() {
		web := &webServer{store: records}
		server := &http.Server{
			Addr:              *httpAddr,
			Handler:           web.routes(),
			ReadHeaderTimeout: 5 * time.Second,
		}
		log.Printf("web: listening on %s", *httpAddr)
		errs <- server.ListenAndServe()
	}()

	log.Fatal(<-errs)
}
