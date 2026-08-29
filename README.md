# smalldns

A small authoritative-ish DNS server for a home network or a tailnet: it
answers the A/AAAA records you configure and forwards everything else to an
upstream resolver. Records are managed from a web UI and stored in a JSON
file. Handy as a Tailscale split-DNS resolver, so a public server’s names
resolve to its tailnet address from inside the tailnet — see below.

No dependencies — standard library only, including the DNS wire format.

## Run

```bash
go run . -dns :53 -http :8080 -upstream 1.1.1.1:53 -records records.json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-dns` | `:53` | address for the DNS listener (UDP **and** TCP) |
| `-http` | `:8080` | address for the web UI |
| `-upstream` | `1.1.1.1:53` | resolver used for names you have not configured |
| `-records` | `records.json` | record file, rewritten on every change |
| `-ttl` | `60` | TTL in seconds for locally served records |
| `-timeout` | `3s` | upstream query timeout |

Port 53 needs elevation (Administrator on Windows, root or
`CAP_NET_BIND_SERVICE` on Linux). For a quick test, use a high port:

```bash
go run . -dns 127.0.0.1:5354 -http 127.0.0.1:8085
```

Then open http://127.0.0.1:8085 and add records, or use the API:

```bash
curl -X POST -H 'Content-Type: application/json' -d '{"domain":"home.example.io","ip":"10.0.0.5"}' http://127.0.0.1:8085/api/records
```

## Docker

Images are published to `ghcr.io/jumoog/small_dns` for `linux/amd64`,
`linux/arm64` and `linux/arm/v7`.

```bash
docker run -d --name smalldns \
  -p 53:5353/udp -p 53:5353/tcp -p 8080:8080 \
  -v smalldns-data:/data \
  ghcr.io/jumoog/small_dns:latest
```

The image is `scratch` plus the static binary and runs as uid 65532, which
cannot bind a low port — so inside the container DNS listens on 5353 and the
host publishes it as 53. Records live in `/data/records.json`; mount something
there to keep them across upgrades.

Flags replace the default command as a whole, so repeat the ones you still
want:

```bash
docker run ... ghcr.io/jumoog/small_dns:latest \
  -dns :5353 -http :8080 -records /data/records.json -upstream 9.9.9.9:53
```

Build it yourself with `docker build -t smalldns .`.

## Tailscale split DNS

The case this was written for: one server that is public *and* runs services
only meant for the tailnet. Public DNS resolves `example.io` to the machine's
public address, but from inside the tailnet you want the same names to land on
its `100.x` address — so internal traffic never leaves the tailnet and the
services can stay bound to the Tailscale interface.

Run smalldns on a tailnet node, bound to that node's tailnet address:

```bash
smalldns -dns 100.101.102.103:53 -http 100.101.102.103:8080
```

Add the names that should resolve internally, e.g. `*.example.io` →
`100.101.102.103`, then in the Tailscale admin console under **DNS →
Nameservers** add a custom nameserver pointing at `100.101.102.103`, tick
**Restrict to domain** and enter `example.io`.

Every tailnet device now sends `example.io` queries to smalldns and everything
else to its usual resolver. Because smalldns forwards names it does not know,
you only need records for the ones you actually want overridden — the rest of
the domain still resolves to its public answers. Devices off the tailnet are
untouched and keep getting the public addresses.

Two things worth knowing: split DNS sends queries to port 53 on the tailnet
address, so the process needs to bind a low port (see above), and the web UI
has no authentication — binding `-http` to the tailnet address keeps it off
the public interface, and a tailnet ACL can narrow it further.

## Records

* Exact names: `home.example.io`
* Wildcards: `*.example.io` matches any name under that suffix
* Both IPv4 (served as `A`) and IPv6 (served as `AAAA`)

Domains are validated on the way in — letters, digits, `-` and `_`, labels of
1 to 63 characters, 253 characters in total — so a record can always be put on
the wire and removed again through the API. A record is only accepted once it
has been written to disk; if that write fails the change is rolled back rather
than living on until the next restart.

An exact record beats a wildcard, and the longest matching wildcard wins, so
`*.dev.example.io` takes precedence over `*.example.io`. Names are matched
case-insensitively. Asking for the family a record does not have (an `AAAA`
query for an IPv4 record) returns `NOERROR` with no answers, which is what a
name that exists without an address of that type is supposed to return.

## HTTP API

| Method | Path | Body / result |
| --- | --- | --- |
| `GET` | `/api/records` | list of `{"domain","ip"}`, sorted by domain |
| `POST` | `/api/records` | `{"domain":"…","ip":"…"}`; adds or replaces, returns the new list |
| `DELETE` | `/api/records/{domain}` | removes one record, returns the new list |

There is no authentication — bind `-http` to a trusted interface.

## How queries are handled

1. Parse the question. Malformed messages get `FORMERR`.
2. `A`/`AAAA` questions in class `IN` that match a record are answered locally
   with `AA` set.
3. Everything else is forwarded to `-upstream` verbatim and the upstream
   response is returned unchanged, so record types this server does not model
   still work. A failed forward becomes `SERVFAIL`.
4. UDP answers are sized to the client's EDNS0 buffer (512 bytes without one,
   capped at 4096), and anything larger is truncated with `TC` so the client
   retries over TCP; a truncated upstream UDP answer is re-fetched over TCP
   first. TCP connections stay open for further queries (RFC 7766).
5. Forwarded responses are accepted only when their transaction ID and question
   match what was sent, so a stale or spoofed datagram cannot become the
   client's answer.

## Tests

```bash
go test ./...
```

Note: Windows `nslookup` cannot query a non-standard port reliably (it ignores
replies that do not come from port 53), so use `dig -p 5354 @127.0.0.1 …` or
point a real resolver at the server when testing on a high port.

## License

[MIT](LICENSE)
