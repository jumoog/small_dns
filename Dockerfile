# syntax=docker/dockerfile:1

# The builder always runs on the native platform and cross-compiles, so
# multi-arch images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY static ./static

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/smalldns .

# The record file lives on a volume, so /data has to belong to the unprivileged
# user the final image runs as.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM scratch

COPY --from=build /out/smalldns /smalldns
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532
VOLUME /data
# 5353 rather than 53: an unprivileged user cannot bind a low port. Publish it
# as `-p 53:5353/udp -p 53:5353/tcp` on the host.
EXPOSE 5353/udp 5353/tcp 8080/tcp

ENTRYPOINT ["/smalldns"]
CMD ["-dns", ":5353", "-http", ":8080", "-records", "/data/records.json"]
