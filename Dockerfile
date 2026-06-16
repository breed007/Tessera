# Tessera — pure-Go static build on distroless (no shell, runs as nonroot).
# The passive sensor needs libpcap (-tags pcap) and is NOT in this image; the
# UniFi poller, active prober, reconciler, and UI all work here.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" \
		-o /out/usr/bin/tessera ./cmd/tessera \
 && mkdir -p /out/etc/tessera /out/var/lib/tessera \
 && cp configs/tessera.example.yaml /out/etc/tessera/config.yaml

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build --chown=nonroot:nonroot /out /
VOLUME /var/lib/tessera
EXPOSE 10404
USER nonroot
ENTRYPOINT ["/usr/bin/tessera"]
CMD ["run", "-config", "/etc/tessera/config.yaml"]
