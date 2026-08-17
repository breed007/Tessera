# Tessera — common developer + release tasks.
VERSION ?= 1.0.1
BUILD ?= $(shell date +%Y.%m.%d.%H.%M)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildNumber=$(BUILD)

.PHONY: build build-pcap test race fmt vet run clean snapshot

build:                ## pure-Go static binary (no packet capture)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o tessera ./cmd/tessera

build-pcap:           ## capture-enabled binary (needs libpcap-dev + cgo)
	CGO_ENABLED=1 go build -tags pcap -ldflags "$(LDFLAGS)" -o tessera ./cmd/tessera

test:                 ## run all tests
	go test ./...

race:                 ## run all tests under the race detector
	go test -race ./...

fmt:
	gofmt -w ./internal ./cmd

vet:
	go vet ./...

run: build            ## build and run with the example config
	./tessera run -config configs/tessera.example.yaml

snapshot:             ## local GoReleaser build (no publish) — produces dist/ incl. .deb/.rpm/.apk
	goreleaser release --snapshot --clean

clean:
	rm -f tessera
	rm -rf dist
