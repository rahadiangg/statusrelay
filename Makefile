# statwatch build pipeline.
#
# `make build` is pure Go: no Node, no codegen, no staging step, so a clean
# checkout builds with the Go toolchain alone and `go install` works.
# Releases are cut by GoReleaser from a v* tag (see .goreleaser.yaml); `make
# snapshot` runs the same pipeline locally without publishing.

BINARY  := statwatch
CTL     := statwatchctl
PKG     := ./cmd/statwatch
CTLPKG  := ./cmd/statwatchctl
# Leading v stripped to match GoReleaser's {{ .Version }}, so a local build
# and a released one print the same shape.
LDFLAGS := -s -w -X main.version=$(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo none)
GOFLAGS := CGO_ENABLED=0

.PHONY: all build run test test-live cover cover-check lint fmt vet tidy snapshot clean

all: build

## build: compile both binaries
build:
	$(GOFLAGS) go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) $(PKG)
	$(GOFLAGS) go build -trimpath -ldflags="$(LDFLAGS)" -o $(CTL) $(CTLPKG)

## run: build then run the daemon
run: build
	./$(BINARY)

## test: the full hermetic suite. No network, no sleeps.
##
## -count=1 is not incidental: a cached pass says nothing about whether the
## fixtures on disk are still the ones the tests claim to read.
test:
	go vet ./...
	go test ./... -race -count=1

## test-live: hit the REAL upstream and assert the schema has not drifted.
## Excluded from `make test` on purpose; run it deliberately or nightly in CI.
test-live:
	go test -tags live -count=1 -v ./internal/incident/canary/

## cover: coverage profile and per-package summary
cover:
	go test ./... -race -count=1 -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out | tail -1

## cover-check: fail below the project floor
cover-check: cover
	@total=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | tr -d '%'); \
	echo "total coverage: $$total%"; \
	awk -v t="$$total" 'BEGIN { if (t+0 < 85.0) { print "FAIL: coverage below 85%"; exit 1 } }'

## lint: golangci-lint (install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.1)
lint:
	golangci-lint run

## fmt: format everything
fmt:
	gofmt -w cmd internal

## vet: static analysis
vet:
	go vet ./...

## tidy: sync go.mod/go.sum
tidy:
	go mod tidy

## snapshot: the full release pipeline (all archives + local container
## images) without a tag and without publishing. Needs goreleaser and docker.
snapshot:
	goreleaser release --snapshot --clean

## clean: remove build artifacts
clean:
	rm -rf $(BINARY) $(CTL) coverage.out dist
