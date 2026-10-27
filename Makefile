BINARY  := 0800
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test race lint fmt vet shots clean integration

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./... -count=1

race:
	go test -race ./... -count=1

fmt:
	gofmt -w .

lint: fmt
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted: $$out"; exit 1; fi
	go vet ./...

vet:
	go vet ./...

shots:
	go run ./tools/screenshot -view main    -w 128 -h 40 -o docs/screenshots/main.svg
	go run ./tools/screenshot -view browser -w 128 -h 40 -o docs/screenshots/browser.svg
	go run ./tools/screenshot -view details -w 128 -h 40 -o docs/screenshots/details.svg
	go run ./tools/screenshot -view help    -w 128 -h 40 -o docs/screenshots/help.svg
	go run ./tools/screenshot -view summary -w 128 -h 40 -o docs/screenshots/summary.svg
	go run ./tools/screenshot -view setup   -w 100 -h 30 -o docs/screenshots/setup.svg

integration:
	go test -tags integration ./internal/integration -v

clean:
	rm -rf $(BINARY) dist 0800-loot
