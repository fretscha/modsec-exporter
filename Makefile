.PHONY: test lint build smoke run clean

GO ?= go
GOPROXY ?= direct
BIN := bin/modsec-exporter

export GOPROXY
export GOSUMDB=off

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...
	@command -v staticcheck >/dev/null && staticcheck ./... || echo "staticcheck not installed; skipping"

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o $(BIN) ./cmd/modsec-exporter

smoke: build
	$(GO) test -tags=e2e ./...

run: build
	./$(BIN) --replay --access-log test/fixtures/access.log --error-log test/fixtures/error.log --listen 127.0.0.1:9555

clean:
	rm -rf bin
