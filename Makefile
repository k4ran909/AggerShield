# AggerShield build / distribution.
#
#   make build      # build agent + server for this machine into ./bin
#   make test       # go test (race detector)
#   make release    # cross-compile distributable binaries into ./dist
#   make clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.agentVersion=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build test vet fmt clean release

all: vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# Cross-compile agent + control plane for every target platform into ./dist.
# These are the binaries you hand to users (agent) and run yourself (server).
release:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=""; \
	  if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
	  echo "building $$os/$$arch"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
	    -o dist/aggershield_$${os}_$${arch}$$ext ./cmd/aggershield; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
	    -o dist/aggershield-server_$${os}_$${arch}$$ext ./cmd/aggershield-server; \
	done
	@echo "done -> ./dist"

clean:
	rm -rf bin dist
