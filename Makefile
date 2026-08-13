BINARY ?= bomly-plugin-osv-matcher

.PHONY: test build

test:
	go test ./...

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)
