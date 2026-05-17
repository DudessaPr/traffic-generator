BINARY   := tgen
CMD      := ./cmd/tgen
BUILD    := build
GOFLAGS  := -trimpath

.PHONY: all build test bench lint clean tidy run-inspect run-sessions

all: build

## build: compile the tgen binary into ./build/
build:
	@mkdir -p $(BUILD)
	CGO_ENABLED=1 go build $(GOFLAGS) -o $(BUILD)/$(BINARY) $(CMD)
	@echo "Built $(BUILD)/$(BINARY)"

## test: run all unit and integration tests
test:
	go test ./... -v -count=1

## test-short: run only unit tests (no PCAP integration tests)
test-short:
	go test ./... -short -count=1

## bench: run all benchmarks and report speed, allocs, and custom metrics
bench:
	go test ./... -run='^$$' -bench=. -benchmem -benchtime=3s

## lint: run golangci-lint (install separately if needed)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || \
		{ echo "golangci-lint not found; install from https://golangci-lint.run"; exit 1; }
	golangci-lint run ./...

## tidy: update go.sum and tidy module graph
tidy:
	go mod tidy

## run-inspect: inspect the bundled traffic.pcap
run-inspect: build
	$(BUILD)/$(BINARY) inspect traffic.pcap

## run-sessions: list all sessions in traffic.pcap
run-sessions: build
	$(BUILD)/$(BINARY) sessions -v traffic.pcap

## run-sessions-filter: show only TCP sessions longer than 100ms
run-sessions-filter: build
	$(BUILD)/$(BINARY) sessions --proto tcp --min-duration 100ms -v traffic.pcap

## clean: remove build artefacts
clean:
	@rm -rf $(BUILD)

help:
	@grep -E '^## ' Makefile | sed 's/## //'
