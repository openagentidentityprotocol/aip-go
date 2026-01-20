# AIP Proxy - Build System
#
# Usage:
#   make build       - Build the aip binary
#   make test        - Run all unit tests
#   make clean       - Remove build artifacts and logs
#   make run-demo    - Run proxy in monitor mode with echo target
#   make lint        - Run go vet and formatting check
#   make help        - Show this help message

.PHONY: build test clean run-demo lint help

# Build configuration
BINARY_NAME := aip
BINARY_DIR := bin
MAIN_PATH := ./cmd/aip-proxy
GO := go

# Default target
all: build

## build: Compile the aip binary to bin/
build:
	@mkdir -p $(BINARY_DIR)
	$(GO) build -o $(BINARY_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Built: $(BINARY_DIR)/$(BINARY_NAME)"

## test: Run all unit tests with verbose output
test:
	$(GO) test -v ./...

## test-coverage: Run tests with coverage report
test-coverage:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## clean: Remove build artifacts, logs, and coverage files
clean:
	rm -rf $(BINARY_DIR)
	rm -f aip-audit.jsonl
	rm -f coverage.out coverage.html
	@echo "Cleaned build artifacts and logs"

## run-demo: Run the proxy in monitor mode with a simple target
run-demo: build
	@echo "Running AIP proxy in monitor mode..."
	@echo "Target: 'echo Hello from MCP server'"
	@echo "Policy: examples/monitor-mode.yaml"
	@echo "---"
	$(BINARY_DIR)/$(BINARY_NAME) \
		--policy examples/monitor-mode.yaml \
		--target "echo Hello from MCP server" \
		--verbose

## run-interactive: Run with Python echo server for interactive testing
run-interactive: build
	@echo "Starting interactive test with Python echo server..."
	$(BINARY_DIR)/$(BINARY_NAME) \
		--policy test/agent.yaml \
		--target "python3 test/echo_server.py" \
		--verbose

## lint: Run go vet and check formatting
lint:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Run 'gofmt -w .' to fix formatting" && exit 1)
	@echo "Lint passed"

## fmt: Format all Go files
fmt:
	$(GO) fmt ./...

## generate-config: Generate Cursor MCP configuration
generate-config: build
	@echo "Generate Cursor config with:"
	@echo "  $(BINARY_DIR)/$(BINARY_NAME) --generate-cursor-config --policy <your-policy.yaml>"

## help: Show this help message
help:
	@echo "AIP Proxy - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
