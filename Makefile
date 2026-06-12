# Sighthound Vulnerability Scanner Makefile

.PHONY: build test test-unit test-integration test-all clean install help fmt clippy

# Default target
all: build test

# Build the project
build:
	@echo "Building Sighthound..."
	cargo build --release

# Run all Rust test suites
test-unit:
	@echo "Running Rust tests..."
	cargo test

# Run integration and end-to-end test suites explicitly
test-integration: build
	@echo "Running integration and end-to-end tests..."
	cargo test --test integration_tests
	cargo test --test end_to_end_tests

# Run all tests
test-all: test-unit test-integration

# Alias for test-all
test: test-all

# Format and lint
fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean

# Install binary to system
install: build
	@echo "Installing Sighthound..."
	cargo install --path .

# Show help
help:
	@echo "Sighthound Build System"
	@echo "======================="
	@echo ""
	@echo "Available targets:"
	@echo "  build             - Build the release binary"
	@echo "  test-unit         - Run all Rust test suites"
	@echo "  test-integration  - Run integration and end-to-end tests"
	@echo "  test-all          - Run all tests"
	@echo "  test              - Alias for test-all"
	@echo "  fmt               - Format code with rustfmt"
	@echo "  clippy            - Run clippy with warnings denied"
	@echo "  clean             - Clean build artifacts"
	@echo "  install           - Install binary to system"
	@echo "  help              - Show this help message"
