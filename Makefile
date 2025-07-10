# Greppy Vulnerability Scanner Makefile

.PHONY: build test test-unit test-integration test-all clean install help

# Default target
all: build test

# Build the project
build:
	@echo "🔨 Building Greppy..."
	cargo build --release

# Run only Rust unit tests
test-unit:
	@echo "🦀 Running Rust unit tests..."
	cargo test

# Run integration tests with the unified test suite
test-integration: build
	@echo "🧪 Running integration tests..."
	./test_data/run_tests.sh

# Run all tests (unit + integration)
test-all: test-unit test-integration

# Alias for test-all
test: test-all

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	rm -rf target/

# Install binary to system
install: build
	@echo "📦 Installing Greppy..."
	cargo install --path .

# Show help
help:
	@echo "Greppy Vulnerability Scanner Build System"
	@echo "========================================"
	@echo ""
	@echo "Available targets:"
	@echo "  build             - Build the release binary"
	@echo "  test-unit         - Run Rust unit tests only"
	@echo "  test-integration  - Run integration tests with unified test suite"
	@echo "  test-all          - Run all tests (unit + integration)"
	@echo "  test              - Alias for test-all"
	@echo "  clean             - Clean build artifacts"
	@echo "  install           - Install binary to system"
	@echo "  help              - Show this help message"
	@echo ""
	@echo "Quick commands:"
	@echo "  make              - Build and run all tests"
	@echo "  make build        - Just build the binary"
	@echo "  make test         - Run all tests"

# Development shortcuts
dev-django:
	@echo "🐍 Testing Django rules..."
	./target/release/sighthound test_data/python/django python rules/python/django/ --threads 1

dev-general:
	@echo "🐍 Testing general Python rules..."
	./target/release/sighthound test_data/python/general python rules/python/python/general.ron --threads 1

dev-malicious:
	@echo "🕵️ Testing malicious pattern detection..."
	./target/release/sighthound test_data/python/malicious python rules/python/malicious/ --threads 1

# Performance testing
perf-test: build
	@echo "⚡ Running performance tests..."
	@echo "Testing parser pooling with 8 threads..."
	time ./target/release/sighthound test_data/python python rules/python/python/general.ron --threads 8
	@echo "Testing single-threaded performance..."
	time ./target/release/sighthound test_data/python python rules/python/python/general.ron --threads 1 