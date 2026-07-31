# Sighthound Vulnerability Scanner Makefile

.PHONY: all build test test-unit test-all clean install help tools

# Default target
all: build test

# Build the project
build:
	@echo "🔨 Building Sighthound..."
	cargo build --release

# Run the Rust test suite via cargo test (blocking CI gate)
test-unit:
	@echo "🦀 Running Rust tests..."
	cargo test

# Run all tests (cargo test runs unit + integration + end_to_end harnesses)
test-all: test-unit

# Canonical test entry point
test: test-all

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	rm -rf target/

# Install binary to system
install: build
	@echo "📦 Installing Sighthound..."
	cargo install --path .

# Install the cargo tools `make ci` uses (same set CI installs)
tools:
	@echo "🧰 Installing CI tools..."
	rustup component add llvm-tools-preview
	cargo install cargo-audit cargo-llvm-cov cargo-modules

# Show help
help:
	@echo "Sighthound Vulnerability Scanner Build System"
	@echo "============================================="
	@echo ""
	@echo "Available targets:"
	@echo "  build       - Build the release binary"
	@echo "  test        - Run cargo test (unit + integration + end_to_end)"
	@echo "  test-unit   - Run cargo test"
	@echo "  test-all    - Run cargo test"
	@echo "  ci          - Full CI pipeline — run before every PR"
	@echo "  bootstrap   - Install git pre-commit + pre-push hooks"
	@echo "  tools       - Install the cargo tools CI uses"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install binary to system"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Quick commands:"
	@echo "  make              - Build and run all tests"
	@echo "  make build        - Just build the binary"
	@echo "  make test         - Run all tests"

# ── Quality harness (delegates to the `cargo harness` runner in harness.rs) ──
HARNESS := cargo harness
HARNESS_TARGETS := check fix lint pre-commit pre-push ci audit post-edit \
	stop-hook complexity coverage crap mutation acceptance arch \
	agents-md-drift sync-agents-md setup-hooks

.PHONY: bootstrap $(HARNESS_TARGETS)
bootstrap: setup-hooks
$(HARNESS_TARGETS):
	$(HARNESS) $@

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
