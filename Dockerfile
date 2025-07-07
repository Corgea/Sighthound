# Multi-stage Dockerfile for building find_vulns binary
# Stage 1: Build the binary
FROM rust:1.80-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Remove Cargo.lock to avoid version conflicts in container
RUN rm -f Cargo.lock

# Build the release binary
RUN cargo build --release

# Export stage - minimal image with just the binary and required files
FROM scratch AS export
COPY --from=builder /app/target/release/find_vulns /find_vulns
COPY --from=builder /app/rules /rules
