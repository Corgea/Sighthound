# Multi-stage Dockerfile for building sighthound binary
# Stage 1: Build the binary
FROM rust:1.89-slim AS builder

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

# Set build-time environment variables
ARG GIT_HASH
ARG BUILD_DATE
ARG TARGETPLATFORM
ENV GIT_HASH=${GIT_HASH}
ENV BUILD_DATE=${BUILD_DATE}

# Configure Rust for the target platform
# Use native compilation (no cross-compilation) - Docker buildx handles platform selection
ENV CARGO_TARGET_DIR=/app/target

# Build the release binary
# Use CARGO_BUILD_RUSTFLAGS to apply target-cpu=generic only to final artifacts, not build scripts
# This prevents SIGILL errors in Docker buildx emulated environments
ENV CARGO_BUILD_RUSTFLAGS="-C target-cpu=generic"
RUN cargo build --release

# Runtime stage - minimal image for running the container
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sighthound /usr/local/bin/sighthound
COPY --from=builder /app/rules /rules
# BSD-2-Clause (Oniguruma, statically linked) requires the notice to accompany
# binary redistributions. /licenses is the OCI convention.
COPY --from=builder /app/LICENSE /app/THIRD-PARTY-NOTICES.md /licenses/
ENTRYPOINT ["/usr/local/bin/sighthound"]

# Export stage - minimal stage with just the binary and required files
FROM scratch AS export
COPY --from=builder /app/target/release/sighthound /sighthound
COPY --from=builder /app/rules /rules
COPY --from=builder /app/LICENSE /LICENSE
COPY --from=builder /app/THIRD-PARTY-NOTICES.md /THIRD-PARTY-NOTICES.md
