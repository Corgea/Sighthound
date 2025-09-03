# Multi-stage Dockerfile for building sighthound binary
# Stage 1: Build the binary
FROM rust:1.89-slim AS builder

# Install build dependencies including cross-compilation tools
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc-x86-64-linux-gnu \
    gcc-aarch64-linux-gnu \
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
ENV GIT_HASH=${GIT_HASH}
ENV BUILD_DATE=${BUILD_DATE}

# Build the release binary
ENV CARGO_TARGET_DIR=/app/target
RUN cargo build --release

# Runtime stage - minimal image for running the container
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sighthound /usr/local/bin/sighthound
COPY --from=builder /app/rules /rules
ENTRYPOINT ["/usr/local/bin/sighthound"]

# Export stage - minimal stage with just the binary and required files
FROM scratch AS export
COPY --from=builder /app/target/release/sighthound /sighthound
COPY --from=builder /app/rules /rules
