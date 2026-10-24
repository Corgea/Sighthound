# Multi-stage Dockerfile for building sighthound binary
# Stage 1: Build the binary
FROM rust:1.89-slim@sha256:8cffb8fe4e8a95cf0d6a2060375e5a28aff4c752155aa9f1f9193530769bdf66 AS builder

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

# Set build-time environment variables
ARG GIT_HASH
ARG BUILD_DATE
ENV GIT_HASH=${GIT_HASH}
ENV BUILD_DATE=${BUILD_DATE}

# Build the release binary
ENV CARGO_TARGET_DIR=/app/target
RUN cargo build --release --locked --bin sighthound

# Runtime stage - minimal image for running the container
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
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
