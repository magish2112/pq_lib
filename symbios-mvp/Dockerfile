# Build stage
FROM rust:1.75-slim AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=builder /app/target/release/symbios-mvp /app/symbios-mvp

# Create data directory
RUN mkdir -p /app/data

# Expose ports
EXPOSE 9001-9104

# Set the binary as entrypoint
ENTRYPOINT ["/app/symbios-mvp"]

