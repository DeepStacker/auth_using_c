# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libulfius-dev \
    libjansson-dev \
    libjwt-dev \
    libsqlite3-dev \
    libgnutls28-dev \
    liborcania-dev \
    libyder-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /app
COPY auth_service.c /app/

# Compile the application
RUN gcc -o auth-service auth_service.c \
    -lulfius \
    -ljansson \
    -ljwt \
    -lsqlite3 \
    -lgnutls \
    -lorcania \
    -lyder \
    -pthread \
    -lcrypt

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libulfius2.7 \
    libjansson4 \
    libjwt0 \
    libsqlite3-0 \
    libgnutls30 \
    liborcania2.2 \
    libyder2.0 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash appuser && \
    mkdir -p /app/data && \
    chown appuser:appuser /app/data

# Copy compiled binary
WORKDIR /app
COPY --from=builder /app/auth-service /app/

# Switch to non-root user
USER appuser

# Set environment variables
ENV AUTH_PORT=8080
ENV AUTH_DB_PATH=/app/data/auth.db

# Expose port
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["./auth-service"]