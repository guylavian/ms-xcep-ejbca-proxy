# MS-XCEP/WSTEP to EJBCA Proxy Server
#
# Multi-stage build for a production-ready container

# Build stage
FROM python:3.12-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libkrb5-dev \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# Production stage
FROM python:3.12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libkrb5-3 \
    libldap-2.5-0 \
    libsasl2-2 \
    libssl3 \
    krb5-user \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false xcepproxy

WORKDIR /app

# Copy wheels from builder and install
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create directories for certificates
RUN mkdir -p /etc/proxy && chown xcepproxy:xcepproxy /etc/proxy

# Set environment variables
ENV PYTHONPATH=/app
ENV XCEP_CONFIG=/app/config/config.yaml

# Switch to non-root user
USER xcepproxy

# Expose HTTPS port
EXPOSE 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f -k https://localhost:443/health || exit 1

# Run with gunicorn
CMD ["gunicorn", \
    "--bind", "0.0.0.0:443", \
    "--workers", "4", \
    "--threads", "2", \
    "--worker-class", "gthread", \
    "--timeout", "30", \
    "--keyfile", "/etc/proxy/server.key", \
    "--certfile", "/etc/proxy/server.crt", \
    "--access-logfile", "-", \
    "--error-logfile", "-", \
    "--capture-output", \
    "src.main:create_wsgi_app()"]
