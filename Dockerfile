FROM python:3.10-slim AS base

# Set environment variables
ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1

# Allow overriding pip index URL at build time (fallback to classic domain per suggestion)
ARG PIP_INDEX_URL=https://pypi.python.org/simple
ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV PIP_INDEX_URL=${PIP_INDEX_URL}
ENV POETRY_PYPI_URL=${PIP_INDEX_URL}
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV http_proxy=${HTTP_PROXY}
ENV https_proxy=${HTTPS_PROXY}
ENV PIP_TRUSTED_HOST="pypi.org pypi.python.org files.pythonhosted.org"

WORKDIR /app

# Ensure CA certificates are installed for SSL (required for pip to access PyPI)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Optional corporate CA support via inline build arg
ARG CUSTOM_CA
RUN if [ -n "$CUSTOM_CA" ]; then \
      printf "%s" "$CUSTOM_CA" > /usr/local/share/ca-certificates/custom-ca.crt && \
      update-ca-certificates || true; \
    fi

# Install poetry and dependencies
FROM base AS builder
COPY requirements.txt /app/
RUN pip install --no-cache-dir --index-url "$PIP_INDEX_URL" \
    --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org \
    -r requirements.txt

# Final image
FROM base

# Install required system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copy installed dependencies from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . /app/

# Create a non-root user to run the application
RUN useradd -m sentinelprobe && \
    chown -R sentinelprobe:sentinelprobe /app
USER sentinelprobe

# Create logs directory
RUN mkdir -p /app/logs && \
    chmod 755 /app/logs

# Expose the application port
EXPOSE 8000

# Set the entrypoint
CMD ["python", "-m", "sentinelprobe"]
