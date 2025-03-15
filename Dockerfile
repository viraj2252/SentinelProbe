FROM python:3.10-slim as base

# Set environment variables
ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1

WORKDIR /app

# Install poetry and dependencies
FROM base as builder
RUN pip install "poetry==$POETRY_VERSION"
COPY pyproject.toml poetry.lock* /app/
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-dev

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