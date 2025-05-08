# Build stage
FROM python:3.13-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Final stage
FROM python:3.13-slim

# Create non-root user
RUN useradd -m appuser

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERT_MONITOR_DATA_DIR=/data \
    FLASK_ENV=production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder stage
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

# Create data directory with proper permissions
RUN mkdir -p /data && chown -R appuser:appuser /data

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && chown -R appuser:appuser /app/logs

# Copy application code
COPY --chown=appuser:appuser . .

# Make scripts executable
RUN chmod +x /app/run.sh /app/init-db.sh

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Use the run script as entrypoint
ENTRYPOINT ["/app/run.sh"]
