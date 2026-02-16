# Build Stage
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
# Install dependencies
COPY pyproject.toml .
COPY src/ src/
RUN pip install --user --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --user --no-cache-dir .

# Runtime Stage
FROM python:3.12-slim

WORKDIR /app

# Install runtime libs (if any needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r cyanide && useradd -r -g cyanide cyanide

# Copy installed python packages from builder
COPY --from=builder /root/.local /home/cyanide/.local

# Update PATH
ENV PATH=/home/cyanide/.local/bin:$PATH
ENV PYTHONPATH=/app/src:/app

# Copy project files
COPY . .

# Copy healthcheck script
COPY deployments/docker/healthcheck.py /app/docker/healthcheck.py

# Create necessary directories and set ownership
RUN mkdir -p var/log/cyanide/tty var/lib/cyanide/quarantine var/run \
    && chown -R cyanide:cyanide /app/var /app/data

# Switch to non-root user
USER cyanide

# Expose ports
EXPOSE 2222 2223 9090

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 /app/docker/healthcheck.py || exit 1

# Run main.py
CMD ["python3", "src/cyanide/main.py"]