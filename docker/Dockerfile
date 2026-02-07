# Build Stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime Stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime libs (if any needed)
# libffi-dev and libssl-dev might be needed for runtime linking of some libs
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

# Create necessary directories and set ownership
# We need write access to var/log/cyanide, var/lib/cyanide, var/run and data/cyanide (for txtcmds/fs.pickle updates if any)
# Note: config is mounted read-only usually, but data might be read-only too. 
# Var is where we write.
RUN mkdir -p var/log/cyanide/tty var/lib/cyanide/quarantine var/run \
    && chown -R cyanide:cyanide /app/var /app/data

# Switch to non-root user
USER cyanide

# Expose ports (High ports for non-root)
EXPOSE 2222 2223 9090

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); result = s.connect_ex(('127.0.0.1', 2222)); exit(result)"

# Run main.py
CMD ["python3", "src/cyanide/main.py"]
