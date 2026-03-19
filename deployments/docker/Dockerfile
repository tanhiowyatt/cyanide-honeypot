# Build Stage
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip setuptools>=78.1.1

COPY pyproject.toml README.md ./
RUN mkdir -p src/cyanide && touch src/cyanide/__init__.py

# Install dependencies and clean in one layer
RUN pip install --user --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --user --no-cache-dir . \
    && find /root/.local -name "*.pyc" -delete \
    && find /root/.local -name "__pycache__" -type d -exec rm -rf {} + \
    && rm -rf /root/.cache/pip

# Runtime Stage
FROM python:3.12-slim

WORKDIR /app

# Copy only necessary Python packages
COPY --from=builder /root/.local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /root/.local/bin /usr/local/bin

# Copy source code
COPY assets assets
COPY configs configs
COPY src/cyanide src/cyanide
COPY deployments/docker/healthcheck.py /app/docker/healthcheck.py

# Create user and directories
RUN groupadd -r cyanide && useradd -r -g cyanide cyanide \
    && mkdir -p var/log/cyanide/tty var/quarantine var/lib/cyanide/run \
    && chown -R cyanide:cyanide /app/var /app/configs/profiles

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER cyanide

EXPOSE 2222 2223 9090 2525

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 /app/docker/healthcheck.py || exit 1

CMD ["python3", "src/cyanide/main.py"]