# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

RUN pip install --no-cache-dir torch --extra-index-url https://download.pytorch.org/whl/cpu # nosemgrep: dockerfile.audit.dockerfile-pip-extra-index-url.dockerfile-pip-extra-index-url

COPY pyproject.toml README.md ./
COPY src/ src/
# Use --extra-index-url for PyTorch (nosemgrep: dockerfile.audit.dockerfile-pip-extra-index-url.dockerfile-pip-extra-index-url)
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels --extra-index-url https://download.pytorch.org/whl/cpu . # nosemgrep: dockerfile.audit.dockerfile-pip-extra-index-url.dockerfile-pip-extra-index-url

# Final stage
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Pre-install CPU-only torch (nosemgrep: dockerfile.audit.dockerfile-pip-extra-index-url.dockerfile-pip-extra-index-url)
RUN pip install --no-cache-dir torch --extra-index-url https://download.pytorch.org/whl/cpu # nosemgrep: dockerfile.audit.dockerfile-pip-extra-index-url.dockerfile-pip-extra-index-url

# Copy wheels and install
COPY --from=builder /app/wheels /tmp/wheels
RUN pip install --no-cache-dir /tmp/wheels/*.whl && rm -rf /tmp/wheels

# Configuration and data setup
COPY src/cyanide/configs/ configs/

RUN mkdir -p var/log/cyanide/tty var/quarantine var/lib/cyanide \
    && groupadd -r cyanide && useradd -r -g cyanide cyanide \
    && chown -R cyanide:cyanide var/log/cyanide var/quarantine var/lib/cyanide

USER cyanide
EXPOSE 2222 2323 2525 9090

ENTRYPOINT ["cyanide"]
