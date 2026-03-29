FROM python:3.14-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir torch --extra-index-url https://download.pytorch.org/whl/cpu

COPY src/ src/
RUN pip install --no-cache-dir .

RUN find /opt/venv -type d -name "__pycache__" -exec rm -rf {} + \
    && find /opt/venv -name "*.pyc" -delete \
    && find /opt/venv -name "*.so" -exec strip --strip-unneeded {} + 2>/dev/null || true

FROM python:3.14-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    openssh-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY src/cyanide/configs/ configs/
COPY src/cyanide/assets assets/

RUN mkdir -p var/log/cyanide/tty var/log/cyanide/keys var/quarantine var/lib/cyanide \
    && groupadd -r cyanide -g 1000 && useradd -r -u 1000 -g cyanide cyanide \
    && python -c "from cyanide.vfs.profile_loader import load; from pathlib import Path; [load(p.name, p.parent) for p in Path('configs/profiles').iterdir() if p.is_dir()]" \
    && ssh-keygen -t rsa -N "" -f var/log/cyanide/keys/ssh_host_rsa_key \
    && ssh-keygen -t ed25519 -N "" -f var/log/cyanide/keys/ssh_host_ed25519_key \
    && chown -R cyanide:cyanide configs var/log/cyanide var/quarantine var/lib/cyanide

USER cyanide
EXPOSE 2222 2323 2525 9090

ENTRYPOINT ["cyanide"]