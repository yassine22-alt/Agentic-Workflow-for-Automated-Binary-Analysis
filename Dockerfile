# Dockerfile
# Agentic Workflow for Automated Binary Analysis (PE & ELF)
#
# Includes:
# - Python 3.11 runtime
# - radare2 (r2), binutils (readelf/objdump/strings), file, upx
# - Minimal runtime deps for CLI/API + MCP tooling
#
# Notes:
# - This is a v1 baseline. You can tighten security later (non-root user, seccomp, etc.)
# - Run with: --network=none (recommended) and mount /samples + /output

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# System deps: analysis tools + build essentials for some python wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    file \
    binutils \
    upx-ucl \
    tini \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG R2_TAG=5.9.8
RUN git clone --depth 1 --branch ${R2_TAG} https://github.com/radareorg/radare2.git /tmp/radare2 \
    && cd /tmp/radare2 \
    && sys/install.sh \
    && r2 -v \
    && rm -rf /tmp/radare2
# Create directories for mounted volumes
RUN mkdir -p /app /samples /output

WORKDIR /app

# Copy dependency files first for better Docker cache utilization
# If you use requirements.txt, keep it at repo root.
COPY requirements.txt /app/requirements.txt

# Install Python deps
RUN python -m pip install --upgrade pip && \
    pip install -r /app/requirements.txt

# Copy project code
COPY . /app

# Basic sanity check that toolchain exists (fails build if missing)
RUN readelf --version | head -n 1 && \
    objdump --version | head -n 1 && \
    file --version | head -n 1 && \
    upx -V | head -n 1

# Run as non-root for security
RUN useradd --no-create-home --shell /bin/false analyst && \
    chown -R analyst:analyst /app /samples /output
USER analyst

EXPOSE 8000

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["bash", "./start.sh"]
