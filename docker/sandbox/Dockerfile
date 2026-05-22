FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y strace && \
    rm -rf /var/lib/apt/lists/*

# Use a non-root user for extra safety, though read-only root is also okay
# But wait, pip install needs a writable home or cache. Let's configure pip to use /tmp/install for cache if needed, or disable cache.
ENV PIP_NO_CACHE_DIR=1

# Ensure /tmp/install is used for temp files by pip and python
ENV TMPDIR=/tmp/install

WORKDIR /tmp/install
