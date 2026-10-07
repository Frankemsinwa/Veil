# Multi-stage production container for Veil Gateway
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app/ ./app/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Production Runner Stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Security: Non-root runtime user
RUN groupadd -g 10001 veilgroup && \
    useradd -u 10001 -g veilgroup -m -s /bin/bash veiluser

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/veil /usr/local/bin/veil
COPY --from=builder /build/app /app/app
COPY pyproject.toml README.md /app/

# Create protected data directory for audit ledger & session vaults
RUN mkdir -p /home/veiluser/.veil && \
    chown -R veiluser:veilgroup /home/veiluser/.veil /app

USER veiluser

ENV VEIL_HOST=0.0.0.0
ENV VEIL_PORT=8080
ENV VEIL_POLICY=STRICT
ENV VEIL_DATA_DIR=/home/veiluser/.veil

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

ENTRYPOINT ["veil", "start", "--host", "0.0.0.0", "--port", "8080"]
