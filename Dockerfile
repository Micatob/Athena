FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    dnsutils \
    netbase \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

COPY . .

RUN addgroup --system --gid 1001 athena && \
    adduser --system --uid 1001 athena --ingroup athena && \
    chown -R athena:athena /app

USER athena

EXPOSE 5000

ENV ATHENA_PROFILE=balanced
ENV ATHENA_STEALTH=true
ENV ATHENA_SAFE_MODE=true
ENV HTTPS_ENABLED=true
ENV REQUIRE_API_KEY=true
ENV LOG_FILE=/app/athena.log
ENV AUDIT_LOG_FILE=/app/athena_audit.log

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

ENTRYPOINT ["python", "athena.py"]
CMD ["--api"]
