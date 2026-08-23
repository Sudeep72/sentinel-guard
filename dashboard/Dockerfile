# SentinelGuard Dashboard — production Dockerfile
#
# NOTE: build context must be the repository root, not dashboard/, since
# this depends on the sibling contracts/ package. docker-compose.yml sets
# `context: .` and `dockerfile: dashboard/Dockerfile` for this service —
# Docker cannot COPY from outside its build context, so this Dockerfile
# cannot be built with `docker build ./dashboard` alone.
FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir hatchling

COPY contracts /build/contracts
RUN pip install --no-cache-dir /build/contracts

COPY dashboard /build/dashboard
WORKDIR /build/dashboard
RUN pip install --no-cache-dir .

# ---- runtime stage ----
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=builder /usr/local/bin/alembic /usr/local/bin/alembic
COPY --from=builder /usr/local/bin/sentinelguard-dashboard /usr/local/bin/sentinelguard-dashboard
COPY --from=builder /usr/local/bin/sentinelguard-mcp /usr/local/bin/sentinelguard-mcp
COPY --from=builder /build/dashboard /app

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
