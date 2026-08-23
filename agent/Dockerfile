# SentinelGuard Linux Agent — Dockerfile
#
# The agent typically runs directly on monitored hosts (not
# containerized) since most Guardian checks need host-level filesystem
# access (permissions, SSH config, sudoers, etc.) that a container
# namespace does not have unless the host filesystem is explicitly
# bind-mounted in. This image is for local development, CI, and
# scanning a mounted host filesystem — not production agent deployment.
#
# NOTE: build context must be the repository root (see docker-compose.yml
# `context: .`, `dockerfile: agent/Dockerfile`), since this depends on
# the sibling contracts/ package.
FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir hatchling

COPY contracts /build/contracts
RUN pip install --no-cache-dir /build/contracts

COPY agent /build/agent
WORKDIR /build/agent
RUN pip install --no-cache-dir .

# ---- runtime stage ----
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin/sentinelguard-agent /usr/local/bin/sentinelguard-agent

ENTRYPOINT ["sentinelguard-agent"]
CMD ["scan"]
