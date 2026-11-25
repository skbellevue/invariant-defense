FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="invariant-defense" \
      org.opencontainers.image.description="Reference implementation of the Invariant Defense Model for AI-enabled malware" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/invariant

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY rules ./rules
COPY config ./config

RUN pip install --no-cache-dir ".[yara]" \
 && useradd --system --uid 10001 invariant \
 && mkdir -p /data && chown invariant /data

USER invariant
WORKDIR /data
ENTRYPOINT ["invariant"]
CMD ["demo"]
