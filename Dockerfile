FROM python:3.13-slim AS builder

WORKDIR /build
RUN python -m pip install --no-cache-dir build==1.3.0
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 signalforge \
    && useradd --uid 10001 --gid signalforge --no-create-home signalforge
WORKDIR /workspace
COPY --from=builder /build/dist /tmp/dist
RUN python -m pip install --no-cache-dir /tmp/dist/*.whl \
    && rm -r /tmp/dist
COPY --chown=signalforge:signalforge rules ./rules
COPY --chown=signalforge:signalforge scenarios ./scenarios
RUN mkdir reports && chown signalforge:signalforge reports

USER 10001:10001
ENTRYPOINT ["signalforge"]
CMD ["replay", "scenarios", "--rules", "rules"]
