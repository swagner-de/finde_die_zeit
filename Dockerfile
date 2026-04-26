FROM debian:13-slim AS build
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes python3-venv gcc libpython3-dev && \
    python3 -m venv /venv && \
    /venv/bin/pip install --upgrade pip setuptools wheel

FROM build AS build-venv
COPY pyproject.toml finde_die_zeit.py /app/
RUN /venv/bin/pip install --disable-pip-version-check /app

FROM gcr.io/distroless/python3-debian13
COPY --from=build-venv /venv /venv
ENTRYPOINT ["/venv/bin/finde-die-zeit"]
