FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS build
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes python3-venv gcc libpython3-dev && \
    python3 -m venv /venv && \
    /venv/bin/pip install --upgrade pip setuptools wheel

FROM build AS build-venv
COPY pyproject.toml finde_die_zeit.py /app/
RUN /venv/bin/pip install --disable-pip-version-check /app && \
    /venv/bin/pip uninstall --yes pip setuptools wheel

FROM gcr.io/distroless/python3-debian13@sha256:0db804f397ca31a1498c9d94c3c1df53fe49ac8007e5942b1cb547c1c3355c09
COPY --from=build-venv /venv /venv
ENTRYPOINT ["/venv/bin/finde-die-zeit"]
