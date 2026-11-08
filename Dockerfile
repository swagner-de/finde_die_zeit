FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS build
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
