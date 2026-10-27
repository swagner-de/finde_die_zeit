FROM debian:13-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS build
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
