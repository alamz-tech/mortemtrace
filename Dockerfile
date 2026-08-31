# Serves either Cloud Run service from one image - api.ingest:app or
# console.ui:app, selected at runtime via the APP_MODULE env var (see
# infra/deploy.sh). This sidesteps gcloud's buildpacks path entirely
# (an older gcloud SDK's buildpacks flow was failing on an unrelated
# internal Google config lookup, not a problem with this project), and
# is more explicit and reviewable than relying on buildpack
# auto-detection either way.
#
# Two-stage: dependencies are installed into a virtualenv in the builder,
# then only the venv and application code are copied into the runtime
# image. Build tooling (pip's caches, compilers pulled in by any wheel
# that needs building) does not ship to production.

# ---- builder -----------------------------------------------------------
# Pinned by digest, not just tag. `python:3.11-slim` is mutable: the same
# Dockerfile built a month apart can produce different base layers with
# different CVEs, which makes a build non-reproducible and an image
# non-auditable. Refresh deliberately (docker pull + update the digest)
# rather than implicitly on every build.
FROM python:3.11-slim@sha256:be1575ed968de893bd54f4c56315ff7c4736ce522c1bca08fd521731aafc0d76 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Dependency metadata first so the (slow) install layer is cached and only
# re-runs when dependencies actually change, not on every source edit.
COPY pyproject.toml constraints.txt ./
COPY README.md ./
# Constraints pin every transitive dependency to the exact versions this
# was tested against. pyproject declares compatible *ranges*; without a
# lockfile two builds a week apart silently resolve different versions.
# That is not hypothetical here - an ADK minor release changed exception
# propagation behaviour this codebase depends on.
RUN pip install --no-cache-dir -c constraints.txt .

# ---- runtime -----------------------------------------------------------
FROM python:3.11-slim@sha256:be1575ed968de893bd54f4c56315ff7c4736ce522c1bca08fd521731aafc0d76

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8080

# Non-root. The previous image ran as root, so any RCE in a dependency
# started with full container privileges; this costs nothing and removes
# that step from an attacker's path.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin mortemtrace

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=mortemtrace:mortemtrace . .

USER mortemtrace

EXPOSE 8080

# exec form via `sh -c` is required because ${APP_MODULE}/${PORT} must be
# expanded at runtime - the image serves two different apps.
CMD ["sh", "-c", "exec uvicorn ${APP_MODULE:-api.ingest:app} --host 0.0.0.0 --port ${PORT}"]
