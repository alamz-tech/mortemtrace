# Serves either Cloud Run service from one image - api.ingest:app or
# console.ui:app, selected at runtime via the APP_MODULE env var (see
# infra/deploy.sh). This sidesteps gcloud's buildpacks path entirely
# (an older gcloud SDK's buildpacks flow was failing on an unrelated
# internal Google config lookup, not a problem with this project), and
# is more explicit and reviewable for a hackathon submission than
# relying on buildpack auto-detection either way.
FROM python:3.11-slim

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir .

ENV PORT=8080
CMD ["sh", "-c", "uvicorn ${APP_MODULE:-api.ingest:app} --host 0.0.0.0 --port ${PORT}"]
