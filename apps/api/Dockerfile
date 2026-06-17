# RedCalibur API — FastAPI + SQLite, local-first and offline.
FROM python:3.13-slim

WORKDIR /app

# Install the API package and its runtime deps.
COPY apps/api/pyproject.toml /app/apps/api/pyproject.toml
COPY apps/api/redcalibur_api /app/apps/api/redcalibur_api
RUN python -m pip install --upgrade pip && python -m pip install -e /app/apps/api

# Persisted, project-local data directory (DB + run artifacts).
ENV REDCALIBUR_DATA_DIR=/data
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "redcalibur_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
