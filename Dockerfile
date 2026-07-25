# Backend image — used for BOTH the FastAPI API and the Celery worker
# (they share the same code; docker-compose overrides the command for the worker).
FROM python:3.11-slim

# System deps: build-essential for any packages without wheels; libgomp1 is required
# by onnxruntime (the local embedding model); curl for the healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so this layer is cached across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

EXPOSE 8000

# Default command = API. The worker service overrides this in docker-compose.yml.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
