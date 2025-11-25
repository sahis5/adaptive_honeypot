# backend/Dockerfile (production)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# copy requirements first (cacheable)
COPY backend/requirements.txt /app/backend/requirements.txt
RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install -r /app/backend/requirements.txt

# copy app code
COPY backend /app/backend

# create dirs and non-root user
RUN mkdir -p /var/log/adaptive && useradd -ms /bin/bash appuser && chown -R appuser:appuser /app /var/log/adaptive
USER appuser

ENV PYTHONPATH=/app

# run Gunicorn
CMD ["gunicorn", "-c", "backend/gunicorn_conf.py", "backend.app:app"]
