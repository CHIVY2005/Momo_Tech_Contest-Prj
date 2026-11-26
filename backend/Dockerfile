FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MALLOC_TRIM_THRESHOLD_=65536 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HF_HUB_CACHE=/app/whisper_cache \
    VERISHIELD_WHISPER_MODEL=tiny

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libatomic1 \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /app/requirements.txt && \
    playwright install --with-deps chromium && \
    chmod -R 755 /ms-playwright && \
    mkdir -p /app/whisper_cache && \
    python -c "from faster_whisper import download_model; download_model('tiny', cache_dir='/app/whisper_cache')"

RUN useradd --create-home --uid 10001 verishield && \
    mkdir -p /data && \
    chown -R verishield:verishield /app /data

COPY --chown=verishield:verishield app /app/app

USER verishield
EXPOSE 8000

ENV UVICORN_WORKERS=1
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${UVICORN_WORKERS:-1} --proxy-headers --forwarded-allow-ips=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]
