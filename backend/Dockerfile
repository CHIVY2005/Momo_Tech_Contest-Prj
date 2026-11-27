FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MALLOC_TRIM_THRESHOLD_=65536 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HF_HUB_CACHE=/app/whisper_cache \
    OCR_MODEL_DIR=/app/ocr_cache \
    VERISHIELD_ALLOW_OCR_DOWNLOAD=0 \
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
    chmod -R 755 /ms-playwright

RUN mkdir -p /app/whisper_cache /app/ocr_cache && \
    python -c "from faster_whisper import download_model; download_model('tiny', cache_dir='/app/whisper_cache')" && \
    python -c "import shutil; from pathlib import Path; import numpy as np; from PIL import Image, ImageDraw; import rapidocr; from rapidocr import EngineType, LangRec, ModelType, OCRVersion, RapidOCR; eng = RapidOCR(params={'Global.use_cls': False, 'Det.engine_type': EngineType.ONNXRUNTIME, 'Det.ocr_version': OCRVersion.PPOCRV5, 'Det.model_type': ModelType.MOBILE, 'Rec.engine_type': EngineType.ONNXRUNTIME, 'Rec.ocr_version': OCRVersion.PPOCRV5, 'Rec.lang_type': LangRec.LATIN, 'Rec.model_type': ModelType.MOBILE, 'EngineConfig.onnxruntime.enable_cpu_mem_arena': False}); img = Image.new('RGB', (320, 80), (255, 255, 255)); ImageDraw.Draw(img).text((20, 28), 'VIETCOMBANK 123456', fill=(0, 0, 0)); res = eng(np.array(img)); assert res.txts, 'OCR warm-up returned empty text'; src = Path(rapidocr.__file__).resolve().parent / 'models'; dst = Path('/app/ocr_cache'); [shutil.copy2(src / n, dst / n) for n in ('ch_PP-OCRv5_det_mobile.onnx', 'latin_PP-OCRv5_rec_mobile.onnx')]; assert all((dst / n).is_file() and (dst / n).stat().st_size > 1_000_000 for n in ('ch_PP-OCRv5_det_mobile.onnx', 'latin_PP-OCRv5_rec_mobile.onnx'))"

RUN useradd --create-home --uid 10001 verishield && \
    mkdir -p /data && \
    chown -R verishield:verishield /app /data

COPY --chown=verishield:verishield app /app/app

USER verishield
EXPOSE 8000

ENV UVICORN_WORKERS=1 \
    UVICORN_FORWARDED_ALLOW_IPS=""
CMD ["sh", "-c", "if [ -n \"${UVICORN_FORWARDED_ALLOW_IPS:-}\" ]; then exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers \"${UVICORN_WORKERS:-1}\" --proxy-headers \"--forwarded-allow-ips=${UVICORN_FORWARDED_ALLOW_IPS}\"; else exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers \"${UVICORN_WORKERS:-1}\" --no-proxy-headers; fi"]
