# ADR-001: Modular OCR Provider Architecture & Production Engine Selection

- **Status:** Accepted
- **Date:** 2026-11-26
- **Deciders:** VeriShield AI Engineering
- **Related Documents:**
  - Design Spec: [`docs/superpowers/specs/2026-11-26-unified-multimodal-ocr-design.md`](../superpowers/specs/2026-11-26-unified-multimodal-ocr-design.md)
  - Empirical Benchmark: [`OCR_BENCHMARK.md`](../../OCR_BENCHMARK.md) (`evaluation/ocr_benchmark/results.json`)
  - Engineering Constitution: [`AGENTS.md`](../../AGENTS.md)

---

## 1. Context & Problem Statement

VeriShield AI processes user-submitted Vietnamese screenshots (chat/SMS messages, banking transfer receipts, VietQR codes, dark-mode screens, and Zalo-recompressed low-quality images) as part of its 3-tier anti-scam pipeline alongside ELA/EXIF/dHash forensics, OpenCV QR decoding, `multilingual-e5-small` INT8 ONNX classification, and Gemini multimodal reasoning.

During our Architecture Audit, we identified three concrete constraints:

1. **Broken Vietnamese diacritics in existing OCR:** `backend/app/services/local_ocr.py` previously depended on legacy `rapidocr-onnxruntime==1.4.4`, which bundled Chinese recognition weights (`ch_PP-OCRv4_rec_infer.onnx`). Vietnamese diacritics were systematically stripped or misrecognized (`CER = 0.2243`, `WER = 0.9222`, `Entity F1 = 0.7158`), and the module lacked a provider abstraction, timeout, or concurrency semaphore.
2. **Strict production VPS resource limits (`docker-compose.prod.yml`):** Production runs on a 4 GB RAM VPS with the `backend` container constrained to **`mem_limit: 2200m`**, **`cpus: 1.5`**, `pids_limit: 256`, and `UVICORN_WORKERS=1`. Inside that 2200 MB envelope, the backend already hosts FastAPI, `scam_e5_int8.onnx`, `faster-whisper` tiny INT8, OpenCV, and Playwright Chromium detonation spikes (~300–500 MB). Production resources must not be upgraded without benchmark justification.
3. **Strict open-source license & security invariants (`AGENTS.md` Rules 2, 4, 6):**
   - Only permissive OSS licenses (`MIT`, `Apache-2.0`, `BSD`, `ISC`, `LGPL-3.0`, `Bitstream Vera`) are permitted in production dependencies and model weights.
   - `backend/requirements.txt` must never include `torch` or `transformers`; ONNX Runtime CPU sessions must disable `enable_cpu_mem_arena` and `enable_mem_pattern`; committed Git model artifacts must stay `< 50 MB`.
   - OCR output must be treated as untrusted data (anti indirect prompt injection, zero auto-visiting of OCR-only URLs, zero raw PII in logs, and never concluding `SAFE` on OCR failure / unreadable image-only inputs).

---

## 2. Evaluated Options & License Audit

We evaluated three upstream ecosystems (`RapidAI/RapidOCR`, `PaddlePaddle/PaddleOCR`, `opendatalab/MinerU`) plus VeriShield's existing Gemini multimodal integration:

| Candidate | Package / Runtime | License Verified from Upstream Repo | Compatible w/ `AGENTS.md` Rule 2? | Measured Peak RSS | Measured p50 / p95 | Local Disk Footprint |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **1. RapidOCR v3 ONNX (PP-OCRv5 Latin mobile)** | `rapidocr>=3.0.0` + `onnxruntime` CPU (`ch_PP-OCRv5_det_mobile.onnx` + `latin_PP-OCRv5_rec_mobile.onnx`) | Code: `Apache-2.0` (`RapidAI/RapidOCR/LICENSE`)<br>Models: `Apache-2.0` (`RapidAI/RapidOCR/python/MODEL_LICENSES.md` & `PaddlePaddle/PaddleOCR/LICENSE`) | **YES** | **336.2 MB** | **733.5 ms / 1,032.1 ms** | **12.14 MB** weights |
| **2. Legacy RapidOCR v1.4 (PP-OCRv4 CH)** | `rapidocr-onnxruntime==1.4.4` (`ch_PP-OCRv4_*`) | `Apache-2.0` | YES | 339.2 MB | 1,341.7 ms / 1,688.8 ms | ~15.5 MB weights |
| **3. MinerU v4.2.3 Basic ONNX** | `mineru>=4.0` (`tier="basic"`, `MINERU_MODEL_ONNX_DEVICE=cpu`) | **`LicenseRef-MinerU-Open-Source-License`** (`opendatalab/MinerU/LICENSE.md`: Apache-2.0 + commercial MAU/revenue caps + mandatory prominent UI attribution + auto-termination) | **NO (Conflict)** | **948.4 MB** | 1,209.8 ms / 1,312.2 ms | **2,766.9 MB** (120 pkgs / 771.8 MB + 1,995.1 MB models) |
| **4. Gemini Multimodal (Existing Gateway)** | Existing `llm_client.py` (CPA / Google GenAI) | Commercial API (existing approved integration) | YES (Fallback only) | 112.2 MB *(client)* | 5,182.0 ms / 12,350.0 ms | 0 MB local |

---

## 3. Production VPS Memory Budget Math (`backend` `mem_limit: 2200m`)

| Component Inside `backend` Container | Estimated Resident / Peak Footprint | Notes |
| :--- | :---: | :--- |
| Python 3.12 + FastAPI + Uvicorn (1 worker) + SQLite WAL | ~160 MB | Baseline idle RSS |
| `multilingual-e5-small` INT8 ONNX (`enable_cpu_mem_arena=False`) | ~140 MB | 35 MB model + tokenizer |
| `faster-whisper` tiny INT8 (lazy-loaded on audio upload) | ~260 MB | Bounded sequential execution |
| **RapidOCR v3 PP-OCRv5 Latin ONNX (`use_cls=False`, arena & pattern disabled)** | **~336 MB** | Measured process Peak RSS (includes Python+CV+ORT) |
| OpenCV ELA/QR + Pillow decoding (bounded `<= 25M` px) | ~120 MB | Short-lived per-request buffers |
| Playwright Chromium spike (`PLAYWRIGHT_MAX_CONCURRENCY=1`) | ~450 MB | Transient during suspicious URL detonation |
| **Estimated Peak Combined (with RapidOCR v5 Latin)** | **~1,250–1,450 MB** | **~750+ MB safe headroom under `2200m` cap** |
| *Counterfactual Peak Combined (if MinerU Basic ONNX were installed)* | *~1,950–2,250+ MB* | **Immediate OOM-kill risk under concurrent Playwright/Whisper load** |

---

## 4. Decision

1. **Adopt a Modular `OcrProvider` Protocol (`backend/app/services/ocr/`):**
   - Standardize all engines behind `OcrProvider` (`base.py`) returning normalized `OcrResult` (`status`, `provider`, `model_id`, `full_text`, `boxes` with pixel coordinates & polygons, `mean_confidence`, `height_cv`, `latency_ms`, `error_code`).
   - Orchestrate execution through `OcrOrchestrator` (`service.py`) enforcing `ocr_max_concurrency` (`asyncio.Semaphore`, default `2`), per-image timeout (`ocr_timeout_sec`, default `8.0s`), and selective fallback budgets.
2. **Select `RapidOcrOnnxProvider` (`PP-OCRv5` mobile detection + `latin_PP-OCRv5_rec_mobile.onnx`, `use_cls=False`) as the Production Primary Engine:**
   - **Best accuracy/resource ratio:** Halves exact Vietnamese CER (`0.2243 → 0.1096`), cuts ASCII CER 3.6× (`0.1054 → 0.0294`; **`0.0112`** on receipts), raises Entity F1 (`0.7158 → 0.8041`), eliminates receipt false positives (`0 FP`), and runs **45% faster** (`733.5 ms` p50) than legacy PP-OCRv4 CH while providing pixel-level bounding boxes for receipt font-height tampering forensics (`ocr_height_cv`).
   - **Ablation-verified configuration:** `use_cls=False` outperformed `use_cls=True` (`0.1096` vs `0.1933` CER; `92%` vs `84%` scam classification accuracy).
   - **Zero Git bloat & production offline safety:** The `12.14 MB` ONNX weights are pre-baked into `/app/ocr_cache` at Docker build time (`backend/Dockerfile`) with `VERISHIELD_ALLOW_OCR_DOWNLOAD=0` in production, keeping Git models under `< 50 MB` and avoiding runtime downloads in non-root containers.
   - **Memory-safe ONNX Runtime:** Enforces both `enable_cpu_mem_arena = False` and `enable_mem_pattern = False` on `OrtInferSession` (`AGENTS.md` Rule 4).
3. **Keep `MinerUBasicOnnxProvider` Strictly as an Optional, Uninstalled Adapter (`mineru_provider.py`):**
   - Guarded by `importlib.util.find_spec("mineru")`; **excluded from `backend/requirements.txt` and production Docker images** due to both the non-permissive `LicenseRef-MinerU-Open-Source-License` conflict and its `948.4 MB` Peak RSS / `2.77 GB` disk / `357%` CPU footprint.
   - Available for offline research or future complex multi-column PDF deployments only if licensing is cleared and dedicated worker infrastructure (`>= 4 vCPU / >= 4 GB RAM`) is provisioned.
4. **Use `GeminiMultimodalOcrProvider` Strictly as a Privacy- & Budget-Bounded Fallback (`gemini_provider.py`):**
   - Reuses VeriShield's existing approved LLM gateway (no new third-party OCR vendor).
   - Fires only when local OCR fails/times out/is unavailable, returns `mean_confidence < 0.45`, or returns empty text on an image-only submission with zero user text/URL/QR — capped at `8.0 s` timeout, `0` retries, and at most `2` images per request.

---

## 5. Security & Reliability Consequences

- **Positive:**
  - Full offline resilience: Tier-1 local Vietnamese OCR, VietQR decoding, receipt validation, and E5 INT8 classification succeed without cloud connectivity.
  - Hardened URL provenance: URLs extracted solely from OCR text are inspected **statically only** (`enable_network=False`) and never detonated in Playwright, closing SSRF/auto-visit vectors from attacker-crafted screenshots.
  - Indirect prompt injection inside screenshots is caught by `guardrails.evaluate_guardrails` and strictly isolated inside `<UNTRUSTED_USER_CONTENT>` (`[OCR_EXTRACTED_UNTRUSTED_TEXT]`).
  - OCR failure or unreadable image-only submissions never certify `SAFE` (`risk_score >= 30`, `confidence <= 0.45`, advisory cap vetoed, persisted through `build_trusted_merchant_summary` and SQLite/PDF redaction).
- **Trade-offs & Mitigations:**
  - `latin_PP-OCRv5_rec_mobile.onnx` still exhibits ~`10.96%` exact Vietnamese diacritic CER (mostly accent marks on small/blurred glyphs, while ASCII CER is only `2.94%`). Downstream `ioc_extractor` and `receipt_validator` already use Unicode-folded Vietnamese matching (`fold_vi_ascii`), and Tier-2 Gemini multimodal reasoning receives the original raw images directly when configured to recover full nuanced phrasing.
  - Because `use_cls=False` is set to avoid false 180° flips on chat bubbles, completely upside-down (180°) screenshots rely on Gemini multimodal fallback / Tier-2 vision rather than local textline rotation.
