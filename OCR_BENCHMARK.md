# VeriShield AI — Empirical Vietnamese OCR Benchmark Report

> **Strict Evidence Policy:** Every metric in this document was measured directly by executing `evaluation/ocr_benchmark/run_ocr_benchmark.py` with subprocess process-memory isolation and saved verbatim in [`evaluation/ocr_benchmark/results.json`](evaluation/ocr_benchmark/results.json). Zero estimated or synthetic metrics are reported.

---

## 1. Benchmark Setup & Methodology

- **Timestamp (UTC):** `2026-11-26T16:01:12Z`
- **Host Environment:** Windows 11 (`Windows-11-10.0.26300-SP0`), Python `3.13.5`, `16` logical CPU threads
- **Production VPS Constraint Baseline (`docker-compose.prod.yml`):** 4 GB RAM VPS — `backend` container capped at **`2200 MB` RAM (`mem_limit: 2200m`), `1.5` CPU (`cpus: 1.5`), `UVICORN_WORKERS=1`**, sharing memory with FastAPI, `multilingual-e5-small` INT8 ONNX, `faster-whisper` tiny INT8, OpenCV QR/ELA, and Playwright Chromium spikes.
- **Dataset (`evaluation/ocr_benchmark/generate_dataset.py`):** **25 deterministic, 100% synthetic Vietnamese images** (zero real PII, rendered with `DejaVuSans.ttf`), 5 images per category:
  1. `chat_sms`: Vietnamese SMS/Zalo scam & legitimate safety-advisory messages with full diacritics, URLs, phones, bank accounts.
  2. `bank_receipt`: Vietcombank, Techcombank, MB Bank, BIDV (English), and ACB transfer receipts including fake mixed-separator amounts (`5,000.000`) and invalid reference codes (`FAKE12`, `FAKE99`).
  3. `vietqr`: OpenCV-rendered QR / VietQR cards paired with Vietnamese payment/refund-trap labels.
  4. `dark_mode`: Dark-theme chat & banking screenshots (light text on `#0f172a` / `#1e293b`).
  5. `low_quality`: Zalo-style recompressed (`JPEG Q=32`), downscaled/upscaled (`0.72x`), Gaussian-blurred (`r=0.65`), noisy, and slightly tilted (`±1.2°–2.0°`) screenshots.
- **Isolation & Measurement Protocol:**
  - Each engine ran in a fresh OS child process so `PeakWorkingSetSize` (`K32GetProcessMemoryInfo`) reflects true per-engine Peak RSS RAM without cross-engine leakage.
  - MinerU (`mineru==4.2.3`) was installed strictly inside a separate, uncommitted `.bench_mineru_venv` (never in `backend/requirements.txt` or `backend/.venv`) with `MINERU_MODEL_ONNX_DEVICE=cpu`, `tier="basic"`, `ocr_mode="ocr"`, `image_analysis=False`. Markdown image tags (`![](data:image/...)` that MinerU emits for QR crops) and `#` heading markers were stripped before computing CER/WER so MinerU was evaluated fairly on its extracted text.
  - Downstream scam-classification accuracy and receipt-detection recall were evaluated by passing each engine's raw OCR text through VeriShield's actual Tier-1 modules (`ScamClassifier` E5 INT8 ONNX + `extract_iocs` + `validate_receipt_logic` + `evaluate_guardrails` + static `_score_single_url`).

---

## 2. Overall Empirical Comparison

| Engine | Model / Runtime | License | CER (Exact VI) ↓ | CER (ASCII) ↓ | WER ↓ | Entity F1 (P / R) ↑ | Scam Acc ↑ | Receipt Recall (FP) | Latency p50 (ms) ↓ | Latency p95 (ms) ↓ | Cold Load (ms) ↓ | Peak RSS (MB) ↓ | CPU Single-Core % | Local Disk Footprint |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **RapidOCR v4 CH** *(Legacy Baseline)* | `ch_PP-OCRv4_det_mobile` + `ch_PP-OCRv4_rec_mobile` (ONNX CPU, 2 threads) | `Apache-2.0` | 0.2243 | 0.1054 | 0.9222 | 0.7158 (81.0% / 64.2%) | 92.0% | 100% (1 FP) | 1,341.7 | 1,688.8 | 1,990.6 | 339.2 | 201.0% | ~15.5 MB |
| **RapidOCR v3 PP-OCRv5 Latin (`use_cls=False`)** *(Selected Production Primary)* | `ch_PP-OCRv5_det_mobile` + `latin_PP-OCRv5_rec_mobile` (ONNX CPU, 2 threads) | `Apache-2.0` | **0.1096** | **0.0294** | **0.4994** | **0.8041** (88.6% / 73.6%) | **92.0%** | **100% (0 FP)** | **733.5** | **1,032.1** | **1,391.4** | **336.2** | **205.8%** | **12.14 MB** |
| **RapidOCR v3 PP-OCRv5 Latin (`use_cls=True`)** *(Orientation Ablation)* | Same + `ch_ppocr_mobile_v2.0_cls_mobile` (ONNX CPU, 2 threads) | `Apache-2.0` | 0.1933 | 0.1251 | 0.5162 | 0.7912 (94.7% / 67.9%) | 84.0% | 100% (0 FP) | 749.2 | 1,069.0 | 1,357.8 | 340.5 | 212.3% | 12.70 MB |
| **MinerU v4.2.3 Basic ONNX** *(Optional Adapter — Non-Prod)* | `mineru==4.2.3` `tier="basic"` (`PP-DocLayoutV2` + ONNX CPU) | `LicenseRef-MinerU-Open-Source-License` *(Non-permissive)* | 0.0906 | 0.0554 | 0.4465 | 0.9400 (100% / 88.7%) | 96.0% | 100% (1 FP) | 1,209.8 | 1,312.2 | 6,384.5 | **948.4** | **357.2%** | **2,766.9 MB** *(771.8 MB venv + 1,995.1 MB models)* |
| **Gemini Multimodal** *(Bounded Fallback)* | Configured live endpoint (`gemini-4-hydrogen`) | Commercial API | **0.0000** | **0.0000** | **0.0000** | **1.0000** (100% / 100%) | 92.0% | 100% (1 FP) | 5,182.0 | 12,350.0 | 0.0 | 112.2 *(HTTP client)* | 3.3% *(HTTP client)* | 0 MB local |

---

## 3. Per-Category Breakdown (Exact VI CER / ASCII CER / WER / p50 Latency)

### 3.1. `chat_sms` (5 Vietnamese SMS/Zalo screenshots)
| Engine | CER (Exact VI) | CER (ASCII) | WER | p50 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: |
| RapidOCR v4 CH (Legacy) | 0.2609 | 0.1115 | 0.9234 | 1,609.3 |
| **RapidOCR v5 Latin (`use_cls=False`)** | **0.1498** | **0.0422** | **0.6749** | **1,020.3** |
| RapidOCR v5 Latin (`use_cls=True`) | 0.4166 | 0.3529 | 0.7257 | 1,009.8 |
| MinerU v4.2.3 Basic ONNX | 0.1001 | 0.0498 | 0.5597 | 1,241.7 |
| Gemini Multimodal | 0.0000 | 0.0000 | 0.0000 | 10,970.1 |

### 3.2. `bank_receipt` (5 Vietnamese & English banking receipts)
| Engine | CER (Exact VI) | CER (ASCII) | WER | p50 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: |
| RapidOCR v4 CH (Legacy) | 0.1614 | 0.1058 | 0.9778 | 1,491.5 |
| **RapidOCR v5 Latin (`use_cls=False`)** | **0.0505** | **0.0112** | **0.3111** | **734.3** |
| RapidOCR v5 Latin (`use_cls=True`) | 0.0505 | 0.0112 | 0.3111 | 749.2 |
| MinerU v4.2.3 Basic ONNX | 0.0403 | 0.0288 | 0.2753 | 1,215.9 |
| Gemini Multimodal | 0.0000 | 0.0000 | 0.0000 | 5,213.9 |

### 3.3. `vietqr` (5 QR / VietQR payment & trap screenshots)
| Engine | CER (Exact VI) | CER (ASCII) | WER | p50 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: |
| RapidOCR v4 CH (Legacy) | 0.2575 | 0.1251 | 0.9493 | 1,332.1 |
| **RapidOCR v5 Latin (`use_cls=False`)** | **0.1154** | **0.0357** | **0.4781** | **730.0** |
| RapidOCR v5 Latin (`use_cls=True`) | 0.1965 | 0.1222 | 0.5115 | 718.7 |
| MinerU v4.2.3 Basic ONNX *(after stripping base64 QR image tag)* | 0.1235 | 0.0913 | 0.4264 | 1,191.1 |
| Gemini Multimodal | 0.0000 | 0.0000 | 0.0000 | 4,587.8 |

> **Important MinerU Observation on `vietqr`:** Before stripping Markdown image tags (`![](data:image/jpeg;base64,...)`), MinerU embedded base64 crops of the QR code inside its Markdown output, inflating raw `vietqr` CER to `129.94` (12,994%) and risking prompt bloat if fed directly into downstream LLM reasoning. `MinerUBasicOnnxProvider` therefore strips Markdown image blobs defensively.

### 3.4. `dark_mode` (5 dark-background chat & banking UI screenshots)
| Engine | CER (Exact VI) | CER (ASCII) | WER | p50 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: |
| RapidOCR v4 CH (Legacy) | 0.1792 | 0.0475 | 0.8073 | 1,253.8 |
| **RapidOCR v5 Latin (`use_cls=False`)** | **0.0995** | **0.0283** | **0.4691** | **656.3** |
| RapidOCR v5 Latin (`use_cls=True`) | 0.0995 | 0.0283 | 0.4691 | 751.6 |
| MinerU v4.2.3 Basic ONNX | 0.0832 | 0.0728 | 0.4330 | 1,210.1 |
| Gemini Multimodal | 0.0000 | 0.0000 | 0.0000 | 4,929.7 |

### 3.5. `low_quality` (5 JPEG Q=32, blurred, noisy, tilted screenshots)
| Engine | CER (Exact VI) | CER (ASCII) | WER | p50 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: |
| RapidOCR v4 CH (Legacy) | 0.2626 | 0.1371 | 0.9533 | 1,188.7 |
| **RapidOCR v5 Latin (`use_cls=False`)** | **0.1331** | **0.0298** | **0.5638** | **698.2** |
| RapidOCR v5 Latin (`use_cls=True`) | 0.2033 | 0.1108 | 0.5638 | 647.4 |
| MinerU v4.2.3 Basic ONNX | 0.1061 | 0.0343 | 0.5379 | 1,183.0 |
| Gemini Multimodal | 0.0000 | 0.0000 | 0.0000 | 4,979.1 |

---

## 4. Key Empirical Takeaways

1. **Massive win upgrading from legacy `rapidocr-onnxruntime` (PP-OCRv4 CH) to `rapidocr` v3 (PP-OCRv5 Latin mobile):**
   - Exact Vietnamese CER dropped **51.1%** (`0.2243 → 0.1096`); ASCII-folded CER dropped **72.1%** (`0.1054 → 0.0294`, reaching **`0.0112` / 98.9% character accuracy on bank receipts**).
   - Entity extraction F1 rose **+8.8 points** (`0.7158 → 0.8041`), receipt false positives dropped to **0**, and median latency fell **45.3%** (`1,341.7 ms → 733.5 ms`) at identical RAM (`336.2 MB` peak RSS) and smaller weights (**`12.14 MB`** total).
   - Preserves pixel-accurate line bounding boxes (`OcrBox`) required by `receipt_validator.py`'s font-height geometry tampering check (`ocr_height_cv`).
2. **Disabling textline orientation classifier (`use_cls=False`) is empirically justified:**
   - Enabling `use_cls=True` degraded `chat_sms` CER from `0.1498` to `0.4166` (due to misclassifying short horizontal lines as 180°-rotated) and cut downstream scam classification accuracy from **92.0% → 84.0%**.
3. **Why MinerU Basic ONNX is kept as an optional non-production adapter only:**
   - **Memory & CPU:** `948.4 MB` peak RSS (**2.82×** RapidOCR) and `357.2%` single-core CPU (~3.6 cores) exceed safe headroom on our `2200 MB` / `1.5 CPU` production container (`docker-compose.prod.yml`).
   - **Footprint & Startup:** `120` transitive packages (`771.8 MB`) + `1,995.1 MB` model cache (`2.77 GB` total) and `6.38 s` cold start vs RapidOCR's `12.14 MB` weights and `1.39 s` cold start.
   - **License:** `LicenseRef-MinerU-Open-Source-License` imposes commercial MAU/revenue thresholds, mandatory prominent UI attribution, and automatic termination — violating `AGENTS.md` Rule 2 (pure permissive licenses only).
   - **ASCII Accuracy on Financial Entities:** RapidOCR PP-OCRv5 Latin achieved lower ASCII CER than MinerU across every single category (`0.0294` vs `0.0554` overall; `0.0112` vs `0.0288` on receipts) and produced 0 receipt false positives vs MinerU's 1.
4. **Why Gemini Multimodal is ideal strictly as a bounded fallback (not primary OCR):**
   - Achieves `0.0000` CER/WER and `1.0000` Entity F1, but runs **7.1× slower at p50 (`5,182 ms`) and 12.0× slower at p95 (`12,350 ms`)**, requires external network/API quota, lacks pixel bounding boxes for receipt geometry forensics, and cannot function offline.
   - Deploying **RapidOCR v3 PP-OCRv5 Latin ONNX** as primary + **Gemini Multimodal** as a bounded single-shot fallback (only on OCR failure/timeout, `< 0.45` confidence, or unreadable image-only inputs; capped at `8.0 s`, `0` retries, max `2` images/request) delivers sub-second local accuracy with cloud-grade recovery when local OCR struggles.

---

## 5. Reproducibility

```powershell
# Regenerate the 25 synthetic Vietnamese benchmark images & run RapidOCR + Gemini
backend\.venv\Scripts\python.exe evaluation\ocr_benchmark\run_ocr_benchmark.py

# Optional: include MinerU v4 Basic ONNX from an isolated non-production virtualenv
backend\.venv\Scripts\python.exe evaluation\ocr_benchmark\run_ocr_benchmark.py --mineru-python .bench_mineru_venv\Scripts\python.exe
```
