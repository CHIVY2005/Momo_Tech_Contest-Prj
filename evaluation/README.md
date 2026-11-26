# VeriShield AI v2.0 — Thực nghiệm Benchmark 40 Ca Tiếng Việt & Red-Team

Bộ đánh giá này đọc cấu hình trực tiếp từ `backend/.env` (`LLM_PROVIDER`, `GEMINI_BASE_URL`, `GEMINI_MODEL`, `GEMINI_API_KEY`, `GEMINI_BACKUP_API_KEY`), thực thi luồng `AnalysisPipeline` thật trên **40 tình huống tổng hợp** (28 ca lừa đảo/tấn công + 12 ca đối chứng an toàn/khuyến cáo chính thống) và ghi lại trung thực 100%:

- **Model thực tế phản hồi từ API** (`actual_models_observed` lấy trực tiếp từ trường `model` của CLIProxyAPI / Google GenAI).
- **Độ trễ thực nghiệm** (`e2e_p50_ms`, `e2e_p95_ms`, `llm_p50_ms`, `llm_p95_ms`, `onnx_p50_ms`, `onnx_p95_ms`).
- **Sức khỏe & lỗi API** (`live_llm_success_count`, `degraded_fallback_count`, `api_error_count`, `error_breakdown`).
- **Chỉ số phân loại chi tiết** (`Precision`, `Recall`, `F1`, `Accuracy`, `safety_advisory_fpr`, `prompt_injection_block_rate`, `fake_bill_catch_rate`).

## Cách kiểm tra kết nối API & chạy Benchmark

1. Tạo file `backend/.env` từ `backend/.env.example` và điền `GEMINI_API_KEY` (không commit file này):
   ```ini
   LLM_PROVIDER=openai_compatible
   GEMINI_BASE_URL=https://cpa.joiboi.app/v1
   GEMINI_MODEL=gemini-2.5-flash
   GEMINI_API_KEY=<dien_key_cpa_cua_ban>
   ```
2. Kiểm tra nhanh kết nối CPA & khả năng trả về JSON có cấu trúc:
   ```powershell
   backend\.venv\Scripts\python scripts/verify_llm_connection.py
   ```
3. Chạy thực nghiệm 40 ca (bắt buộc sử dụng LLM thật qua cờ `--require-live-llm`):
   ```powershell
   backend\.venv\Scripts\python evaluation/run_benchmark.py --require-live-llm --output evaluation/results.json
   ```
