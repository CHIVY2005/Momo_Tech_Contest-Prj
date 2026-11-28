"""Generate print-ready Vietnamese assessment & improvement PDF report for VeriShield AI."""

from __future__ import annotations

import html
import os
from pathlib import Path

from playwright.sync_api import Browser, Playwright, sync_playwright
from playwright.sync_api import Error as PlaywrightError
from pypdf import PdfReader

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PDF = REPO_ROOT / "docs" / "VeriShield_AI_Danh_Gia_Va_Cai_Thien_Du_An.pdf"
FONT_PATH = REPO_ROOT / "backend" / "app" / "data" / "fonts" / "DejaVuSans.ttf"


def _launch_chromium(pw: Playwright) -> Browser:
    """Launch default Playwright Chromium or fall back to cached local Chromium/Edge/Chrome."""
    default_exe = Path(pw.chromium.executable_path)
    if default_exe.exists():
        return pw.chromium.launch(headless=True)

    cache_roots = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright",
        Path.home() / ".cache" / "ms-playwright",
    ]
    for root in cache_roots:
        if not root.exists():
            continue
        for pat in ("chromium-*/chrome-win64/chrome.exe", "chromium-*/chrome-linux*/chrome"):
            matches = sorted(root.glob(pat), reverse=True)
            if matches:
                return pw.chromium.launch(headless=True, executable_path=str(matches[0]))

    last_err: PlaywrightError | None = None
    for channel in ("msedge", "chrome"):
        try:
            return pw.chromium.launch(channel=channel, headless=True)
        except PlaywrightError as exc:
            last_err = exc
    raise RuntimeError("No usable Chromium/Edge/Chrome browser found.") from last_err


def _build_html() -> str:
    """Construct print-calibrated Vietnamese HTML report grounded in project docs."""
    font_uri = FONT_PATH.as_uri() if FONT_PATH.exists() else ""
    font_face_css = (
        f"@font-face {{ font-family: 'VSDejaVu'; src: url('{html.escape(font_uri)}') "
        "format('truetype'); font-weight: 100 900; font-style: normal; }"
        if font_uri
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8" />
<title>VeriShield AI — Báo cáo Đánh giá Điểm tốt, Tồn đọng &amp; Lộ trình Cải thiện</title>
<style>
{font_face_css}
@page {{
  size: A4 portrait;
  margin: 13mm 13mm 15mm 13mm;
}}
* {{
  box-sizing: border-box;
}}
body {{
  margin: 0;
  font-family: 'Segoe UI', 'VSDejaVu', Arial, sans-serif;
  color: #0f172a;
  background: #ffffff;
  font-size: 9.4pt;
  line-height: 1.46;
}}
.hero {{
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  color: #f8fafc;
  border-radius: 10px;
  padding: 16px 18px;
  margin-bottom: 12px;
  border-left: 5px solid #f59e0b;
}}
.hero-kicker {{
  font-size: 7.8pt;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #fbbf24;
  margin-bottom: 4px;
}}
.hero h1 {{
  margin: 0 0 6px 0;
  font-size: 15.5pt;
  line-height: 1.25;
  color: #ffffff;
}}
.hero-sub {{
  margin: 0;
  font-size: 8.8pt;
  color: #cbd5e1;
}}
.meta-strip {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
  font-size: 7.8pt;
  color: #e2e8f0;
}}
.meta-pill {{
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.18);
  border-radius: 999px;
  padding: 2px 9px;
}}
.kpi-grid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-bottom: 12px;
}}
.kpi-card {{
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  padding: 8px 10px;
  background: #f8fafc;
  break-inside: avoid;
}}
.kpi-card.good {{
  border-top: 3px solid #059669;
  background: #f0fdf4;
}}
.kpi-card.warn {{
  border-top: 3px solid #d97706;
  background: #fffbeb;
}}
.kpi-card.risk {{
  border-top: 3px solid #e11d48;
  background: #fff1f2;
}}
.kpi-label {{
  font-size: 7.3pt;
  font-weight: 700;
  text-transform: uppercase;
  color: #475569;
  margin-bottom: 2px;
}}
.kpi-val {{
  font-size: 12.2pt;
  font-weight: 800;
  color: #0f172a;
}}
.kpi-note {{
  font-size: 7.5pt;
  color: #334155;
  margin-top: 2px;
}}
h2 {{
  font-size: 11.4pt;
  color: #0f172a;
  margin: 12px 0 6px 0;
  padding-bottom: 3px;
  border-bottom: 2px solid #e2e8f0;
  display: flex;
  align-items: center;
  gap: 6px;
  break-after: avoid;
}}
.sec-num {{
  background: #0f172a;
  color: #fbbf24;
  font-size: 8pt;
  font-weight: 800;
  padding: 1px 6px;
  border-radius: 4px;
}}
p {{
  margin: 4px 0 7px 0;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  margin: 6px 0 10px 0;
  font-size: 8.3pt;
}}
th {{
  background: #0f172a;
  color: #f8fafc;
  text-align: left;
  padding: 6px 7px;
  font-weight: 700;
  border: 1px solid #0f172a;
}}
td {{
  padding: 5.5px 7px;
  border: 1px solid #cbd5e1;
  vertical-align: top;
}}
tr {{
  break-inside: avoid;
}}
tbody tr:nth-child(even) {{
  background: #f8fafc;
}}
.callout {{
  border-radius: 8px;
  padding: 9px 11px;
  margin: 7px 0 10px 0;
  break-inside: avoid;
}}
.callout-danger {{
  background: #fff1f2;
  border: 1px solid #fda4af;
  border-left: 4px solid #e11d48;
}}
.callout-amber {{
  background: #fffbeb;
  border: 1px solid #fcd34d;
  border-left: 4px solid #d97706;
}}
.callout-title {{
  font-size: 9.2pt;
  font-weight: 800;
  margin-bottom: 4px;
}}
.callout-danger .callout-title {{
  color: #9f1239;
}}
.callout-amber .callout-title {{
  color: #92400e;
}}
ul.compact {{
  margin: 4px 0 2px 0;
  padding-left: 16px;
}}
ul.compact li {{
  margin-bottom: 3px;
}}
.cards-2col {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin: 6px 0 10px 0;
}}
.strength-card {{
  border: 1px solid #bbf7d0;
  border-left: 4px solid #059669;
  background: #f8fafc;
  border-radius: 7px;
  padding: 7px 9px;
  break-inside: avoid;
}}
.strength-title {{
  font-size: 8.8pt;
  font-weight: 800;
  color: #065f46;
  margin-bottom: 3px;
}}
.strength-body {{
  font-size: 8.1pt;
  color: #1e293b;
}}
.badge {{
  display: inline-block;
  font-size: 7.2pt;
  font-weight: 800;
  padding: 1px 5px;
  border-radius: 4px;
  white-space: nowrap;
}}
.b-ok {{ background: #dcfce7; color: #166534; border: 1px solid #86efac; }}
.b-p0 {{ background: #ffe4e6; color: #9f1239; border: 1px solid #fda4af; }}
.b-p1 {{ background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }}
.b-p2 {{ background: #e0f2fe; color: #075985; border: 1px solid #7dd3fc; }}
code {{
  font-family: Consolas, 'VSDejaVu', monospace;
  font-size: 7.8pt;
  background: #f1f5f9;
  padding: 0.5px 3px;
  border-radius: 3px;
  color: #0f172a;
}}
.page-break {{
  break-before: page;
}}
</style>
</head>
<body>

<div class="hero">
  <div class="hero-kicker">Báo cáo rà soát kỹ thuật &amp; bám sát đề bài cuộc thi</div>
  <h1>VeriShield AI — Đánh giá Điểm tốt, Điểm chưa tốt &amp; Kế hoạch Cải thiện</h1>
  <p class="hero-sub">
    Đối chiếu trực tiếp năng lực hệ thống hiện tại với đề bài
    <strong>Imagine the Future Workspace (Human Centered. AI Powered)</strong> trong
    <code>docs/momo.md</code> và hiến pháp kỹ thuật <code>AGENTS.md</code>.
  </p>
  <div class="meta-strip">
    <span class="meta-pill">Ngày đánh giá: 28/11/2026</span>
    <span class="meta-pill">Nhánh code: v3 / feat/verishield-v2 (7e30ea0)</span>
    <span class="meta-pill">Hạn nộp &amp; đóng băng: 03/12/2026</span>
    <span class="meta-pill">Chung kết dự kiến: 11/12/2026</span>
  </div>
</div>

<div class="kpi-grid">
  <div class="kpi-card good">
    <div class="kpi-label">Bám sát đề bài</div>
    <div class="kpi-val">3 / 3 Chủ đề</div>
    <div class="kpi-note">Chống lừa đảo · An ninh mạng · Trợ lý AI</div>
  </div>
  <div class="kpi-card good">
    <div class="kpi-label">Độ hoàn thiện Web MVP</div>
    <div class="kpi-val">~90% Sẵn sàng</div>
    <div class="kpi-note">60/60 test FE · 4/4 E2E Chromium thật</div>
  </div>
  <div class="kpi-card risk">
    <div class="kpi-label">Rủi ro lớn nhất (P0)</div>
    <div class="kpi-val">Lệch Tài liệu nộp</div>
    <div class="kpi-note">Slide/Guide cũ hơn bản Web &amp; Trợ lý mới</div>
  </div>
  <div class="kpi-card warn">
    <div class="kpi-label">Nguyên tắc nước rút</div>
    <div class="kpi-val">Không mở rộng scope</div>
    <div class="kpi-note">Ưu tiên đồng bộ, deploy live &amp; 4 file nộp</div>
  </div>
</div>

<h2><span class="sec-num">01</span> Đối chiếu với Đề bài Cuộc thi &amp; Ranh giới "Tránh đi xa"</h2>
<p>
  Đề bài <code>docs/momo.md</code> yêu cầu sản phẩm ứng dụng AI làm cốt lõi, dùng thử được trực tuyến
  ngay mà không phụ thuộc máy local, thuộc ít nhất 1 trong 3 chủ đề (<strong>Trợ lý AI</strong>,
  <strong>An ninh mạng</strong>, <strong>Chống lừa đảo</strong>) và hoàn thiện đủ 4 hạng mục nộp bài.
</p>

<table>
  <thead>
    <tr>
      <th style="width: 24%;">Tiêu chí đề bài</th>
      <th style="width: 14%;">Trạng thái</th>
      <th style="width: 62%;">Mức độ đáp ứng của VeriShield AI &amp; Trọng tâm cần giữ</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Chủ đề 1: Chống lừa đảo</strong></td>
      <td><span class="badge b-ok">ĐẠT RÕ RỆT</span></td>
      <td>
        Phát hiện tin nhắn giả danh, bẫy chuyển khoản VietQR hoàn tiền, biên lai giả/tái sử
        dụng, đường dẫn lừa đảo, và bật bước tạm dừng 30 giây khi người dùng đang nghe điện thoại.
      </td>
    </tr>
    <tr>
      <td><strong>Chủ đề 2: An ninh mạng</strong></td>
      <td><span class="badge b-ok">ĐẠT RÕ RỆT</span></td>
      <td>
        Chống SSRF gắn IP công cộng tới tận socket, trình duyệt cách ly kiểm tra DOM/.apk,
        chống Prompt Injection, bảo vệ nút quản trị /radar bằng HMAC &amp; chống đầu độc dữ liệu.
      </td>
    </tr>
    <tr>
      <td><strong>Chủ đề 3: Trợ lý AI</strong></td>
      <td><span class="badge b-ok">ĐẠT RÕ RỆT</span></td>
      <td>
        <strong>Trợ lý VeriShield</strong> giải thích kết quả, gợi ý câu phản hồi an toàn cho
        cá nhân &amp; người thân, kiểm tra thêm bằng chứng cục bộ và hỏi đáp dựa trên RAG lai
        E5 + BM25.
      </td>
    </tr>
    <tr>
      <td><strong>AI là giá trị cốt lõi</strong></td>
      <td><span class="badge b-ok">ĐẠT</span></td>
      <td>
        Tự huấn luyện &amp; lượng tử hóa <code>scam_e5_int8.onnx</code> (34,30 MB, CPU 10 ms),
        kết hợp OCR PP-OCRv5, Whisper STT và AI đa phương thức tầng 2 (có dự phòng nội bộ khi
        lỗi).
      </td>
    </tr>
    <tr>
      <td><strong>Dùng thử trực tuyến không phụ thuộc local</strong></td>
      <td><span class="badge b-p1">CẦN DEPLOY</span></td>
      <td>
        Giao diện Zero-Login sẵn sàng với các kịch bản mẫu 1 bấm, nhưng cần hoàn tất deploy lên
        VPS công khai (<code>verishield.joiboi.app</code>) và kiểm tra qua 4G + trình duyệt ẩn
        danh.
      </td>
    </tr>
    <tr>
      <td><strong>4 thành phần bài nộp</strong><br/>(HDSD 1p, Zip, Slide 10p, Video 3p)</td>
      <td><span class="badge b-p0">CẦN ĐỒNG BỘ</span></td>
      <td>
        Đã có khung <code>submission/</code>, nhưng Slide 10 trang, Hướng dẫn 1 trang và Kịch
        bản Video 3 phút hiện vẫn theo bản cũ trước khi gộp khung nhập đa phương thức &amp; thêm
        Trợ lý AI.
      </td>
    </tr>
  </tbody>
</table>

<div class="callout callout-danger">
  <div class="callout-title">
    5 việc TUYỆT ĐỐI KHÔNG LÀM trong 5 ngày cuối để tránh đi xa đề bài
  </div>
  <ul class="compact">
    <li>
      <strong>Không thêm màn hình đăng ký / đăng nhập bắt buộc:</strong> Giám khảo cần dùng thử
      ngay trên web; cơ chế khóa phiên HMAC 2 giờ hiện tại đã đủ bảo vệ hồ sơ mà vẫn giữ trải
      nghiệm Zero-Login.
    </li>
    <li>
      <strong>Không dồn sức mở rộng Telegram Bot hay tính năng ngoài Web MVP:</strong> Trọng tâm
      trình diễn và chấm điểm trực tiếp là Web App (<code>/</code> + Trợ lý +
      <code>/radar</code>); Telegram chỉ giữ vai trò kênh bổ trợ nhẹ nhàng.
    </li>
    <li>
      <strong>Không nạp thêm thư viện/model nặng hay dính giấy phép hạn chế:</strong> Tuyệt đối
      không đưa <code>torch</code>/<code>transformers</code> vào runtime, không dùng mô hình
      <code>AGPL-3.0</code> hoặc chỉ dành cho nghiên cứu.
    </li>
    <li>
      <strong>Không nới lỏng nguyên tắc trung thực biên lai:</strong> Không bao giờ biến sản
      phẩm thành công cụ "cam kết tiền đã vào tài khoản" từ ảnh chụp — đây là điểm đạo đức AI tạo
      uy tín lớn với giám khảo fintech.
    </li>
    <li>
      <strong>Không tự ý thay đổi cấu trúc UI lớn sau khi quay video &amp; xuất Slide PDF:</strong>
      Vì Slide 10 trang không được sửa sau 03/12, mọi thay đổi muộn làm lệch Slide/Video với bản
      chạy trực tuyến sẽ bị mất điểm nhất quán.
    </li>
  </ul>
</div>

<h2><span class="sec-num">02</span> 6 Điểm Tốt Nổi Bật Cần Nhấn Mạnh Với Ban Giám Khảo</h2>
<div class="cards-2col">
  <div class="strength-card">
    <div class="strength-title">1. Kiến trúc AI 3 tầng thực dụng, chạy mượt trên CPU phổ thông</div>
    <div class="strength-body">
      Tự xây dựng mô hình <code>intfloat/multilingual-e5-small</code> (MIT) cắt tỉa 36.000 token và
      lượng tử hóa INT8 còn <strong>34,30 MB</strong> (<code>Macro-F1 = 0,9314</code>, trễ trung
      vị <strong>10 ms</strong>). Khi AI đám mây gặp sự cố hoặc quá tải, hệ thống tự chuyển về
      Tầng 1 mà vẫn trả kết quả ổn định.
    </div>
  </div>
  <div class="strength-card">
    <div class="strength-title">
      2. Khung nhập thống nhất &amp; Trợ lý VeriShield Hybrid RAG an toàn
    </div>
    <div class="strength-body">
      Người dùng chỉ cần 1 ô duy nhất để dán chữ, link, ảnh <code>Ctrl+V</code> hoặc tệp ghi âm.
      Trợ lý dùng chung 1 phiên E5 + BM25 (<code>R@3 = 98,4%</code>, chặn ngoài miền
      <strong>100%</strong>, từ chối nhầm <strong>1,56%</strong> trên 97 ca kiểm thử) kèm cổng
      kiểm duyệt 3 tầng chống bịa thông tin.
    </div>
  </div>
  <div class="strength-card">
    <div class="strength-title">
      3. Đạo đức AI Fintech: Nguyên tắc trung thực biên lai người bán
    </div>
    <div class="strength-body">
      Ngay cả khi ảnh chuyển khoản đạt điểm rủi ro thấp, hệ thống luôn đánh dấu <em>chưa thể xác
      nhận tiền đã vào tài khoản từ ảnh chụp</em> và nhắc kiểm tra trực tiếp biến động số dư hoặc
      loa thông báo nhận tiền.
    </div>
  </div>
  <div class="strength-card">
    <div class="strength-title">
      4. Phòng thủ an ninh mạng từ ứng dụng đến tầng Socket &amp; Radar
    </div>
    <div class="strength-body">
      Gắn IP công cộng khi truy vết URL/Playwright để chống SSRF/DNS rebinding; che giấu SĐT/STK
      trước khi lưu &amp; băm HMAC-SHA256 trên <code>/radar</code>. Đồ thị <code>/radar</code> tự
      viết tối ưu đạt <strong>98–120 FPS</strong> ở 500 nút không chồng lấn.
    </div>
  </div>
  <div class="strength-card">
    <div class="strength-title">5. Lựa chọn OCR &amp; Pháp y VietQR dựa trên thực nghiệm đo lường</div>
    <div class="strength-body">
      Thực nghiệm 25 ảnh chứng minh <strong>RapidOCR PP-OCRv5 Latin</strong> (12,14 MB, Apache-2.0)
      giảm <strong>51,1%</strong> lỗi ký tự gốc và <strong>72,1%</strong> lỗi không dấu, nhanh và
      nhẹ RAM gấp ~3 lần mô hình nặng. Giải mã VietQR chuẩn EMVCo/CRC-16 phát hiện bẫy hoàn tiền.
    </div>
  </div>
  <div class="strength-card">
    <div class="strength-title">
      6. Kỷ luật kỹ thuật, giấy phép sạch &amp; bộ kiểm thử quy mô lớn
    </div>
    <div class="strength-body">
      <code>100%</code> thư viện giấy phép mở tự do/LGPL-3.0, <code>100%</code> dữ liệu tổng hợp
      không PII thật; đạt <strong>60/60</strong> unit/mock test Frontend, <strong>4/4</strong>
      kịch bản E2E trình duyệt Chromium thật, <code>ruff</code> + <code>mypy --strict</code> 71
      file và hơn 419 ca pytest đạt chuẩn.
    </div>
  </div>
</div>

<div class="page-break"></div>

<h2>
  <span class="sec-num">03</span> Điểm Chưa Tốt Hiện Tại &amp; Cách Cải Thiện Cụ Thể (Theo Ưu Tiên)
</h2>
<table>
  <thead>
    <tr>
      <th style="width: 11%;">Ưu tiên</th>
      <th style="width: 27%;">Điểm chưa tốt hiện tại</th>
      <th style="width: 24%;">Ảnh hưởng tới cuộc thi</th>
      <th style="width: 38%;">Cách cải thiện cụ thể &amp; thực thi ngay</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><span class="badge b-p0">P0 · GẤP</span></td>
      <td>
        <strong>Bộ tài liệu nộp bài bị lệch phiên bản code mới</strong><br/>
        <code>slides/index.html</code>, <code>guide/index.html</code>,
        <code>video-script-3min.md</code> và PDF trong <code>submission/dist/</code> render từ
        26/11 vẫn mô tả 3 nút chế độ cũ, thiếu Trợ lý RAG &amp; PP-OCRv5.
      </td>
      <td>
        Giám khảo xem slide/video khác với web đang chạy thật sẽ nghi ngờ tính trung thực hoặc đánh
        giá thiếu đồng bộ khi chấm vòng loại &amp; chung kết.
      </td>
      <td>
        Cập nhật lại Slide 10 trang, Hướng dẫn 1 trang A4 và kịch bản Video 3 phút khớp giao diện
        thống nhất mới, số liệu PP-OCRv5 &amp; RAG B6, bỏ từ ngữ nội bộ (<code>in_active_call</code>,
        <code>HTTP 409</code>), sau đó chạy lại <code>render_pdfs.py</code>.
      </td>
    </tr>
    <tr>
      <td><span class="badge b-p0">P0 · GẤP</span></td>
      <td>
        <strong>Chưa chốt bản Deploy VPS &amp; Benchmark model thật</strong><br/>
        <code>evaluation/results.json</code> vẫn ghi nhận lần chạy cũ ngày 26/11 (gọi alias
        <code>gemini-4-hydrogen</code>); chưa chạy smoke test mở rộng cho luồng Trợ lý AI trên VPS
        công khai.
      </td>
      <td>
        Đề bài bắt buộc giám khảo dùng thử trực tuyến ổn định. Nếu benchmark không khớp model
        production thật hoặc API Trợ lý lỗi trên VPS sẽ mất điểm cốt lõi.
      </td>
      <td>
        Chạy lại <code>evaluation/run_benchmark.py --require-live-llm</code> bằng model production
        chính thức (ví dụ <code>gemini-2.5-flash</code>); cấu hình <code>deploy/.env.prod</code>,
        deploy VPS qua <code>deploy_vps.sh</code>, bổ sung kiểm thử
        <code>/assistant/chat/stream</code> vào <code>smoke_test_live.py</code> và test 4G Mobile.
      </td>
    </tr>
    <tr>
      <td><span class="badge b-p1">P1 · CAO</span></td>
      <td>
        <strong>Cổng <code>verify.ps1</code> trên Windows chưa đạt 100% do môi trường</strong><br/>
        Thiếu gói <code>rapidocr</code> trong <code>backend/.venv</code> (5 test OCR lỗi) và
        <code>onnxruntime 1.32.0</code> với <code>ORT_ENABLE_ALL</code> làm xác suất
        <code>SAFE_ADVISORY</code> ra <code>0,5666</code> (&lt; 0,60).
      </td>
      <td>
        Khó tự tin khi build/đóng băng cuối kỳ nếu chạy kiểm tra trên máy Windows bị đỏ 6 test, dù
        code logic thực tế vẫn đúng trên Linux/Docker.
      </td>
      <td>
        Cài đủ gói <code>backend/requirements.txt</code> vào <code>.venv</code> hoặc chạy
        <code>verify.sh</code> trong Docker Linux giống hệt VPS thật; đánh giá dùng
        <code>ORT_ENABLE_BASIC</code> trong <code>onnx_session.py</code> (đã kiểm chứng khôi phục
        xác suất <code>0,7156</code> và nhanh hơn).
      </td>
    </tr>
    <tr>
      <td><span class="badge b-p1">P1 · CAO</span></td>
      <td>
        <strong>Đồng bộ Git &amp; kiểm tra tệp <code>.zip</code> sạch</strong><br/>
        Nhánh <code>v3</code> đã đồng bộ lên <code>origin/v3</code>; cần kiểm tra lại phạm vi đóng
        gói để không lọt file thừa hay cấu hình cục bộ.
      </td>
      <td>
        Nguy cơ thiếu đồng bộ giữa mã nguồn nộp bài (.zip), nhánh Git lưu trữ và bản chạy trên
        server nếu quên push hoặc đóng gói nhầm.
      </td>
      <td>
        Hoàn tất push mọi cập nhật mới nhất lên <code>origin/v3</code>; chạy
        <code>scripts/package_submission.py</code> và giải nén kiểm thử sang một thư mục sạch để
        chắc chắn không lọt <code>.env</code>, <code>.db</code> hay file nháp.
      </td>
    </tr>
    <tr>
      <td><span class="badge b-p2">P2 · NÊN LÀM</span></td>
      <td>
        <strong>Còn sót 1 vài chỗ thuật ngữ &amp; cạnh nhỏ trên UI/Pipeline</strong><br/>
        <code>AssistantDrawer.tsx</code> &amp; <code>AssistantEvidenceCard.tsx</code> còn chữ
        <code>Soundbox</code> / <code>Radar cộng đồng</code>; <code>detectEvidenceAttachmentKind</code>
        chưa chặn <code>.svg</code>; <code>EvidenceTabs.tsx</code> chưa reset tab theo
        <code>case_id</code>; <code>pipeline.py</code> chưa dùng <code>transfer_amount</code>.
      </td>
      <td>
        Không chặn luồng chính nhưng nếu giám khảo thử tải <code>.svg</code> vào khung chat, xem
        nhiều ảnh biên lai liên tiếp hoặc đọc kỹ câu chữ trong Drawer có thể thấy thiếu trau chuốt.
      </td>
      <td>
        Đồng bộ chặn <code>image/svg+xml</code> và câu chữ <em>"loa thông báo nhận tiền / Trung
        tâm giám sát"</em> trong Drawer; thêm <code>key=&#123;report.case_id&#125;</code> cho
        <code>EvidenceTabs</code>; bổ sung ngưỡng cảnh báo mềm khi số tiền lớn + đang gọi điện.
      </td>
    </tr>
    <tr>
      <td><span class="badge b-p2">P2 · NÊN LÀM</span></td>
      <td>
        <strong>Diễn giải trung thực giới hạn dữ liệu tổng hợp</strong><br/>
        Kết quả 40/40 trên tập mẫu tổng hợp dễ bị giám khảo chất vấn nếu trình bày như độ chính xác
        thực tế 100%.
      </td>
      <td>
        Ban giám khảo kỹ thuật fintech đánh giá rất cao sự trung thực khoa học và dễ trừ điểm nếu
        đội thi "thổi phồng" số liệu demo.
      </td>
      <td>
        Nhấn mạnh trong Slide &amp; Q&amp;A: 100% dữ liệu tổng hợp để bảo mật thông tin người
        dùng; nêu rõ tỷ lệ nhận diện thực tế trên tập khó tách nhóm (<code>Macro-F1 = 0,9314</code>,
        OCR <code>CER = 0,1096</code>) như một điểm mạnh về tính kỷ luật.
      </td>
    </tr>
  </tbody>
</table>

<h2><span class="sec-num">04</span> Lộ Trình 5 Ngày Nước Rút &amp; Chuẩn Bị Q&amp;A Chung Kết</h2>
<table>
  <thead>
    <tr>
      <th style="width: 17%;">Mốc thời gian</th>
      <th style="width: 48%;">Đầu việc trọng tâm (ưu tiên Web MVP)</th>
      <th style="width: 35%;">Tiêu chí hoàn tất (Definition of Done)</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Ngày 1 (28–29/11)</strong></td>
      <td>
        Hoàn tất push nhánh <code>v3</code>; xử lý các mục P2 nhỏ nếu cần; kiểm tra
        <code>verify.sh</code> trong Docker và chạy lại
        <code>run_benchmark.py --require-live-llm</code> với model production.
      </td>
      <td>
        <code>verify</code> xanh hoàn toàn trong Docker; <code>evaluation/results.json</code> mới
        không còn alias thử nghiệm nội bộ.
      </td>
    </tr>
    <tr>
      <td><strong>Ngày 2 (30/11)</strong></td>
      <td>
        Deploy bản chính thức lên VPS (<code>verishield.joiboi.app</code>); chạy smoke test đầy đủ
        (gồm cả chatbot Trợ lý &amp; <code>/radar</code>); thử nghiệm thật trên điện thoại 4G và
        trình duyệt ẩn danh.
      </td>
      <td>
        Truy cập mượt từ 4G; thời gian phản hồi ổn định; không lỗi SSL, CORS hay mất token phiên.
      </td>
    </tr>
    <tr>
      <td><strong>Ngày 3 (01/12)</strong></td>
      <td>
        Cập nhật <code>submission/slides/index.html</code> (10 trang), <code>guide/index.html</code>
        (1 trang A4) và kịch bản video 3 phút khớp 100% giao diện &amp; số liệu mới; render PDF và
        quét thử mã QR.
      </td>
      <td>
        <code>VeriShield_AI_Slides_10p.pdf</code> đúng 10 trang, <code>UserGuide_1p.pdf</code>
        đúng 1 trang A4, mã QR mở đúng link live.
      </td>
    </tr>
    <tr>
      <td><strong>Ngày 4 (02/12)</strong></td>
      <td>
        Quay &amp; dựng video demo trực tiếp trên web thật (<strong>2 phút 45 giây – 2 phút 55
        giây</strong>, MP4 1080p); đóng gói <code>verishield-ai-source.zip</code> và test dựng
        lại từ file giải nén.
      </td>
      <td>
        Video ≤ 3:00 rõ âm thanh, thấy đủ 3 phần: Nhập kiểm tra → Trợ lý VeriShield → Giám sát
        <code>/radar</code>.
      </td>
    </tr>
    <tr>
      <td><strong>Ngày 5 (03/12)</strong></td>
      <td>
        Kiểm tra lại toàn bộ 4 tệp nộp, tải lên cổng nộp bài cuộc thi <strong>trước 18:00</strong>,
        chụp biên nhận và <strong>đóng băng</strong> hoàn toàn mã nguồn/deploy đến hết 11/12/2026.
      </td>
      <td>
        Nộp đủ 4 hạng mục đúng hạn 03/12; hệ thống live chạy ổn định phục vụ chấm vòng loại
        (08/12) và chung kết (11/12).
      </td>
    </tr>
  </tbody>
</table>

<div class="callout callout-amber">
  <div class="callout-title">
    Trọng tâm trả lời Ban Giám Khảo khi thuyết trình &amp; Q&amp;A (tránh lan man kỹ thuật)
  </div>
  <ul class="compact">
    <li>
      <strong>"Điểm khác biệt so với hỏi ChatGPT/Gemini bình thường?"</strong> → Gemini trả lời
      chung chung và dễ bị đánh lừa bởi ảnh giả hay prompt injection. VeriShield AI kết hợp kiểm
      chứng kỹ thuật xác định (EMVCo VietQR, ELA, kiểm tra URL chống SSRF), mô hình E5 chuyên biệt
      cho tiếng Việt, nút tạm dừng 30 giây theo ngữ cảnh cuộc gọi và nguyên tắc không khẳng định tiền
      đã về từ ảnh biên lai.
    </li>
    <li>
      <strong>"Tại sao dùng E5-Small INT8 + RapidOCR nhẹ thay vì model lớn?"</strong> → Để toàn hệ
      thống chạy gọn trên 1 máy chủ 4 GB RAM với độ trễ ~10 ms cho phân loại, tự duy trì hoạt động
      nội bộ khi API AI bên ngoài gián đoạn và bảo vệ dữ liệu người dùng tốt hơn.
    </li>
    <li>
      <strong>"Độ tin cậy thực tế ra sao khi dùng dữ liệu tổng hợp?"</strong> → Dữ liệu tổng hợp
      giúp tuân thủ 100% bảo mật PII trong giai đoạn thi; chúng tôi tách hoàn toàn tập đánh giá
      theo nhóm câu và công bố thẳng độ chính xác theo từng lớp (<code>Macro-F1 = 0,9314</code>,
      RAG <code>R@3 = 98,4%</code>, <code>OOD Reject = 100%</code>) thay vì phóng đại.
    </li>
  </ul>
</div>

</body>
</html>
"""


def main() -> int:
    OUTPUT_PDF.parent.mkdir(parents=True, exist_ok=True)
    html_content = _build_html()

    with sync_playwright() as pw:
        browser = _launch_chromium(pw)
        try:
            page = browser.new_page(viewport={"width": 794, "height": 1123})
            page.set_content(html_content, wait_until="load")
            page.pdf(
                path=str(OUTPUT_PDF),
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template="<div></div>",
                footer_template=(
                    "<div style='width:100%;font-size:8px;color:#64748b;"
                    "padding:0 13mm;display:flex;justify-content:space-between;'>"
                    "<span>VeriShield AI — Đánh giá Điểm tốt, Tồn đọng &amp; Kế hoạch Cải thiện</span>"
                    "<span>Trang <span class='pageNumber'></span> / "
                    "<span class='totalPages'></span></span></div>"
                ),
                margin={"top": "12mm", "right": "12mm", "bottom": "15mm", "left": "12mm"},
            )
            page.close()
        finally:
            browser.close()

    reader = PdfReader(str(OUTPUT_PDF))
    num_pages = len(reader.pages)
    first_text = reader.pages[0].extract_text() or ""
    if num_pages < 2 or "VeriShield AI" not in first_text:
        raise RuntimeError(f"Generated PDF validation failed (pages={num_pages}).")

    size_kb = OUTPUT_PDF.stat().st_size / 1024.0
    print(f"Generated {OUTPUT_PDF} ({num_pages} pages, {size_kb:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
