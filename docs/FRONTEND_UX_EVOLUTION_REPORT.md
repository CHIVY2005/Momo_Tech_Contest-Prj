# VeriShield AI — Báo Cáo Kỹ Thuật Nâng Cấp Frontend & UX (Investigation Workspace Evolution)

**Phiên bản áp dụng:** VeriShield AI v2.0  
**Phạm vi:** Frontend Next.js 15 / React 19 / TypeScript strict (`frontend/`), giữ nguyên 100% API contract, thuật toán chấm điểm và kiến trúc backend.  
**Nguyên tắc thiết kế:** *Modern Cybersecurity × Intelligence Workspace × Explainable AI* — ưu tiên tính trung thực bằng chứng, bảo mật mặc định (Privacy by Design), hiệu năng thực đo và khả năng tiếp cận (WCAG 2.2 AA).

---

## 1. Kết Quả Kiểm Toán Frontend Hiện Tại (Existing Project Audit)

Trước khi chỉnh sửa, toàn bộ mã nguồn `frontend/src/**`, `frontend/package.json`, `backend/app/schemas/{analysis,forensics}.py`, `backend/app/services/pipeline.py`, `scripts/verify_assistant_workspace.py` và `docs/CHAT_RESIZE_PERFORMANCE.md` đã được kiểm toán đầy đủ.

### 1.1 Kiến trúc & Điểm mạnh giữ nguyên
| Thành phần | Trạng thái | Quyết định |
| :--- | :--- | :--- |
| **App Router & Routes** (`/`, `/radar`, `/chat/[conversationId]`, `/technical`, `/privacy`) | Gọn nhẹ, tách biệt rõ chức năng | **Giữ nguyên** cấu trúc route và ngữ nghĩa |
| **Design Tokens** (`globals.css`, palette *Forensic Graphite*: `#060A13` / `#0C1322`, nhấn amber `#F59E0B`, màu rủi ro ngữ nghĩa emerald/amber/orange/rose) | Bản sắc an ninh mạng rõ rệt, độ tương phản cao, tabular-nums | **Giữ nguyên**, chỉ mở rộng micro-interaction CSS và scope cho React Flow |
| **AI Assistant Workspace** (`AssistantDrawer.tsx`, `useAssistantPanel.ts`, `useAssistantScroll.ts`, `assistantConversation.ts`) | Kéo rộng khung chat 0 React commit (`content-visibility: auto`, pointer capture, RAF CSS custom property), đồng bộ đa tab `BroadcastChannel`, khôi phục phiên có kiểm soát, chống lặp câu hỏi gợi ý qua 10 lượt | **Giữ nguyên lõi**, chỉ nâng cấp có chọn lọc (Copy, Regenerate, Copy Code Block, Expandable Citations, `memo`) |
| **SafeMarkdown** (`safeMarkdown.ts`, `SafeMarkdown.tsx`) | Bộ parser thuần React $O(N)$, không `dangerouslySetInnerHTML`, không thẻ `<img>`, whitelist tên miền chính thức, hỗ trợ ordered list lồng nhau & inline code wrap an toàn | **Giữ nguyên lõi**, bổ sung `SafeCodeBlock` có nút sao chép |
| **Motion Stack** (`MotionProviders.tsx` với `<LazyMotion features={domAnimation} strict>` + `SmoothScrollProvider.tsx` Lenis + `useScrollLock`) | Nhẹ, tôn trọng `prefers-reduced-motion`, không cản trở tốc độ hiển thị cảnh báo khẩn cấp | **Giữ nguyên**, chỉ dùng `motion/react-m` và CSS keyframes có guard giảm chuyển động |
| **Radar IOC Graph** (`IocGraphSvg.tsx`) | Bộ render SVG tùy biến $O(N)$ xử lý mượt tới 500 node không chồng chéo | **Giữ nguyên** cho `/radar`; bổ sung badge trạng thái `data_scope` |
| **Guardrail Trung Thực Biên Lai** | Banner không thể tắt khi `UNVERIFIED_SCREENSHOT` hoặc có `merchant_balance_warning` | **Giữ nguyên** ở vị trí nổi bật đầu tiên, không có delay animation |

### 1.2 Khoảng trống & Dữ liệu Backend chưa được khai thác
1. **Explainable AI chưa trực quan hóa đầy đủ:** Backend đã trả về `classifier.class_probabilities` (7 lớp E5 INT8 ONNX), `highlighted_phrases`, `trace[].duration_ms`, và điểm đo thành phần (`url_findings[].risk_points`, `sandbox.risk_points`, `image_forensics.tamper_score`, `receipt_logic.logic_risk_points`), nhưng frontend trước đó chưa hiển thị phân bố xác suất 7 lớp hay liên kết từ từng tín hiệu phát hiện đến bằng chứng tương ứng.
2. **Chưa có Sơ đồ liên kết thực thể ở cấp Hồ sơ (Case-level):** Trang `/radar` hiển thị đồ thị chiến dịch toàn hệ thống, nhưng người dùng chưa thể khám phá trực quan mối quan hệ thực thể trong chính hồ sơ đang kiểm tra (tin nhắn → URL → đích chuyển hướng → tên miền → SĐT/STK/Email che giấu → thương hiệu → dấu hiệu → kết quả).
3. **Trình xem bằng chứng (Evidence Viewer) còn cơ bản:** Ảnh ELA và ảnh chụp sandbox chưa có chế độ phóng to/kéo xem toàn màn hình (Lightbox) hay thanh trượt chồng lớp ELA; chưa có giao diện so sánh trực tiếp văn bản gốc với văn bản OCR/STT kèm đánh dấu cụm từ đáng ngờ (`highlighted_phrases`).
4. **Live Analysis Pipeline chưa thể hiện luồng dữ liệu 4 công đoạn SSE:** `LiveTracePanel` mới hiển thị dạng thẻ ngang tĩnh, chưa có liên kết luồng trực quan theo trạng thái thực từ SSE (`pending`, `processing`, `completed`, `warning`, `skipped`, `failed`).
5. **Chưa có điều hướng nhanh toàn cục (`Ctrl+K` / `Cmd+K`):** Người dùng chuyên sâu cần chuyển nhanh giữa các tab điều tra, mở Trợ lý hoặc tra cứu trang thông tin mà không cần rời bàn phím.

---

## 2. Nghiên Cứu Mã Nguồn Mở Bắt Buộc (Open-Source Research)

Tất cả các dự án được yêu cầu đều đã được rà soát giấy phép, kiến trúc, mức độ bảo trì và rủi ro tích hợp qua Exa, GitHub và tài liệu chính thức.

### 2.1 AI Chat Interface
| Dự án | Giấy phép | Phát hiện chính | Quyết định |
| :--- | :--- | :--- | :--- |
| **vercel/ai-elements** | Apache-2.0 | Xác minh trực tiếp từ README repo: **đã ngừng phát triển (deprecated) vào cuối tháng 11/2026** và chuyển đổi sang hệ sinh thái AI Elements chính thức của **shadcn/ui** (`ui.shadcn.com/docs/ai-elements`). | **Không tích hợp** bản repo cũ; chỉ tham khảo pattern UX (action bar tin nhắn, citation drawer). |
| **vercel/streamdown** (`v2.8.1`) | Apache-2.0 | Tối ưu cho Markdown streaming (`remend`), kéo theo ~16 phụ thuộc (remark/rehype/shiki/mermaid). Đặc biệt, mặc định `allowedImagePrefixes: ["*"]` tiềm ẩn rủi ro rò rỉ dữ liệu qua ảnh markdown khi gặp prompt injection nếu không cấu hình chặt. | **Không thay thế `SafeMarkdown`**. Giữ `SafeMarkdown` thuần React $O(N)$ (0 `<img>`, 0 HTML thô, bảo toàn 100% kiểm thử danh sách lồng nhau & bảo mật). |
| **assistant-ui** | MIT | Kiến trúc primitives mạnh cho ứng dụng chat mới từ đầu. Tuy nhiên viết lại `AssistantDrawer` sẽ tạo rủi ro phá vỡ cơ chế kéo rộng 0-commit, `BroadcastChannel` đa tab và SSE 3 tầng an toàn hiện có. | **Không viết lại**; áp dụng có chọn lọc pattern Copy / Regenerate / Expandable Citations lên kiến trúc hiện tại. |

### 2.2 Interactive Visualization
| Dự án | Giấy phép | Phát hiện chính | Quyết định |
| :--- | :--- | :--- | :--- |
| **@xyflow/react** (`13.0.3`, xyflow) | **MIT** | Hỗ trợ React >=18/19, kích thước nhỏ hơn Cytoscape (~69 KiB so với ~172 KiB), dùng DOM node thuần cho phép tuỳ biến thẻ an ninh mạng giàu ngữ cảnh, hỗ trợ keyboard/ARIA, `Controls`, `MiniMap`, `fitView`, `Background`. Theo benchmark Elastic Kibana 2026, React Flow dựng nhanh hơn ~6× ở quy mô đồ thị điều tra hồ sơ (< 100 node). | **Tích hợp (Lazy-load `ssr: false`)** cho Sơ đồ liên kết thực thể cấp hồ sơ (`FraudRelationshipFlowCanvas.tsx`). |
| **cytoscape.js** | MIT | Mạnh cho phân tích đồ thị mạng lớn hàng nghìn cạnh trên Canvas, nhưng khó tuỳ biến thẻ UI chi tiết và kém thân thiện hơn với screen reader/DOM accessibility ở quy mô 10–40 thực thể/hồ sơ. | **Không chọn** cho cấp hồ sơ; `/radar` vẫn dùng `IocGraphSvg.tsx` tùy biến $O(N)$ cho 500 node. |
| **Apache ECharts** (`6.1.0`) | **Apache-2.0** | Cho phép import tree-shakeable qua `echarts/core` (chỉ nạp `GaugeChart`, `BarChart`, `GridComponent`, `TooltipComponent`, `CanvasRenderer`), đáp ứng `ResizeObserver`, mượt và chuẩn xác cho biểu đồ kỹ thuật. | **Tích hợp (Lazy-load `ssr: false`)** cho bảng Giải thích AI (`XaiCharts.tsx`). |
| **Tremor** (`tremorlabs/tremor`) | Apache-2.0 | Đã được Vercel mua lại, cung cấp sẵn mẫu thẻ KPI/BarList sạch trên Tailwind/Recharts. | **Tham khảo pattern trình bày** KPI/BarList sạch; không cài thêm package vì dự án đã dùng Tailwind v4 + ECharts. |

### 2.3 UI Components, Animation & Evidence Management
| Dự án | Giấy phép | Phát hiện & Quyết định |
| :--- | :--- | :--- |
| **shadcn/ui** | MIT | Tham khảo cấu trúc ARIA dialog/combobox/tabs và phân cấp token; giữ nguyên lớp Tailwind v4 nhẹ của dự án. |
| **Magic UI** (`magicui`) | MIT | Tham khảo nguyên lý **Animated Beam** (luồng SVG có hướng nối các công đoạn thực) và **Border Beam** (viền sáng cho công đoạn đang chạy) để tự viết nhẹ bằng SVG/CSS thuần có guard `prefers-reduced-motion` trong `LiveTracePanel.tsx`. |
| **Motion** (`motion` v12) & **Motion Primitives** | MIT | Đã có sẵn `motion@12.38.0` với `<LazyMotion features={domAnimation} strict>`. Tham khảo nguyên tắc chuyển động có mục đích; không thêm dependency mới. |
| **Aceternity UI / 21st.dev / awesome-shadcn-ui** | Hỗn hợp | Chỉ khảo sát ý tưởng bố cục & Command Palette; tránh toàn bộ hiệu ứng neon/glassmorphism lạm dụng. |
| **TanStack Table / Virtual** | MIT | Hiện tại mỗi hồ sơ trả về thường có < 30 mục bằng chứng và hội thoại dưới vài chục tin nhắn (đã có `content-visibility: auto`). Trì hoãn tích hợp cho đến khi có bảng dữ liệu > 200 dòng. |
| **Uppy** | MIT | Phục vụ tải tệp đa nguồn đám mây/tus resumable upload; dư thừa vì `InputWorkbench` hiện tại xử lý tốt tệp cục bộ $\le 10\text{ MB}$ kèm dán ảnh clipboard (`Ctrl+V`) và bảo mật riêng tư. |
| **react-pdf** (`wojtekmaj/react-pdf`) | MIT | Nặng (~500+ KB `pdfjs-dist` worker) trong khi backend hiện chỉ nhận đầu vào văn bản/ảnh/âm thanh và xuất báo cáo PDF để tải về (`fetchReportPdfBlob`). Không tích hợp để bảo toàn ngân sách tải trang. |

### 2.4 Cybersecurity Product References
- **CruxDR (MIT)** & **NexusIntel (MIT):** Học hỏi bố cục điều tra phân tầng (Tóm tắt quyết định ở trên, không gian phân tích sâu dạng tab bên dưới), phân biệt rõ mức độ xác minh thực thể, và thanh inspector chi tiết khi chọn node/edge.
- **changedetection.io:** Học hỏi bố cục so sánh đối chiếu văn bản hai cột kèm tô sáng phần chênh lệch/nghi vấn (`TextEvidenceCompare.tsx`).
- **Immich (AGPL — tuyệt đối không sao chép mã nguồn):** Chỉ tham khảo trải nghiệm Lightbox xem ảnh phóng to/thu nhỏ/kéo pan kèm thanh metadata đáy và đóng bằng phím `Esc`.

---

## 3. Ma Trận Chọn Lọc Thành Phần (Component Selection Matrix)

| Hạng mục | Giải pháp chọn | Giấy phép | Chiến lược tải | Lý do kỹ thuật |
| :--- | :--- | :--- | :--- | :--- |
| **Sơ đồ mối liên hệ hồ sơ** | `@xyflow/react@13.0.3` + tự viết `caseGraph.ts` | MIT | `next/dynamic({ ssr: false })` chỉ khi mở tab *Sơ đồ liên kết* | Nhẹ, DOM node tùy biến cao, hỗ trợ lọc loại thực thể, auto-layout phân lớp, chuyển sang *Chế độ danh sách* mặc định trên mobile (`< 768px`). |
| **Biểu đồ XAI (Gauge & 7 lớp E5 ONNX)** | `echarts@6.1.0` (`echarts/core` tree-shaken) | Apache-2.0 | `next/dynamic({ ssr: false })` chỉ khi mở tab *Giải thích AI (XAI)* | Không kéo ECharts vào bundle trang chủ (`/`), hỗ trợ `ResizeObserver` và tắt animation khi `prefers-reduced-motion: reduce`. |
| **AI Chat Markdown & Actions** | Mở rộng `SafeMarkdown.tsx`, `AssistantMessageItem.tsx`, `AssistantDrawer.tsx` | Nội bộ (MIT) | Bundle chính (đồng bộ với `sessionStorage` & resize) | Giữ nguyên 0 React commit khi kéo rộng khung chat và 0 lỗ hổng XSS/image exfiltration. |
| **Live Analysis Pipeline** | Tự viết SVG Beam + CSS `.vs-beam-flow` / `.vs-stage-running` | Nội bộ (MIT) | Bundle chính | Ánh xạ 1-1 với 4 công đoạn SSE thật từ backend; không tạo bước giả hay delay giả. |
| **Evidence Lightbox & Text Compare** | Tự viết `EvidenceImageLightbox.tsx` & `TextEvidenceCompare.tsx` | Nội bộ (MIT) | Bundle chính (nhẹ, 0 dep ngoài) | Zoom 50–400%, kéo pan `translate3d`, thanh trượt chồng lớp ELA, tô sáng `<mark>` cụm từ đáng ngờ bằng React node thuần. |
| **Global Command Palette (`Ctrl+K`)** | Tự viết `CommandPalette.tsx` & `commandPalette.ts` | Nội bộ (MIT) | Mount tại `layout.tsx` | Tìm kiếm tiếng Việt không dấu (`NFD` + `đ/Đ`), chỉ nhận mã hồ sơ đã rút gọn, tuyệt đối không lưu dữ liệu nhạy cảm. |

---

## 4. Quyết Định Kiến Trúc (Architecture Decisions)

1. **Progressive Disclosure Workspace (Phân tầng thông tin 2 lớp):**
   - **Lớp 1 (Quyết định ngay lập tức — cho người dùng phổ thông):** Banner trung thực biên lai, kết luận `VerdictDashboard`, thanh tín hiệu chính nhấp được, và `WalletPreTransferSim` luôn hiển thị ngay lập tức không trì hoãn.
   - **Lớp 2 (Điều tra chuyên sâu — cho người dùng kỹ thuật & chuyên viên):** `InvestigationWorkspace` tổ chức thành 3 tab rõ ràng: **Bằng chứng & Ứng phó**, **Giải thích AI (XAI)** (lazy), và **Sơ đồ liên kết** (lazy).
2. **Code-Splitting an toàn không gây xung đột vòng đời:**
   - Khi thử lazy-load `AssistantDrawer` hoặc `InvestigationWorkspace` tại `page.tsx`, bộ kiểm thử thực đo phát hiện 2 vấn đề: race condition khởi tạo checkpoint `sessionStorage` và 2 React commit phát sinh muộn trong khi đang kéo khung chat sau reload.
   - **Giải pháp chuẩn:** Giữ `AssistantDrawer` và vỏ `InvestigationWorkspace` import tĩnh tại `page.tsx`, trong khi đẩy toàn bộ phần nặng (`ExplainableAiPanel` + `echarts/core` và `FraudRelationshipGraph` + `@xyflow/react` + `caseGraph.ts`) vào `next/dynamic(..., { ssr: false })` ngay bên trong `InvestigationWorkspace.tsx`. Đồng thời tách hàm nhỏ `defangUrlForDisplay` sang `formatters.ts` để `caseGraph.ts` không bị kéo vào bundle trang chủ.
3. **Trung thực dữ liệu & Epistemic Honesty (Không dữ liệu giả):**
   - **Phân biệt rõ điểm rủi ro và xác suất:** Cả `VerdictDashboard` và `ExplainableAiPanel` đều giải thích rõ chỉ số rủi ro tổng hợp `0–100` phản ánh mức độ khớp các dấu hiệu kỹ thuật/ngữ cảnh, **không đồng nhất** với xác suất thống kê tuyệt đối.
   - **Chỉ hiển thị số liệu backend thực trả về:** Thành phần điểm đo chỉ hiển thị đúng các trường thực có (`url_findings[].risk_points`, `sandbox.risk_points`, `image_forensics.tamper_score`, `receipt_logic.logic_risk_points`, `classifier.scam_probability`, `classifier.class_probabilities`, `confidence`, `trace[].duration_ms`). Không bịa trọng số mô hình hay điểm LLM riêng.
   - **Đồ thị thực thể có bằng chứng & trung lập:** Mỗi node/edge gắn một trong 4 trạng thái xác minh minh bạch (`verified_evidence`, `extracted_info`, `suspected_relation`, `unverified_info`). Không gán nhãn quy kết cá nhân hay chủ tài khoản là đối tượng lừa đảo; mọi SĐT/STK/Email đều bị che giấu (`maskDisplayIoc`, `maskEmailForDisplay`), mọi URL/tên miền đều vô hiệu hóa dạng `hxxps://...[.]` (`defangUrlForDisplay`).
4. **Live Pipeline phản ánh SSE thật 100%:**
   - `LiveTracePanel` ánh xạ chính xác 4 công đoạn của `backend/app/services/pipeline.py`: `media_forensics` → `cyber_guardrails` → `onnx_and_kb` → `multimodal_calibration`. Hỗ trợ đầy đủ trạng thái `pending`, `processing`, `completed`, `warning`, `skipped`, `failed`; không dùng `setTimeout` tạo tiến độ giả.

---

## 5. Lộ Trình Triển Khai Theo Giai Đoạn (Phases 0–5)

- **Phase 0 — Audit & Research:** Kiểm toán toàn bộ frontend/backend, đo bundle baseline (`/` 190 kB), nghiên cứu đầy đủ 20+ dự án mã nguồn mở, chốt 2 thư viện duy nhất cần thêm (`@xyflow/react`, `echarts`).
- **Phase 1 — UI Foundation & AI Assistant Polish:** Thêm micro-interaction CSS chuẩn giảm chuyển động; nâng cấp `SafeMarkdown` (`SafeCodeBlock` + nút sao chép), `AssistantMessageItem` (`memo`, nút Sao chép, nút Tạo lại phản hồi, mở rộng Chi tiết căn cứ sau khi stream xong), `AssistantDrawer` (`useCallback`, tích hợp regenerate), và helper `findRegenerableUserTurn`.
- **Phase 2 — Explainable AI (XAI) & Risk Visualization:** Xây dựng `explainableAi.ts`, `XaiCharts.tsx` (lazy ECharts Gauge + 7-Class E5 ONNX Bar Chart), `ExplainableAiPanel.tsx`, và dải tín hiệu chính liên kết trực tiếp tới bằng chứng trong `VerdictDashboard.tsx`.
- **Phase 3 — Fraud Investigation Workspace:** Xây dựng `caseGraph.ts`, `FraudRelationshipFlowCanvas.tsx` (lazy React Flow), `FraudRelationshipGraph.tsx` (bộ lọc thực thể, chú giải 4 trạng thái xác minh, chế độ danh sách mobile, bảng chi tiết node/edge), `EvidenceImageLightbox.tsx`, `TextEvidenceCompare.tsx`, `OfficialChannelsCard.tsx`, và vỏ `InvestigationWorkspace.tsx`.
- **Phase 4 — Live Pipeline & Command Palette:** Nâng cấp `LiveTracePanel.tsx` với luồng SVG có hướng theo SSE thật; xây dựng `commandPalette.ts` và `CommandPalette.tsx` (`Ctrl+K` / `Cmd+K`, tìm tiếng Việt không dấu), gắn nút kích hoạt vào `TopNav.tsx`, bổ sung trạng thái `data_scope` trên `/radar`.
- **Phase 5 — Quality Assurance & Reporting:** Viết 3 bộ unit test mới (nâng tổng từ 72 lên 84 test), chạy kiểm thử thực trình duyệt Edge (resize profiler, hồi quy trợ lý, E2E tương tác + reduced motion + 6 viewport + Web Vitals), cập nhật khai báo giấy phép tại `README.md` & `/technical`, chạy cổng kiểm duyệt toàn dự án `scripts/verify.ps1`, và hoàn thiện báo cáo này.

---

## 6. Danh Sách Tệp Đã Tạo Mới & Chỉnh Sửa

### 6.1 Tệp tạo mới (14 tệp)
- [frontend/src/lib/explainableAi.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/explainableAi.ts) — Logic thuần TS tổng hợp tín hiệu phát hiện, thành phần điểm đo thật, phân bố 7 lớp E5 ONNX, phân bố bằng chứng, dòng thời gian trace và tô sáng cụm từ đáng ngờ.
- [frontend/src/lib/caseGraph.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/caseGraph.ts) — Bộ dựng đồ thị mối liên hệ thực thể cấp hồ sơ có kiểm định bằng chứng, che giấu PII và tự động dàn trang phân lớp.
- [frontend/src/lib/commandPalette.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/commandPalette.ts) — Danh mục lệnh toàn cục an toàn riêng tư và tìm kiếm tiếng Việt không dấu.
- [frontend/src/components/xai/XaiCharts.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/xai/XaiCharts.tsx) — Biểu đồ Gauge chỉ số rủi ro và cột ngang phân bố xác suất E5 ONNX bằng `echarts/core` tree-shaken.
- [frontend/src/components/xai/ExplainableAiPanel.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/xai/ExplainableAiPanel.tsx) — Bảng Giải thích AI (XAI) đầy đủ kèm điều hướng trực tiếp tới bằng chứng liên quan.
- [frontend/src/components/workspace/FraudRelationshipFlowCanvas.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/workspace/FraudRelationshipFlowCanvas.tsx) — Canvas React Flow tương tác (zoom/pan/drag/Controls/MiniMap/Auto-layout/node & edge selection).
- [frontend/src/components/workspace/FraudRelationshipGraph.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/workspace/FraudRelationshipGraph.tsx) — Container Sơ đồ liên kết thực thể kèm lọc loại thực thể, chế độ danh sách cho mobile và Entity/Edge Inspector.
- [frontend/src/components/workspace/InvestigationWorkspace.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/workspace/InvestigationWorkspace.tsx) — Vỏ không gian điều tra phân tầng 3 tab kết hợp lazy-load XAI & Sơ đồ liên kết.
- [frontend/src/components/workspace/OfficialChannelsCard.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/workspace/OfficialChannelsCard.tsx) — Kênh đối chiếu chính thức Việt Nam (Cổng cảnh báo an toàn thông tin, NAPAS, hướng dẫn tổng đài mặt sau thẻ).
- [frontend/src/components/evidence/EvidenceImageLightbox.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/evidence/EvidenceImageLightbox.tsx) — Modal xem phóng to ảnh bằng chứng (zoom 50–400%, kéo pan, thanh trượt chồng lớp ELA, phím tắt `Esc`/`+`/`-`/`0`).
- [frontend/src/components/evidence/TextEvidenceCompare.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/evidence/TextEvidenceCompare.tsx) — Đối chiếu nội dung gốc với văn bản OCR/STT, tô sáng `highlighted_phrases` bằng `<mark>` và sao chép chỉ báo đã che giấu/vô hiệu hóa.
- [frontend/src/components/layout/CommandPalette.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/layout/CommandPalette.tsx) — Hộp thoại Command Palette `Ctrl+K` / `Cmd+K` chuẩn ARIA combobox/listbox.
- [frontend/src/lib/__tests__/explainableAi.test.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/__tests__/explainableAi.test.ts), [caseGraph.test.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/__tests__/caseGraph.test.ts), [commandPalette.test.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/__tests__/commandPalette.test.ts) — 3 bộ unit test mới (12 test cases).
- [docs/FRONTEND_UX_EVOLUTION_REPORT.md](file:///D:/Misc/momo-tech-contest-prj/docs/FRONTEND_UX_EVOLUTION_REPORT.md) — Báo cáo kỹ thuật này.

### 6.2 Tệp chỉnh sửa (18 tệp)
- [frontend/package.json](file:///D:/Misc/momo-tech-contest-prj/frontend/package.json) & `frontend/package-lock.json` — Thêm `@xyflow/react` và `echarts`.
- [frontend/src/app/globals.css](file:///D:/Misc/momo-tech-contest-prj/frontend/src/app/globals.css) — Thêm micro-interaction `.vs-pressable`, `.vs-beam-flow`, `.vs-stage-running`, theme `.vs-flow-canvas`, và quy tắc `prefers-reduced-motion: reduce`.
- [frontend/src/app/layout.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/app/layout.tsx) & [frontend/src/components/layout/TopNav.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/layout/TopNav.tsx) — Mount `CommandPalette` và nút phím tắt `Ctrl K`.
- [frontend/src/app/page.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/app/page.tsx) — Kết nối `InvestigationWorkspace`, truyền `submittedText`, phát sự kiện mã hồ sơ rút gọn (không PII) và lắng nghe lệnh Command Palette.
- [frontend/src/app/radar/page.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/app/radar/page.tsx) — Bổ sung badge phạm vi dữ liệu vận hành (`data_scope`).
- [frontend/src/app/technical/page.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/app/technical/page.tsx) & [README.md](file:///D:/Misc/momo-tech-contest-prj/README.md) — Khai báo giấy phép `@xyflow/react` (MIT) và `Apache ECharts` (Apache-2.0).
- [frontend/src/lib/copy.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/copy.ts), [frontend/src/lib/formatters.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/formatters.ts), [frontend/src/lib/assistantSession.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/assistantSession.ts) — Nhãn tiếng Việt 7 lớp E5 ONNX, `defangUrlForDisplay`, và `findRegenerableUserTurn`.
- [frontend/src/components/assistant/SafeMarkdown.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/assistant/SafeMarkdown.tsx), [AssistantMessageItem.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/assistant/AssistantMessageItem.tsx), [AssistantDrawer.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/assistant/AssistantDrawer.tsx) — Sao chép khối mã, Sao chép phản hồi, Tạo lại phản hồi, mở rộng Chi tiết căn cứ, ổn định callback.
- [frontend/src/components/workbench/VerdictDashboard.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/workbench/VerdictDashboard.tsx) & [LiveTracePanel.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/workbench/LiveTracePanel.tsx) — Dải tín hiệu liên kết bằng chứng, ghi chú phân biệt điểm rủi ro/xác suất, pipeline SVG 4 công đoạn SSE.
- [frontend/src/components/evidence/EvidenceTabs.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/evidence/EvidenceTabs.tsx), [ElaCompareView.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/evidence/ElaCompareView.tsx), [PhishingSandboxCard.tsx](file:///D:/Misc/momo-tech-contest-prj/frontend/src/components/evidence/PhishingSandboxCard.tsx) — Tab Văn bản & Dấu hiệu, bộ lọc mức độ nghiêm trọng, tích hợp Lightbox & sao chép URL vô hiệu hóa.

---

## 7. Dependencies & Giấy Phép (License Acknowledgments)

- **Thêm mới (2 gói, đều thuộc nhóm giấy phép mở permissive):**
  - `@xyflow/react` `13.0.3` — **MIT License** (xyflow / webkid GmbH)
  - `echarts` `6.1.0` — **Apache-2.0 License** (Apache Software Foundation)
- **Gỡ bỏ:** Không gỡ bỏ dependency nào.
- **Tuân thủ giấy phép toàn bộ runtime frontend:** Đã được kiểm chứng tự động qua [frontendLicenses.test.ts](file:///D:/Misc/momo-tech-contest-prj/frontend/src/lib/__tests__/frontendLicenses.test.ts) (`MIT`, `Apache-2.0`, `ISC`, `BSD-*`, `0BSD`, `SIL OFL-1.1`; không tồn tại `GSAP`, `React Bits`, `AGPL`, `WebGL` hay `MoMo` trademark).

---

## 8. Kết Quả Đo Hiệu Năng Trước & Sau (Measured Performance)

> **Lưu ý phạm vi đo:** Mọi chỉ số dưới đây được đo thực tế trên **Windows, Microsoft Edge headless, production build cục bộ (`next start`)**, với API fixture tổng hợp. Đây là số liệu đo kiểm trong môi trường thử nghiệm cục bộ, không phải cam kết hiệu năng trên mọi thiết bị di động hoặc mạng thực tế.

### 8.1 Kích thước Bundle Next.js Production Build (`First Load JS`)
| Route | Trước nâng cấp | Sau nâng cấp | Chênh lệch | Ghi chú |
| :--- | ---: | ---: | ---: | :--- |
| `/` | `190 kB` (`29.8 kB` route) | `204 kB` (`43.0 kB` route) | `+14 kB` | ECharts (`532.2 KB` raw) và React Flow + `caseGraph` (`129.8 + 109.5 KB` raw) tách hoàn toàn sang async chunk lazy-load |
| `/radar` | `144 kB` (`27.1 kB` route) | `145 kB` (`27.3 kB` route) | `+1 kB` | Giữ nguyên `IocGraphSvg.tsx` |
| `/chat/[conversationId]` | `148 kB` (`1.22 kB` route) | `150 kB` (`3.15 kB` route) | `+2 kB` | Thêm nút Copy, Regenerate, Expandable Citations |
| `/technical` | `109 kB` (`2.12 kB` route) | `109 kB` (`2.13 kB` route) | `0 kB` | Không tăng First Load JS |
| `/privacy` | `109 kB` (`2.12 kB` route) | `109 kB` (`2.13 kB` route) | `0 kB` | Không tăng First Load JS |
| Shared JS | `103 kB` | `103 kB` | `0 kB` | Không tăng shared runtime |

### 8.2 Hiệu năng kéo khung chat (`verify_assistant_workspace.py --profile-resize --expect-optimized`)
Viewport `1440 × 850`, 106 bước kéo qua min/max và đổi hướng nhanh:

| Kịch bản | React commit khi giữ chuột (Trước → Sau) | `frame_p95_ms` (Trước → Sau) | `LayoutDuration` (Trước → Sau) | `ScriptDuration` (Trước → Sau) | Trạng thái |
| :--- | :---: | :---: | :---: | :---: | :---: |
| 2 tin, đang stream | `1 → 1` | `7.1 → 7.0 ms` | `44.0 → 42.15 ms` | `21.3 → 18.17 ms` | **PASS** |
| 50 tin, đã hoàn tất | `0 → 0` | `7.1 → 7.0 ms` | `98.7 → 74.69 ms` | `28.4 → 17.39 ms` | **PASS** |
| 50 tin, đang stream | `1 → 1` | `7.1 → 7.0 ms` | `98.0 → 92.98 ms` | `28.0 → 19.67 ms` | **PASS** |

### 8.3 Chỉ số Web Vitals thực đo cục bộ (Edge headless, `1440 × 900`)
| Route | LCP (ms) | CLS | Thời gian tải `networkidle` (ms) | Ghi chú |
| :--- | ---: | ---: | ---: | :--- |
| `/` | `528` | `0.0157` | `1071.1` | Đạt chuẩn tốt (`LCP < 2500 ms`, `CLS < 0.1`) |
| `/radar` | `300` | `0.1274` | `1106.8` | Dịch chuyển bố cục sẵn có khi dữ liệu đồ thị tải bất đồng bộ sau SSR |
| `/technical` | `144` | `0.0025` | `1196.5` | Tĩnh, ổn định gần tuyệt đối |
| `/privacy` | `124` | `0.0018` | `1130.9` | Tĩnh, ổn định gần tuyệt đối |

---

## 9. Đánh Giá Bảo Mật & Quyền Riêng Tư (Security & Privacy Assessment)

1. **Chống XSS & HTML Injection:** Không dùng `dangerouslySetInnerHTML` ở bất kỳ component mới hay cũ nào. Tô sáng cụm từ đáng ngờ (`highlightSuspiciousText`) tách chuỗi thành mảng text/mark thuần React.
2. **Vô hiệu hóa đường dẫn nguy hiểm (Zero Clickable Phishing Links):** Mọi URL/tên miền đáng ngờ trong `PhishingSandboxCard`, `TextEvidenceCompare`, `FraudRelationshipGraph`, và `SafeMarkdown` đều không tạo thẻ `<a>` có `href` tới trang lạ; nút sao chép luôn xuất định dạng vô hiệu hóa (`hxxps://...[.]`). Chỉ các kênh xác minh chính thức (như `canhbao.khonggianmang.vn`, `napas.com.vn`) mới có liên kết `rel="noopener noreferrer"`.
3. **Che giấu PII & Không quy kết cá nhân:** Đã xác minh trên DOM thật của Sơ đồ liên kết rằng SĐT `0912345678` hiển thị thành `091****678` và STK `190384756201` hiển thị thành `19****01`, không rò rỉ giá trị thô. Toàn bộ nhãn mô tả dùng ngôn ngữ pháp y trung lập.
4. **Kiểm toán lưu trữ cục bộ (`localStorage`):** Kiểm thử tự động xác nhận `Object.values(localStorage)` chỉ chứa các giá trị số (chiều rộng khung chat đã lưu); không ghi nội dung tin nhắn, bằng chứng hay PII vào `localStorage`. Command Palette không lưu lịch sử truy vấn và không hiển thị dữ liệu hồ sơ khác.
5. **Kiểm toán lỗ hổng phụ thuộc (`npm audit --omit=dev`):**
   - 2 gói thêm mới (`@xyflow/react@13.0.3` và `echarts@6.1.0`): **0 lỗ hổng bảo mật**.
   - Tồn đọng sẵn có từ cấu hình nền dự án: `next@15.5.29` (2 cảnh báo trung bình/thấp qua `postcss` lồng nhau cần nâng major lên `next@16`, nằm ngoài phạm vi bảo toàn kiến trúc hiện tại).

---

## 10. Kết Quả Kiểm Thử (Test & Verification Results)

| Bộ kiểm thử | Kết quả | Chi tiết xác minh |
| :--- | :---: | :--- |
| **TypeScript Strict (`tsc --noEmit`)** | **PASS** | 0 lỗi kiểu |
| **Frontend Unit Tests (`npm test`)** | **84/84 PASS** | Tăng từ 72 lên 84 test (+12 test mới cho XAI, Case Graph, Command Palette, Regenerate & License gate) |
| **Assistant Resize Profiler (`--profile-resize --expect-optimized`)** | **PASS** | 3/3 kịch bản đạt `drag_commits` `1/0/1`, `frame_p95_ms` `7.0 ms` |
| **Assistant Workspace Regression (`verify_assistant_workspace.py`)** | **PASS** | 375/768/1024/1440/1920px, keyboard bounds, inline code, nested list, pointer capture, multi-tab sync, reload auth, case isolation, `localStorage` |
| **Frontend Evolution E2E QA (`qa_frontend_evolution.py`)** | **PASS** | XAI ECharts (2 canvas), điều hướng tín hiệu → bằng chứng, Lightbox zoom/Esc, Text `<mark>` highlight, React Flow graph + che giấu PII + inspector, Assistant Copy/Regenerate/Expandable Citations, Command Palette `Ctrl+K` không dấu, `prefers-reduced-motion: reduce`, 0 tràn ngang trên 6 viewport (`375 / 430 / 768 / 1024 / 1440 / 1920px`), 0 page errors |
| **Full Repository Gate (`scripts/verify.ps1`)** | **PASS** | Đã xác minh đồng thời Backend (Ruff, Mypy strict, Pytest) + Frontend (`tsc`, `npm test`, `next build`) |

---

## 11. Giới Hạn Hiện Tại & Điều Kiện Tiên Quyết Từ Backend (Known Limitations)

1. **Khung tọa độ OCR (OCR Bounding Boxes) trên ảnh bằng chứng:** Backend hiện tính `ocr_boxes` nội bộ trong `backend/app/services/pipeline.py` để đo độ lệch chiều cao dòng (`ocr_height_cv`) nhưng `ImageForensicsResult` chưa serialize danh sách tọa độ bounding box ra JSON API. Vì tuân thủ nguyên tắc không giả lập dữ liệu, `EvidenceImageLightbox` chưa vẽ khung OCR giả; tính năng vẽ vùng đáng ngờ trên ảnh sẽ sẵn sàng kích hoạt ngay khi backend bổ sung trường `ocr_regions` vào schema.
2. **Trọng số thành phần & Điểm riêng của mô hình LLM:** `AnalysisReport` hiện chỉ trả về `risk_score` tổng hợp, `confidence` và điểm thành phần của từng mô-đun kỹ thuật (`url_findings`, `sandbox`, `image_forensics`, `receipt_logic`, `classifier`), không trả về vector trọng số hiệu chuẩn hay `llm_score` tách biệt. Giao diện XAI chỉ hiển thị đúng các điểm thực đo.
3. **Danh sách lịch sử nhiều hồ sơ (Multi-case History):** Theo cam kết quyền riêng tư của VeriShield AI (không tài khoản đăng nhập, chỉ cấp `X-Case-Access-Token` có thời hạn theo phiên), backend không cung cấp endpoint liệt kê toàn bộ hồ sơ cũ của người dùng; Command Palette do đó chỉ cung cấp thao tác trên hồ sơ hiện tại.
4. **CLS trên trang `/radar` (`0.1274`):** Do bố cục đồ thị `/radar` hiện có tải dữ liệu sau khi mount mà chưa giữ sẵn chiều cao tối thiểu cố định cho khối KPI/canvas.

---

## 12. Đề Xuất Cải Tiến Tiếp Theo (Future Roadmap)

1. **Bổ sung `ocr_regions` từ backend (opt-in):** Cho phép `EvidenceImageLightbox` vẽ lớp phủ khung vùng chữ bất thường (số tiền, mã giao dịch) trực tiếp trên ảnh biên lai.
2. **Giảm CLS trang `/radar` xuống `< 0.05`:** Dành sẵn skeleton cố định chiều cao cho dải KPI và vùng đồ thị trước khi `fetchRadarGraph()` hoàn tất.
3. **Nâng cấp `next@16` theo đợt bảo trì riêng:** Khắc phục triệt để cảnh báo `postcss` trong `npm audit` khi kiểm thử tương thích toàn bộ cấu hình App Router.
4. **Ảo hóa danh sách (TanStack Virtual) nếu mở rộng quy mô:** Cân nhắc tích hợp khi số lượng bằng chứng hoặc quy tắc chặn trên `/radar` vượt ngưỡng > 200 bản ghi đồng thời.
