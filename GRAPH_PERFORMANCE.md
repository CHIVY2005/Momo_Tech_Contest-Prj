# VeriShield AI — Graph Rendering Performance & Animation Optimization (`GRAPH_PERFORMANCE.md`)

> Tài liệu kỹ thuật ghi nhận đầy đủ quá trình tái hiện lỗi, phân tích nguyên nhân gốc (Root Cause Analysis), kiến trúc tối ưu, đánh giá thư viện đồ thị, số liệu benchmark thực đo (Before / After) trên 14–500 node và kiểm thử tương thích đa trình duyệt (Chrome, Edge, Firefox) cho component **Mạng lưới liên kết** (`IocGraphSvg`) tại trang `/radar`.

---

## 1. Tóm tắt điều hành (Executive Summary)

Qua profiling thực tế trên production build Next.js (`next start`) bằng Chrome DevTools Protocol (`Performance.getMetrics`), React Fiber commit instrumentation, `PerformanceObserver` (CLS), `MutationObserver`, rAF frame-time profiler và ghi hình trực tiếp qua Playwright trên Chrome, Edge và Firefox:

| Triệu chứng ghi nhận | Nguyên nhân gốc đã xác minh (Root Cause) | Trạng thái sau tối ưu |
|---|---|---|
| **Bóng kép / chồng hình / giật nảy khi di chuột vào nút** | Thanh trạng thái `flex-wrap` nằm **in-flow phía trên `<svg>`** giãn từ 1 dòng (`34px`) sang 3 dòng (`77.5px`, `+43.5px`) khi hiển thị tên chiến dịch dài, đẩy `<svg>` tụt xuống khỏi con trỏ → kích hoạt `onMouseLeave` → thanh co lại `-43.5px` → `<svg>` bật lên lại → `onMouseEnter`, tạo **vòng lặp dao động ~80 Hz** (`32` lần React re-render trong `200ms`, `CLS = 1.685`). | **Đã triệt tiêu hoàn toàn**: `hover_svg_y_shift_px = 0.0 px`, `hover_cls = 0.000`, `hover_react_renders = 1` (chỉ trong tooltip cô lập). |
| **Cuộn chuột zoom đồ thị nhưng trang web cũng bị cuộn theo** | React synthetic `onWheel` được gắn ở chế độ **passive** (`Unable to preventDefault inside passive event listener invocation`), làm rò rỉ `120 px` cuộn dọc (`window.scrollY`) mỗi thao tác zoom. | **Đã khắc phục**: Native listener `addEventListener("wheel", ..., { passive: false })` → `wheel_scroll_leak_px = 0 px`, `0` lỗi console passive listener trên cả Chrome, Edge và Firefox. |
| **Kéo (pan) bị giật và lệch tỷ lệ so với con trỏ** | (1) Gọi `setPan`/`setZoom` trong React state cho từng `pointermove` và `wheel` thô (`78–100` commits, `79–297 ms` script time); (2) chia pixel CSS cho `zoom` nhưng bỏ qua tỷ lệ `viewBox` (`860×480`) so với kích thước SVG thực tế → lệch `25.43 px` trên cú kéo `100×40 px`. | **Đã khắc phục**: Imperative `useRef` + gom khung hình `requestAnimationFrame` + ánh xạ đúng `preserveAspectRatio="xMidYMid meet"` → `1` lần render đồ thị duy nhất, `pan_tracking_error_px = 0.0 px` (Chrome/Edge) và `≤ 0.42 px` (sub-pixel rounding trên Firefox), giảm **60–82%** `ScriptDuration`. |
| **Node chồng lấn, che khuất nút trung tâm & layout chậm ở quy mô lớn (100–500 node)** | Thuật toán đẩy lặp `O(N² × 24)` ép tất cả node vào khung cố định `860×480` → ở 500 node mất `15.91 ms`, phát sinh **4.048 cặp chồng lấn**, và node chiến dịch bị vòng IOC đè lên (`first_node_click_occluded = true`). | **Đã khắc phục**: Không gian tọa độ thích ứng (`computeOptimalGraphExtent`) + lưới phân cụm đều + repulsion lưới băm không gian `O(N)` (`runSpatialRepulsion`) → `2.10 ms` (**nhanh hơn 7.6×**), **0 cặp chồng lấn** ở 14/50/100/500 node, `first_node_click_occluded = false`. |
| **Re-render thừa từ trang cha `/radar`** | Bộ đếm TTL 5 giây (`nowMs`) trong `RadarPage` tạo mới hàm inline `openNodeBlockModal` ở mỗi chu kỳ, làm re-render cả cây SVG. | **Đã khắc phục**: `React.memo` cho `IocGraphSvg` & `GraphSceneLayer` + bọc `openNodeBlockModal` bằng `useCallback(..., [])`. |

---

## 2. Phân tích nguyên nhân gốc (Root Cause Analysis)

Trước khi chỉnh sửa bất kỳ dòng mã nào, toàn bộ triệu chứng đã được tái hiện định lượng trên production build gốc (`perf_before.json` và `layout_before.json`). Các triệu chứng **không xuất phát từ một nguyên nhân duy nhất**, mà đến từ **6 bottleneck độc lập**:

### RC-1: Vòng lặp dao động bố cục do Tooltip nằm trong dòng chảy tài liệu (In-Flow Layout Thrashing)
- **Vị trí trước tối ưu:** Thanh trạng thái hiển thị mô tả node hover nằm trực tiếp trong layout phía trên `<svg>` với `flex-wrap` không khóa chiều cao.
- **Cơ chế gây bóng kép / rung giật:** Khi di chuột vào nút chiến dịch có nhãn tiếng Việt dài (60–75 ký tự), thanh trạng thái xuống 2–3 dòng và đẩy `<svg>` xuống **`+43.5 px`**. Điểm nằm dưới con trỏ chuột lúc này không còn là nút nữa nên `onMouseLeave` lập tức kích hoạt → thanh trạng thái co lại `-43.5 px` → nút trượt ngược về dưới con trỏ → `onMouseEnter` kích hoạt lại.
- **Bằng chứng thực đo:** Trong cửa sổ hover tĩnh `200 ms` trên tập 14/50/100 node, `IocGraphSvg` re-render **`30–32` lần** (~80 Hz) và tích lũy **`CLS = 1.580 – 1.685`**. Dao động dọc 43.5 px ở tần số cao này chính là nguồn gốc phần mềm của hiện tượng **bóng kép / nhảy hình** khi di chuột.

### RC-2: Xung đột cuộn trang và thu phóng do Passive Wheel Listener
- **Vị trí trước tối ưu:** `<svg onWheel={handleWheel}>` sử dụng synthetic event của React.
- **Cơ chế:** Trên Chromium/Edge và Firefox hiện đại, React gắn `wheel` listener ở chế độ `{ passive: true }`. Lời gọi `e.preventDefault()` bên trong bị trình duyệt từ chối với lỗi console `Unable to preventDefault inside passive event listener invocation.`.
- **Bằng chứng thực đo:** Mỗi thao tác `wheel(0, -180)` làm trang dịch chuyển **`120 px`** (`wheel_scroll_leak_px = 120`) đồng thời phát sinh 4 lỗi console liên tiếp.

### RC-3: Bão React Re-render trong quá trình Pan & Zoom
- **Vị trí trước tối ưu:** `pan`, `zoom`, `isDragging`, `hoveredId` đều là React `useState` ngay trong `IocGraphSvg`, đồng thời không tách layer tĩnh (`GraphSceneLayer`) khỏi viewport transform.
- **Cơ chế:** Mỗi sự kiện `pointermove` và `wheel` kích hoạt reconciler duyệt lại toàn bộ cây SVG (halos, edges, shapes, text pills, badges) và tính lại các mảng phụ trợ.
- **Bằng chứng thực đo:** Kịch bản stress (60 bước drag + 20 bước wheel + 8 hover + 1 click) tạo **`78–100` React renders/commits** trên `IocGraphSvg`, `ScriptDuration` tăng lên **`79.0 ms` (14 node) → `297.1 ms` (500 node)**, `max_frame_ms` đạt **`97.3 ms` (100 node)** và **`152.8 ms` (500 node)**.

### RC-4: Sai lệch hệ quy chiếu tọa độ khi Pan (`viewBox` vs CSS Pixels)
- **Vị trí trước tối ưu:** Tính delta kéo bằng `(clientX - startX) / zoom` thay vì chia cho hệ số tỷ lệ thực của `viewBox` (`scaleToCss = min(rect.width / VIEW_W, rect.height / VIEW_H)`).
- **Bằng chứng thực đo:** Trên viewport `1440×900@1.0x`, chiều rộng SVG thực tế ~657 px tương ứng `viewBox` 860 đơn vị (`ratio ≈ 1.309`). Một cú kéo chuột đúng `(100 px, 40 px)` chỉ làm nút di chuyển `(76.39 px, 30.56 px)` — sai số kéo **`25.43 px`**, gây cảm giác "trượt tay / nặng nề" khi kéo bản đồ.

### RC-5: Sụp đổ bố cục `O(N² × 24)` và quá tải không gian cố định ở 100–500 node
- **Vị trí trước tối ưu:** `computeRadarLayout` trong `frontend/src/lib/radarLayout.ts` luôn chạy trên mặt phẳng cố định `860×480`, bố trí >3 chiến dịch trên một vòng tròn duy nhất và đẩy chống chồng lấn bằng vòng lặp đôi `O(N²)`.
- **Bằng chứng thực đo:**
  - Ở `100 node`: `26` cặp chồng lấn sát (`< 32 px`).
  - Ở `500 node`: Thời gian tính layout đạt **`15.908 ms` mean / `17.260 ms` p95** (chiếm trọn 1 khung hình 60Hz), tạo **`4.048` cặp chồng lấn**, làm node chiến dịch bị các nút IOC đè kín (`first_node_click_occluded = true`, không thể click thông thường).

### RC-6: Hiệu ứng Paint nền SVG Pattern & Re-render từ Component Cha
- Nền chấm bi trước đây dùng `<pattern>` + `<rect>` ngay bên trong `<svg>`, buộc trình duyệt rasterize lại pattern cùng SVG; đồng thời nút `"Bỏ chọn"` thêm/xóa khỏi flex container khi chọn node và `RadarPage` truyền callback mới ở mỗi nhịp 5 giây.

---

## 3. Kiến trúc & Tối ưu hóa đã triển khai

Toàn bộ phần render và tương tác của `Mạng lưới liên kết` được cấu trúc lại theo kiến trúc **4 lớp tách biệt** trên 4 tệp chính:
- [`frontend/src/lib/radarLayout.ts`](frontend/src/lib/radarLayout.ts)
- [`frontend/src/components/radar/IocGraphSvg.tsx`](frontend/src/components/radar/IocGraphSvg.tsx)
- [`frontend/src/app/globals.css`](frontend/src/app/globals.css)
- [`frontend/src/app/radar/page.tsx`](frontend/src/app/radar/page.tsx)

### 3.1. Tách biệt 4 lớp trạng thái (Data / Layout / Viewport / Overlay)
1. **Graph Data (`nodes`, `edges`):** Prop đầu vào bất biến; hàm `buildGraphTopologyKey(nodes, edges)` tạo khóa cấu trúc chỉ phụ thuộc `node_id`, `kind` và quan hệ cạnh — hoàn toàn bỏ qua trạng thái `blocked`, `hit_count`, hover hay selection.
2. **Stable Graph Layout (`coordsById`):** Chỉ tính lại khi `topologyKey` thay đổi (`useMemo(..., [topologyKey])`). Khi pan, zoom, hover, chọn node hoặc bật/tắt quy tắc chặn, tọa độ node giữ nguyên 100% (`layout_computes_during_interact = 0`).
3. **Unified Imperative Viewport (`viewportRef` + `requestAnimationFrame`):**
   - Lưu trạng thái camera `{ scale, x, y }` trong `viewportRef` thay vì `useState`.
   - Gom tất cả sự kiện `pointermove` và `wheel` tần suất cao vào 1 frame duy nhất qua `scheduleViewportFlush()`.
   - Áp trực tiếp `transform="matrix(s 0 0 s x y)"` lên **một lớp `<g ref={viewportGroupRef}>` duy nhất** bao trọn halos, edges, nodes và labels — đảm bảo đồng bộ tọa độ tuyệt đối, không lệch lớp.
   - Chỉ cập nhật `textContent` của nhãn phần trăm zoom (`zoomLabelRef`) khi giá trị phần trăm làm tròn thực sự thay đổi (`lastZoomPctRef`), tránh kích hoạt style/layout thừa khi chỉ kéo pan.
   - Không làm mất vị trí camera khi người dùng chọn/bỏ chọn node (JSX gắn `viewportRef.current` và chỉ reset về `fitViewport` khi `topologyKey` đổi).
4. **Isolated Floating Overlay (`FloatingNodeTooltip`):**
   - Bọc trong `React.memo(forwardRef(...))` với `useImperativeHandle` (`show`/`hide`), sở hữu state cục bộ riêng biệt và `contain: layout style`, `pointer-events-none`, `transform: translate3d(x, y, 0)`.
   - Tọa độ được kẹp chống tràn viền qua `clampFloatingTooltip(...)` (tự động lật xuống dưới nếu gần cạnh trên, kẹp trong mép trái/phải).
   - **Kết quả:** Hover qua mọi nút trên sơ đồ gây **0 lần re-render** trên `IocGraphSvg` / `GraphSceneLayer` và **0.0 px** dịch chuyển bố cục.

### 3.2. Thuật toán Layout thích ứng `O(N)` cho 14–500+ node
- **`computeOptimalGraphExtent(nodeCount, 860, 480)`:** Giữ đúng mặt phẳng `860×480` cho đồ thị nhỏ (`≤ 26` node); tự động mở rộng theo `sqrt(nodeCount / 14)` cho đồ thị lớn (`1625×907` ở 50 node, `2298×1283` ở 100 node, `5139×2869` ở 500 node), sau đó `computeFitViewport(...)` tự tính scale vừa khung nhìn ban đầu.
- **Đặt cụm đa vòng & lưới đều:** Với >3 chiến dịch, các tâm chiến dịch được bố trí vào tâm từng ô lưới đều `(col + 0.5) * cellW`, `(row + 0.5) * cellH`; các cụm đông (>8 IOC) bung theo vòng xoắn đồng tâm đa tầng.
- **`runSpatialRepulsion` (`O(N)`):** Thay vòng lặp cặp `O(N²)` bằng lưới băm không gian (spatial hash grid), mỗi node chỉ kiểm tra 9 ô lân cận `3×3`.
- **Thứ tự vẽ Z-order trong `GraphSceneLayer`:** Render các nút IOC trước, nút trung tâm chiến dịch (`campaign`) sau cùng để hub chiến dịch không bao giờ bị đè che mất sự kiện click.

### 3.3. Tối ưu sự kiện, Cache hình học & Cleanup
- **Native non-passive wheel:** `svg.addEventListener("wheel", handleNativeWheel, { passive: false })` kèm chuẩn hóa `deltaMode` (0: pixel, 1: line × 18, 2: page × 120) thống nhất giữa Chrome, Edge và Firefox; thu phóng mượt theo hàm mũ `Math.exp(-clampedDelta * 0.0018)` quanh đúng tọa độ con trỏ (`zoomViewportAroundPoint`).
- **Pointer Events & Pointer Capture:** Sử dụng `onPointerDown` / `onPointerMove` / `onPointerUp` / `onPointerCancel` + `setPointerCapture` + `touch-none`; cập nhật `svg.style.cursor` trực tiếp không qua state.
- **Cache hình học bằng `ResizeObserver`:** `readViewportMetrics()` lưu cache `svgRect`, `boxRect`, `scaleToCss`, `offsetX`, `offsetY` và chỉ hủy cache khi `ResizeObserver`, `window.resize` hoặc `window.scroll` (passive) kích hoạt — loại bỏ forced synchronous reflow trong vòng lặp wheel/hover.
- **Dọn dẹp tài nguyên:** Hủy toàn bộ `requestAnimationFrame` (`pendingFlushRafRef`, `animRafRef`), `ResizeObserver`, `wheel`, `keydown`, `scroll` và `resize` listener trong hàm cleanup của `useEffect`.

### 3.4. Tinh chỉnh Animation & `prefers-reduced-motion`
- **Không dùng `transition: all`** ở bất kỳ thành phần đồ thị nào; **không có CSS transform transition** khi drag hoặc cuộn wheel trực tiếp.
- **Thời lượng có kiểm soát theo mục tiêu thiết kế:**
  - Hover / focus viền nút (`.radar-node-shape`): `110ms ease-out` (mục tiêu `100–120ms`).
  - Làm mờ / nổi bật khi chọn nút (`.radar-node`, `.radar-edge`): `150ms ease-out` (mục tiêu `150ms`).
  - Thu/phóng bằng nút bấm (`+` / `−`): `180ms` nội suy `easeOutCubic` qua `rAF` (mục tiêu `150–200ms`).
  - Đưa vừa khung nhìn (`Vừa khung`): `220ms` nội suy `easeOutCubic` qua `rAF` (mục tiêu `200–250ms`).
  - Mọi animation nút bấm lập tức bị hủy (`cancelViewportAnimation()`) ngay khi người dùng kéo chuột hoặc cuộn wheel mới, đảm bảo không bao giờ có hai animation cạnh tranh trên `transform`.
- **Nền chấm bi tĩnh CSS (`.radar-canvas-grid`):** Dùng `radial-gradient` tĩnh trên container có `contain: layout paint style` thay cho SVG `<pattern>`.
- **Hỗ trợ `prefers-reduced-motion: reduce`:** Cả media query trong `globals.css` lẫn kiểm tra `prefersReducedMotion()` trong `animateViewportTo()` đều chuyển tức thì không nội suy.

---

## 4. Đánh giá thư viện đồ thị: Custom SVG tối ưu vs Cytoscape.js

| Tiêu chí | Custom SVG hiện tại (đã tối ưu) | Chuyển sang Cytoscape.js |
|---|---|---|
| **Kích thước bundle (`/radar`)** | **24.1 kB** route / **132 kB** First Load JS (**+0 kB** dependency mới) | Thêm ~330–400 kB minified JS (tăng ~3× First Load JS của `/radar`) |
| **Hiệu năng 14 – 100 node** | **120.0 FPS** ổn định, `avg = 7.34–7.63 ms`, `p95 = 7.10 ms`, `layout ≤ 0.31 ms` | Tương đương (~60–120 FPS), chi phí khởi tạo canvas ban đầu cao hơn |
| **Hiệu năng 500 node** | **98.3–108.1 FPS**, `avg = 9.25–10.18 ms`, `layout = 2.10 ms`, **0 chồng lấn** | Canvas 2D nhanh hơn khi vẽ >1.500 node cùng lúc |
| **Độ sắc nét HiDPI / Zoom & Accessibility** | Vector sắc nét ở mọi DPR (1×, 1.25×, 1.5×, 2×); giữ nguyên `role="button"`, `tabIndex`, `aria-pressed`, `aria-label` từng nút & hỗ trợ bàn phím | Cần tự xây lớp a11y song song; text trên canvas dễ mờ nhẹ nếu không tự xử lý DPR/backing store |
| **Khả năng bảo trì & đồng bộ Design System** | Thuần TypeScript + Tailwind token + kiểm thử unit trực tiếp trên hàm thuần (`25/25` unit test) | Thêm API imperative cồng kềnh, khó đồng bộ theme token và kiểm thử unit |

**Quyết định kiến trúc:** **Giữ nguyên engine SVG tùy biến đã tối ưu**, không đưa thêm dependency nặng vào dự án vì toàn bộ 6 nguyên nhân gốc đã được giải quyết triệt để và hiệu năng dư giả vượt chuẩn 60 FPS tới 500 node.

**Ngưỡng xem xét chuyển đổi trong tương lai:** Chỉ nên cân nhắc bổ sung tầng render Canvas 2D / WebGL (như Sigma.js hoặc Cytoscape.js kèm chiến lược LOD/clustering phía backend) nếu đồ thị thực tế trên `/radar` cần hiển thị đồng thời **> 1.500–2.000 node tương tác trực tiếp** trên màn hình mà không phân cụm theo chiến dịch.

---

## 5. Kết quả Benchmark thực đo (Before vs After)

### 5.1. Phương pháp đo
- **Môi trường:** Production build Next.js (`next build` + `next start` trên `127.0.0.1:3012`), dữ liệu đồ thị tổng hợp xác định (synthetic, 0 PII) với 4 quy mô: **14, 50, 100 và 500 node**.
- **Đo Layout thuần:** Node.js `performance.now()` (30 vòng lặp warm-up + đo cho từng quy mô) kèm đếm số cặp node chồng lấn sát (`|dx| < 32 && |dy| < 32`).
- **Đo Tương tác trình duyệt thực tế:** Playwright điều khiển Chrome, Edge và Firefox thực hiện kịch bản chuẩn gồm:
  1. Kiểm tra dịch chuyển hover (`hover_svg_y_shift_px`, `hover_cls`, `hover_react_renders`).
  2. Kiểm tra xung đột cuộn trang (`wheel_scroll_leak_px` với `wheel(0, -180)`).
  3. Kiểm tra độ chính xác kéo 1:1 (`pan_tracking_error_px` trên cú kéo `100×40 px`).
  4. Chuỗi tương tác cường độ cao: **60 bước kéo tròn liên tục + 20 bước wheel zoom vào/ra + hover 8 nút + click chọn nút** — thu thập rAF frame deltas (FPS, avg, p95, max, frame >20ms / >33.3ms), React Fiber renders/commits, Chrome CDP `ScriptDuration`, `JSHeapUsedSize`, `Nodes`, và xác minh bảo toàn danh tính DOM (`same_svg_identity`, `same_node_identity`).
- *Lưu ý minh bạch về số liệu:*
  - Headless Chrome trên màn hình/compositor 120Hz của máy kiểm thử trả rAF nhịp ~7.1–8.3 ms (FPS được kẹp tối đa `120.0`).
  - Trong bài test frontend độc lập không bật backend FastAPI, chỉ có 1 log HTTP 500 từ endpoint nền `/api/v1/health` ở cả Before và After; ở Before còn có thêm 4 lỗi console `"Unable to preventDefault inside passive event listener invocation."` (đã về **0** ở After).
  - Trong `perf_after`, Chrome CDP `LayoutCount` (~138–159) bao gồm cả các lệnh `locator.bounding_box()` do chính kịch bản benchmark gọi khi di chuột qua 8 nút và cập nhật hình học nội bộ của SVG bị cô lập trong `contain: layout paint style` (`interaction_cls = 0.000`).

### 5.2. Hiệu năng tính toán Layout thuần (Node.js `computeRadarLayout`)

| Quy mô | Edges | Layout Mean (Before → After) | Layout P95 (Before → After) | Cải thiện Mean | Chồng lấn sát `<32px` (Before → After) | Không gian tọa độ (After) |
|---:|---:|---:|---:|---:|---:|---:|
| **14 node** | 14 | `0.098 ms` → **`0.098 ms`** | `0.564 ms` → **`0.364 ms`** | Ngang bằng (-35% p95) | `0` → **`0`** | `860 × 480` |
| **50 node** | 58 | `0.338 ms` → **`0.314 ms`** | `0.820 ms` → **`0.654 ms`** | **-7%** | `0` → **`0`** | `1625 × 907` |
| **100 node** | 121 | `0.584 ms` → **`0.309 ms`** | `1.692 ms` → **`0.407 ms`** | **-47% (1.9×)** | `26` → **`0`** | `2298 × 1283` |
| **500 node** | 644 | `15.908 ms` → **`2.096 ms`** | `17.260 ms` → **`3.652 ms`** | **-87% (7.6×)** | `4.048` → **`0`** | `5139 × 2869` |

### 5.3. Độ ổn định tương tác (Chrome `1440×900@1.0x` — Before vs After)

| Chỉ số lỗi / trải nghiệm | 14 node (Before → After) | 50 node (Before → After) | 100 node (Before → After) | 500 node (Before → After) |
|---|---:|---:|---:|---:|
| **Dịch chuyển SVG khi hover (`hover_svg_y_shift_px`)** | `43.5 px` → **`0.0 px`** | `43.5 px` → **`0.0 px`** | `43.5 px` → **`0.0 px`** | `0.0 px`* → **`0.0 px`** |
| **CLS khi hover (`hover_cls`)** | `1.685` → **`0.000`** | `1.607` → **`0.000`** | `1.580` → **`0.000`** | `0.000`* → **`0.000`** |
| **React render trong 200ms hover** | `32` → **`1`** (tooltip) | `31` → **`1`** (tooltip) | `30` → **`1`** (tooltip) | `2`* → **`1`** (tooltip) |
| **Rò rỉ cuộn trang khi wheel zoom (`wheel_scroll_leak_px`)** | `120 px` → **`0 px`** | `120 px` → **`0 px`** | `120 px` → **`0 px`** | `120 px` → **`0 px`** |
| **Lỗi console passive wheel listener** | `4` → **`0`** | `4` → **`0`** | `4` → **`0`** | `4` → **`0`** |
| **Sai số kéo pan 1:1 (`pan_tracking_error_px`)** | `25.43 px` → **`0.0 px`** | `25.43 px` → **`0.0 px`** | `25.43 px` → **`0.0 px`** | `25.43 px` → **`0.0 px`** |
| **Nút chiến dịch bị che khuất click (`first_node_click_occluded`)** | `false` → **`false`** | `false` → **`false`** | `false` → **`false`** | **`true`** → **`false`** |
| **Giữ nguyên DOM SVG & Node khi chọn (`no remount`)** | `true` → **`true`** | `true` → **`true`** | `true` → **`true`** | `true` → **`true`** |

*\*Ghi chú: Ở bản Before với 500 node, nút chiến dịch đầu tiên bị các vòng IOC đè khuất nên chuột di vào không chạm trúng nút chiến dịch, khiến thanh trạng thái không đổi dòng và click bị chặn (`first_node_click_occluded = true`). Ở bản After, 0 chồng lấn nên cả hover và click đều hoạt động bình thường với `0.0 px` dịch chuyển.*

### 5.4. Hiệu năng Runtime trong chuỗi tương tác nặng (Chrome `1440×900@1.0x`)

| Quy mô | `IocGraphSvg` Renders (Before → After) | Tổng React Commits (Before → After) | `ScriptDuration` (Before → After) | JS Heap Used (Before → After) | DOM Nodes (Before → After) | FPS / Avg Frame (After) | P95 / Max Frame (After) | Layout recompute khi tương tác |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **14 node** | `91` → **`1`** (-98.9%) | `91` → **`11`** (-87.9%) | `79.0 ms` → **`32.3 ms`** (-59%) | `7.27 MB` → **`6.57 MB`** (-10%) | `1,106` → **`829`** | `120.0 FPS` / `7.34 ms` | `7.10 ms` / `62.6 ms` | **`0`** |
| **50 node** | `100` → **`1`** (-99.0%) | `100` → **`11`** (-89.0%) | `98.9 ms` → **`32.9 ms`** (-67%) | `7.00 MB` → **`6.42 MB`** (-8%) | `1,202` → **`1,203`** | `120.0 FPS` / `7.55 ms` | `7.10 ms` / `41.6 ms` | **`0`** |
| **100 node** | `79` → **`1`** (-98.7%) | `79` → **`11`** (-86.1%) | `97.9 ms` → **`35.8 ms`** (-63%) | `9.25 MB` → **`6.69 MB`** (-28%) | `1,909` → **`1,576`** | `120.0 FPS` / `7.63 ms` | `7.10 ms` / `41.7 ms` | **`0`** |
| **500 node** | `78` → **`1`** (-98.7%) | `78` → **`12`** (-84.6%) | `297.1 ms` → **`53.2 ms`** (**-82%**) | `14.66 MB` → **`8.14 MB`** (**-44%**) | `5,138` → **`4,655`** | `98.3 FPS` / `10.18 ms` | `27.80 ms` / `83.3 ms` *(Before max: `152.8 ms`)* | **`0`** |

*(Ghi chú: 11–12 commits còn lại ở bản After gồm 1 commit duy nhất của `IocGraphSvg` khi click chọn node và 10–11 commit cực nhẹ nằm hoàn toàn bên trong component `FloatingNodeTooltip` khi di chuột qua 8 nút mẫu — không đụng vào `GraphSceneLayer`.)*

---

## 6. Báo cáo tương thích đa trình duyệt & Điều tra bóng kép (Browser Compatibility Report)

Kiểm thử chéo trên **11 cấu hình** gồm **Google Chrome**, **Microsoft Edge** và **Mozilla Firefox (Playwright Firefox 159.0)** với quy mô **50 node**, bao phủ màn hình Desktop 100%, HiDPI 1.5×, Zoom trình duyệt 125% (`1152×720@1.25x`), chế độ `prefers-reduced-motion: reduce`, và thiết bị di động `390×844@2.0x`:

| Trình duyệt & Cấu hình | FPS | Avg Frame | P95 Frame | Hover Y-Shift | Wheel Leak | Pan Error | Số lớp SVG | Lỗi Runtime |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Chrome** Desktop 100% (`1440×900@1.0x`) | `120.0` | `7.56 ms` | `7.10 ms` | `0.0 px` | `0 px` | `0.00 px` | `1` | `0` |
| **Chrome** HiDPI (`1440×900@1.5x`) | `120.0` | `7.53 ms` | `7.10 ms` | `0.0 px` | `0 px` | `0.00 px` | `1` | `0` |
| **Chrome** 125% Zoom (`1152×720@1.25x`) | `120.0` | `7.27 ms` | `7.10 ms` | `0.0 px` | `0 px` | `0.01 px` | `1` | `0` |
| **Chrome** Reduced Motion (`1440×900@1.0x`) | `120.0` | `7.57 ms` | `7.10 ms` | `0.0 px` | `0 px` | `0.00 px` | `1` | `0` |
| **Chrome** Mobile (`390×844@2.0x`) | `120.0` | `7.25 ms` | `7.10 ms` | `0.0 px` | `0 px` | `0.00 px` | `1` | `0` |
| **Microsoft Edge** Desktop 100% (`1440×900@1.0x`) | `120.0` | `7.50 ms` | `7.10 ms` | `0.0 px` | `0 px` | `0.00 px` | `1` | `0` |
| **Microsoft Edge** 125% Zoom (`1152×720@1.25x`) | `120.0` | `7.45 ms` | `7.10 ms` | `0.0 px` | `0 px` | `0.01 px` | `1` | `0` |
| **Firefox** Desktop 100% (`1440×900@1.0x`) | `63.8` | `15.66 ms` | `48.60 ms` | `0.0 px` | `0.0 px` | `0.42 px` | `1` | `0` |
| **Firefox** HiDPI (`1440×900@1.5x`) | `75.4` | `13.25 ms` | `34.72 ms` | `0.0 px` | `0.0 px` | `0.42 px` | `1` | `0` |
| **Firefox** 125% Zoom (`1152×720@1.25x`) | `120.0` | `8.26 ms` | `13.88 ms` | `0.0 px` | `0.0 px` | `0.35 px` | `1` | `0` |
| **Firefox** Mobile (`390×844@2.0x`) | `105.8` | `9.46 ms` | `20.84 ms` | `0.0 px` | `0.0 px` | `0.26 px` | `1` | `0` |

### Phân tích đặc thù Firefox & Tách bạch lỗi phần mềm với bóng mờ màn hình (Ghosting)
1. **Hành vi trên Firefox:**
   - Gecko không hỗ trợ `PerformanceObserver({ type: "layout-shift" })` (API chỉ có trên Chromium), nên độ ổn định bố cục trên Firefox được kiểm chứng trực tiếp bằng đo tọa độ `bounding_box()` của `<svg>` trước và trong khi hover → kết quả **`0.0 px`** trên mọi cấu hình.
   - `pan_tracking_error_px` trên Firefox là `0.26–0.42 px` (nhỏ hơn nửa pixel, do làm tròn sub-pixel của `getBoundingClientRect()` trên phần tử SVG sau `matrix()`).
   - Chuẩn hóa `ev.deltaMode` (`DOM_DELTA_LINE` trên Firefox) + `{ passive: false }` giữ `wheel_scroll_leak_px = 0.0 px`.
   - FPS trung bình trên Firefox đạt `63.8 – 120.0 FPS` (vượt ngưỡng mượt 60 FPS); độ biến thiên p95 cao hơn Chromium (`34.7–48.6 ms` trên desktop headless) là đặc trưng của pipeline rasterize SVG trên Firefox headless khi thay đổi `transform` liên tục kết hợp với các bước truy vấn `bounding_box()`.
2. **Xác minh trực tiếp bằng Screen Recording & Frame Capture (Tách lỗi phần mềm khỏi hiện tượng màn hình/camera):**
   - Đã ghi hình trực tiếp luồng xuất framebuffer của trình duyệt (Playwright `.webm`) và chụp khung hình trực tiếp trong lúc **hover** và **giữa cú kéo (`mid_drag`)** trên cả **Chrome** lẫn **Firefox**.
   - **Kết quả kiểm tra thị giác & DOM:**
     - Chỉ tồn tại duy nhất **1 thẻ `<svg>`** và **1 thẻ `<g>` transform** (`svg_count = 1`), không có lớp trùng lặp hay node render kép.
     - Trong khung hình `hover`, tooltip nổi đè phía trên nút gọn gàng, thanh gợi ý giữ cố định `32 px`, không còn hiện tượng bật lên/tụt xuống 80 Hz.
     - Trong khung hình `mid_drag`, tooltip ẩn tức thì khi bắt đầu kéo, các đường nối và nhãn dịch chuyển đồng bộ hoàn toàn không để lại vệt kéo hay ảnh bóng.
   - **Kết luận về bóng kép:** Nguyên nhân **phần mềm** gây bóng kép/rung hình (dao động hover `+43.5 px` ở ~80 Hz) đã bị loại bỏ 100%. Nếu người dùng vẫn quan sát thấy vệt mờ khi quay màn hình bằng điện thoại trong lúc kéo rất nhanh, đó là đặc tính vật lý của **thời gian đáp ứng pixel / overdrive trên tấm nền LCD** hoặc lệch tần số quét camera, không phải lỗi render hay compositing của ứng dụng.

---

## 7. Hướng dẫn kiểm chứng lại (Verification & Reproducibility)

1. **Unit tests cho layout, viewport math, tooltip clamping & 500-node zero-overlap:**
   ```powershell
   cd frontend
   npm test
   ```
   Tệp kiểm thử: [`frontend/src/lib/__tests__/radarLayout.test.ts`](frontend/src/lib/__tests__/radarLayout.test.ts) (`25/25` test pass).

2. **Full Repository Verification Gate (Lint, Typecheck, Unit Tests, Production Build):**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
   ```
   (hoặc `bash scripts/verify.sh` trên Linux/VPS).
