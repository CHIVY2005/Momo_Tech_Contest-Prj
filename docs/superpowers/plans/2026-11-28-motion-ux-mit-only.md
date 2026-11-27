# Motion UX (Phương án 1 — 100% MIT) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bổ sung chuyển động có mục đích (cuộn mượt, số liệu odometer, spotlight thẻ, vẽ luồng dữ liệu SVG, nhịp xuất hiện kết quả) cho frontend VeriShield AI chỉ bằng thư viện giấy phép MIT, không làm chậm cảnh báo an toàn.

**Architecture:** `lenis` (MIT) cung cấp cuộn mượt toàn cục qua một client provider đặt trong `layout.tsx`, có khóa cuộn đếm tham chiếu cho drawer/modal. `motion` (MIT, dùng `LazyMotion` + `domAnimation` + `m`) xử lý nhịp xuất hiện. Ba micro-UI tự viết (`AnimatedNumber`, `SpotlightGroup`, `DrawOnView`) lấy cảm hứng từ React Bits nhưng **không sao chép mã nguồn** của nó. Mọi phép tính thuần nằm trong `src/lib/motion/*.ts` để test bằng `node --test`.

**Tech Stack:** Next.js 15.5 App Router, React 19.1, Tailwind CSS v4, TypeScript strict, `lenis@^1.3.28` (MIT), `motion` bản mới nhất major `>=12` (MIT), Node test runner.

**Spec:** Phần "Phương án 1" trong phiên nghiên cứu Exa (2026-11-28) + `AGENTS.md` §2 Rule 2 (chỉ giấy phép permissive) + `docs/momo.md` (README phải khai báo thư viện mã nguồn mở).

## Global Constraints

- Chỉ được thêm đúng 2 dependency runtime: `lenis` và `motion`. **Cấm** `gsap`, `@gsap/*`, mọi mã sao chép từ `DavidHDev/react-bits` / `reactbits.dev` (MIT + Commons Clause), `@hugeicons/*`, `three`, `ogl`.
- Giấy phép mọi entry `dependencies` trong `frontend/package.json` phải thuộc allowlist: `MIT`, `ISC`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `0BSD`.
- Không load script từ CDN (CSP Caddy: `script-src 'self' 'unsafe-inline'`). Chỉ import qua bundler.
- Không dùng thư viện cho pan/zoom/drag của `IocGraphSvg.tsx`; không đổi logic `matrix(...)` của nó.
- **An toàn trước thẩm mỹ:** phần tử `role="alert"` (Rào chắn Trung thực Tiểu thương, lỗi), nhãn verdict, nút hành động khẩn cấp **không bao giờ** có `initial` opacity 0 hay delay. Thời lượng mọi animation `<= 600ms`; entrance `<= 320ms`.
- Chỉ animate `transform`, `opacity`, `stroke-dashoffset`, CSS custom properties. Không animate `width/height/top/margin`.
- `prefers-reduced-motion: reduce` ⇒ không tạo instance Lenis, số hiển thị ngay giá trị cuối, đường SVG hiển thị đầy đủ, không có shimmer/entrance.
- Progressive enhancement: khi chưa hydrate / tắt JS, mọi nội dung (đường SVG, số liệu) phải hiển thị đầy đủ. Chỉ JS mới được "ẩn để vẽ lại".
- Offset neo cuộn dưới sticky header = `84` px (khớp `scroll-margin-top: 84px` trong `globals.css`).
- File trong `src/lib/motion/` không được dùng alias `@/` và không chứa JSX (để `node --test` import trực tiếp như `../composerUtils.ts`).
- Mọi test file mới phải được thêm vào script `"test"` trong `frontend/package.json` (script liệt kê file tường minh).
- Gate cuối: `powershell -ExecutionPolicy Bypass -File scripts/verify.ps1` exit 0.

## Review Focus

1. **Bật reduced-motion giữa phiên** (đổi cài đặt OS khi trang đang mở) ⇒ Lenis bị `destroy()` ngay, cuộn native hoạt động, không còn rAF chạy nền. → test `shouldEnableSmoothScroll` (Task 1) + bước QA thủ công Task 7.
2. **Lăn chuột trên đồ thị `/radar`** phải zoom đồ thị, không cuộn trang; danh sách dài trong 3 drawer phải cuộn bên trong, trang nền đứng yên; hai drawer mở chồng nhau rồi đóng một cái thì trang vẫn bị khóa. → test `createScrollLockCounter` (Task 1) + QA Task 7.
3. **Link neo / skip-link / mục lục `DocsToc`**: URL hash được cập nhật, focus chuyển tới đích, tiêu đề đích nằm ngay dưới header 84 px; hash độc hại (`#a"],b`, `#` rỗng, URL khác trang) bị bỏ qua để trình duyệt xử lý mặc định. → test `parseSameDocumentHash` (Task 1).
4. **Đổi demo liên tục / huỷ giữa chừng SSE**: `AnimatedNumber` đổi đích giữa chừng phải đi tiếp từ giá trị đang hiển thị, unmount huỷ rAF; tự cuộn tới kết quả chỉ xảy ra một lần cho mỗi `case_id` và chỉ khi khối kết quả nằm ngoài viewport. → test `interpolateCount` + `shouldAutoScrollIntoView` (Task 1).
5. **Điều hướng `/radar` → `/technical` khi còn quán tính cuộn** phải về đầu trang mới, không bị Lenis kéo lại vị trí cũ. → `stopInertiaOnNavigate: true` + `lenis.scrollTo(0, { immediate: true, force: true })` khi `pathname` đổi (Task 2) + QA Task 7.

---

## File Structure

| File | Trách nhiệm |
| :--- | :--- |
| `frontend/src/lib/motion/motionMath.ts` (mới) | Hàm thuần: easing, nội suy số, stagger, vị trí spotlight |
| `frontend/src/lib/motion/scrollControl.ts` (mới) | Hàm thuần: điều kiện bật Lenis, parse hash an toàn, quyết định tự cuộn, bộ đếm khóa cuộn |
| `frontend/src/lib/__tests__/motionMath.test.ts` (mới) | Test `motionMath.ts` |
| `frontend/src/lib/__tests__/scrollControl.test.ts` (mới) | Test `scrollControl.ts` |
| `frontend/src/lib/__tests__/frontendLicenses.test.ts` (mới) | Guard giấy phép dependency + cấm gsap/react-bits |
| `frontend/src/components/motion/SmoothScrollProvider.tsx` (mới) | Vòng đời Lenis, context `useSmoothScroll`, hook `useScrollLock`, xử lý click neo |
| `frontend/src/components/motion/MotionProviders.tsx` (mới) | `LazyMotion` + `MotionConfig reducedMotion="user"` bọc `SmoothScrollProvider` |
| `frontend/src/components/motion/AnimatedNumber.tsx` (mới) | Số đếm rAF, a11y (giá trị thật cho screen reader) |
| `frontend/src/components/motion/SpotlightGroup.tsx` (mới) | Một listener `pointermove` uỷ quyền, set `--spot-x/--spot-y` cho thẻ `.vs-spotlight` |
| `frontend/src/components/motion/DrawOnView.tsx` (mới) | IntersectionObserver vẽ các đường `[marker-end]` trong SVG con |
| `frontend/src/app/layout.tsx` | Bọc `MotionProviders`, import `lenis/dist/lenis.css` |
| `frontend/src/app/globals.css` | Bỏ `scroll-behavior: smooth`; thêm `.vs-spotlight`, `.vs-shimmer-text`, `.vs-draw` |
| `frontend/src/app/page.tsx` | Tự cuộn tới kết quả một lần/case |
| `frontend/src/app/radar/page.tsx` | `AnimatedNumber` + `SpotlightGroup` cho 4 KPI |
| `frontend/src/app/technical/page.tsx`, `frontend/src/app/privacy/page.tsx` | Bọc 3 SVG bằng `DrawOnView`; cập nhật bảng giấy phép §18 |
| `frontend/src/components/workbench/VerdictDashboard.tsx` | `AnimatedNumber` cho `risk_score`; entrance cho khối phụ |
| `frontend/src/components/workbench/LiveTracePanel.tsx` | Entrance từng bước + shimmer "Đang kiểm tra..." |
| `frontend/src/components/workbench/DemoScenarioBar.tsx` | `SpotlightGroup` cho lưới demo |
| `frontend/src/components/radar/IocGraphSvg.tsx` | `data-lenis-prevent` trên khung SVG |
| `AssistantDrawer.tsx`, `CampaignDetailDrawer.tsx`, `ApiPlaygroundCard.tsx`, `RuleActionModal.tsx` | `useScrollLock(open)` + `data-lenis-prevent` trên vùng cuộn |
| `README.md` | Khai báo `lenis` (MIT), `motion` (MIT) |

---

### Task 0: Baseline, dependency và guard giấy phép

**Files:**
- Modify: `frontend/package.json`, `frontend/package-lock.json`
- Create: `frontend/src/lib/__tests__/frontendLicenses.test.ts`

**Interfaces:**
- Produces: dependency `lenis`, `motion` có sẵn cho các task sau.

- [ ] **Step 1: Ghi baseline bundle**

Run (trong `frontend/`): `npm run build`
Ghi lại cột "First Load JS" của `/`, `/radar`, `/technical`, `/privacy` vào phần "Kết quả đo" cuối plan này.

- [ ] **Step 2: Viết test guard giấy phép (fail trước khi cài)**

```ts
// frontendLicenses.test.ts — đọc ../../../package.json và node_modules/<dep>/package.json bằng node:fs
const ALLOWED = new Set(["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD"]);
const BANNED = [/^gsap$/, /^@gsap\//, /react-bits/i, /^@hugeicons\//, /^three$/, /^ogl$/];

test("mọi runtime dependency có giấy phép permissive", () => {
  for (const dep of Object.keys(pkg.dependencies)) {
    assert.ok(ALLOWED.has(readLicense(dep)), `${dep} license ${readLicense(dep)}`);
  }
});
test("không có dependency bị cấm (GSAP / React Bits / WebGL)", () => {
  for (const dep of [...Object.keys(pkg.dependencies), ...Object.keys(pkg.devDependencies)]) {
    assert.ok(!BANNED.some((re) => re.test(dep)), dep);
  }
});
test("lenis và motion đã được khai báo", () => {
  assert.ok(pkg.dependencies.lenis);
  assert.ok(pkg.dependencies.motion);
});
test("không có mã nguồn sao chép từ React Bits trong src/", () => {
  // quét đệ quy src/**/*.ts(x) (trừ __tests__), assert không chứa "reactbits.dev" hay "David Haz"
});
```

`readLicense(dep)` trả về `license` (string) hoặc `license.type` từ `node_modules/<dep>/package.json`.

- [ ] **Step 3: Thêm test vào script và chạy để thấy fail**

Thêm `src/lib/__tests__/frontendLicenses.test.ts` vào cuối chuỗi `"test"` trong `package.json`.
Run: `npm test` → Expected: FAIL ở "lenis và motion đã được khai báo".

- [ ] **Step 4: Cài dependency**

Run: `npm install lenis@^1.3.28 motion@latest`
Kiểm tra `node_modules/motion/package.json` có major `>=12`; nếu `peerDependencies` của motion không chấp nhận React 19 thì dừng lại và báo cáo.

- [ ] **Step 5: Chạy lại**

Run: `npm test` → Expected: toàn bộ PASS (42 test cũ + 4 test mới).

- [ ] **Step 6: Commit**

```bash
git add frontend/package.json frontend/package-lock.json frontend/src/lib/__tests__/frontendLicenses.test.ts
git commit -m "build(frontend): add MIT-only motion deps (lenis, motion) with license guard"
```

---

### Task 1: Hàm thuần cho motion và điều khiển cuộn

**Files:**
- Create: `frontend/src/lib/motion/motionMath.ts`, `frontend/src/lib/motion/scrollControl.ts`
- Test: `frontend/src/lib/__tests__/motionMath.test.ts`, `frontend/src/lib/__tests__/scrollControl.test.ts`

**Interfaces:**
- Produces (`motionMath.ts`):
  - `easeOutCubic(t: number): number` — clamp `t` về `[0,1]`.
  - `interpolateCount(from: number, to: number, progress: number): number` — làm tròn số nguyên, clamp progress, dùng `easeOutCubic`.
  - `countDurationMs(from: number, to: number): number` — `min(600, max(240, |to-from| * 8))`.
  - `staggerDelaysMs(count: number, stepMs: number, maxTotalMs: number): number[]` — nếu `(count-1)*stepMs > maxTotalMs` thì nén step còn `maxTotalMs/(count-1)`; `count<=0` → `[]`.
  - `spotlightPosition(rect: {left:number; top:number; width:number; height:number}, clientX: number, clientY: number): { xPct: number; yPct: number }` — phần trăm clamp `[0,100]`, rect rỗng → `{50,50}`.
- Produces (`scrollControl.ts`):
  - `ANCHOR_OFFSET_PX = 84`
  - `shouldEnableSmoothScroll(env: { reducedMotion: boolean; hasWindow: boolean }): boolean`
  - `parseSameDocumentHash(href: string, currentPathname: string): string | null` — chỉ chấp nhận `#id` hoặc `/<currentPathname>#id`; id phải khớp `/^[A-Za-z][A-Za-z0-9_-]{0,63}$/`; khác → `null`.
  - `shouldAutoScrollIntoView(input: { targetTop: number; viewportHeight: number; headerHeight: number; alreadyScrolledForCase: boolean }): boolean` — `false` nếu đã cuộn cho case này; `true` khi `targetTop < headerHeight` hoặc `targetTop > viewportHeight * 0.6`.
  - `createScrollLockCounter(onChange: (locked: boolean) => void): { acquire(): () => void }` — release idempotent; chỉ gọi `onChange` khi chuyển 0↔1.

- [ ] **Step 1: Viết test thất bại**

```ts
// motionMath.test.ts
test("easeOutCubic clamps and hits endpoints", () => {
  assert.equal(easeOutCubic(-1), 0); assert.equal(easeOutCubic(0), 0);
  assert.equal(easeOutCubic(1), 1); assert.equal(easeOutCubic(2), 1);
  assert.ok(easeOutCubic(0.5) > 0.5);
});
test("interpolateCount is integer, monotonic, exact at ends, supports retarget downwards", () => {
  assert.equal(interpolateCount(0, 93, 0), 0); assert.equal(interpolateCount(0, 93, 1), 93);
  assert.equal(interpolateCount(93, 12, 1), 12);
  assert.ok(Number.isInteger(interpolateCount(0, 93, 0.37)));
});
test("countDurationMs bounded 240..600", () => {
  assert.equal(countDurationMs(5, 5), 240); assert.equal(countDurationMs(0, 1000), 600);
});
test("staggerDelaysMs compresses to budget", () => {
  assert.deepEqual(staggerDelaysMs(0, 40, 200), []);
  assert.deepEqual(staggerDelaysMs(3, 40, 200), [0, 40, 80]);
  assert.deepEqual(staggerDelaysMs(11, 40, 200), [0,20,40,60,80,100,120,140,160,180,200]);
});
test("spotlightPosition clamps and handles empty rect", () => {
  const r = { left: 100, top: 50, width: 200, height: 100 };
  assert.deepEqual(spotlightPosition(r, 200, 100), { xPct: 50, yPct: 50 });
  assert.deepEqual(spotlightPosition(r, 0, 999), { xPct: 0, yPct: 100 });
  assert.deepEqual(spotlightPosition({ left: 0, top: 0, width: 0, height: 0 }, 5, 5), { xPct: 50, yPct: 50 });
});

// scrollControl.test.ts
test("shouldEnableSmoothScroll", () => {
  assert.equal(shouldEnableSmoothScroll({ reducedMotion: false, hasWindow: true }), true);
  assert.equal(shouldEnableSmoothScroll({ reducedMotion: true, hasWindow: true }), false);
  assert.equal(shouldEnableSmoothScroll({ reducedMotion: false, hasWindow: false }), false);
});
test("parseSameDocumentHash accepts safe same-page anchors only", () => {
  assert.equal(parseSameDocumentHash("#thu-vien-giay-phep", "/technical"), "thu-vien-giay-phep");
  assert.equal(parseSameDocumentHash("/technical#main-content", "/technical"), "main-content");
  assert.equal(parseSameDocumentHash("/privacy#x", "/technical"), null);
  assert.equal(parseSameDocumentHash("#", "/"), null);
  assert.equal(parseSameDocumentHash('#a"],b', "/"), null);
  assert.equal(parseSameDocumentHash("https://evil.example/#a", "/"), null);
  assert.equal(parseSameDocumentHash("#9abc", "/"), null);
});
test("shouldAutoScrollIntoView", () => {
  const base = { viewportHeight: 800, headerHeight: 84, alreadyScrolledForCase: false };
  assert.equal(shouldAutoScrollIntoView({ ...base, targetTop: 300 }), false);
  assert.equal(shouldAutoScrollIntoView({ ...base, targetTop: 700 }), true);
  assert.equal(shouldAutoScrollIntoView({ ...base, targetTop: 20 }), true);
  assert.equal(shouldAutoScrollIntoView({ ...base, targetTop: 700, alreadyScrolledForCase: true }), false);
});
test("createScrollLockCounter is ref-counted and release is idempotent", () => {
  const calls: boolean[] = [];
  const c = createScrollLockCounter((l) => calls.push(l));
  const r1 = c.acquire(); const r2 = c.acquire();
  r1(); r1(); assert.deepEqual(calls, [true]);
  r2(); assert.deepEqual(calls, [true, false]);
});
```

- [ ] **Step 2: Thêm 2 file test vào script `"test"`, chạy** — `npm test` → Expected: FAIL (module not found).
- [ ] **Step 3: Implement hai module theo đúng signature ở Interfaces.**
- [ ] **Step 4: Chạy** — `npm test` → Expected: PASS. `npm run typecheck` → 0 lỗi.
- [ ] **Step 5: Commit** — `git commit -m "feat(frontend): add pure motion math and scroll-control helpers"`

---

### Task 2: Cuộn mượt toàn cục (Lenis) + khóa cuộn + cô lập vùng cuộn

**Files:**
- Create: `frontend/src/components/motion/SmoothScrollProvider.tsx`, `frontend/src/components/motion/MotionProviders.tsx`
- Modify: `frontend/src/app/layout.tsx`, `frontend/src/app/globals.css:65-70,152-155`, `frontend/src/components/radar/IocGraphSvg.tsx` (phần tử bọc `<svg>` có listener `wheel` tại dòng ~798), `frontend/src/components/assistant/AssistantDrawer.tsx:~963`, `frontend/src/components/radar/CampaignDetailDrawer.tsx:~91`, `frontend/src/components/radar/ApiPlaygroundCard.tsx:~163`, `frontend/src/components/radar/RuleActionModal.tsx`

**Interfaces:**
- Consumes: `shouldEnableSmoothScroll`, `parseSameDocumentHash`, `createScrollLockCounter`, `ANCHOR_OFFSET_PX` (Task 1).
- Produces:
  - `SmoothScrollProvider({ children }: { children: React.ReactNode }): JSX.Element`
  - `useSmoothScroll(): { scrollToElement(el: HTMLElement, opts?: { offset?: number; immediate?: boolean }): void; isSmooth: boolean }` — khi không có Lenis dùng `el.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" })`.
  - `useScrollLock(active: boolean): void`
  - `MotionProviders({ children }): JSX.Element` = `<LazyMotion features={domAnimation} strict><MotionConfig reducedMotion="user"><SmoothScrollProvider>{children}</SmoothScrollProvider></MotionConfig></LazyMotion>`

- [ ] **Step 1: Implement `SmoothScrollProvider.tsx` (`"use client"`)**

Quyết định cố định:
- Đọc `window.matchMedia("(prefers-reduced-motion: reduce)")`; nếu `shouldEnableSmoothScroll` thì `new Lenis({ autoRaf: true, lerp: 0.1, smoothWheel: true, syncTouch: false, stopInertiaOnNavigate: true })`; nghe sự kiện `change` để `destroy()` / tạo lại; cleanup `destroy()` khi unmount.
- **Không** bật option `anchors` / `allowNestedScroll` của Lenis. Thay vào đó một listener `click` (capture) trên `document`: bỏ qua nếu `event.defaultPrevented`, `button !== 0`, có modifier, `target` không phải `<a>` hoặc có `target="_blank"`; lấy id bằng `parseSameDocumentHash(anchor.getAttribute("href"), location.pathname)`; nếu `null` hoặc `getElementById` không thấy → để mặc định. Ngược lại `preventDefault()`, cuộn với `offset: -ANCHOR_OFFSET_PX`, `history.pushState(null, "", "#"+id)`, rồi focus đích (`tabIndex=-1` nếu chưa focus được, `focus({ preventScroll: true })`). Áp dụng cho skip-link `#main-content` và `DocsToc`.
- `usePathname()` đổi ⇒ `lenis?.scrollTo(0, { immediate: true, force: true })` trừ khi URL có hash.
- Khóa cuộn: một `createScrollLockCounter` trong ref; `onChange(true)` → `lenis?.stop()`, `onChange(false)` → `lenis?.start()`. `useScrollLock(active)` gọi `acquire()` trong `useEffect` khi `active`, trả release trong cleanup.

- [ ] **Step 2: Implement `MotionProviders.tsx` và nối vào `layout.tsx`**

Trong `layout.tsx`: `import "lenis/dist/lenis.css";` trước `./globals.css`; bọc toàn bộ nội dung bên trong `<body>` (skip-link, header, main, footer) bằng `<MotionProviders>`. `layout.tsx` vẫn là Server Component.

- [ ] **Step 3: Sửa `globals.css`**

Xoá `scroll-behavior: smooth;` khỏi `html` (dòng 69) và khối `html { scroll-behavior: auto; }` trong media reduced-motion (dòng 153-155) vì không còn cần.

- [ ] **Step 4: Cô lập vùng cuộn**

- `IocGraphSvg.tsx`: thêm `data-lenis-prevent` vào phần tử bọc trực tiếp `<svg>` đang gắn listener `wheel`.
- Ba vùng `overflow-y-auto` (AssistantDrawer ~963, CampaignDetailDrawer ~91, ApiPlaygroundCard ~163): thêm `data-lenis-prevent`.
- Gọi `useScrollLock(isOpen)` trong `AssistantDrawer`, `useScrollLock(campaign !== null)` trong `CampaignDetailDrawer`, `useScrollLock(open)` trong `ApiPlaygroundCard`, `useScrollLock(modal !== null)` trong `RuleActionModal`.

- [ ] **Step 5: Kiểm tra**

Run: `npm run typecheck; npm test; npm run build` → 0 lỗi, toàn bộ test PASS, build 8/8 route.
Run `npm run dev` và kiểm tra thủ công: cuộn `/technical` mượt; bấm mục lục → URL đổi hash, tiêu đề nằm dưới header; Tab đầu trang + Enter skip-link → focus vào `main`; lăn chuột trên đồ thị `/radar` chỉ zoom; mở drawer chiến dịch → trang nền không cuộn, danh sách trong drawer cuộn được.

- [ ] **Step 6: Commit** — `git commit -m "feat(frontend): add Lenis smooth scroll with ref-counted scroll lock and safe anchor handling"`

---

### Task 3: `AnimatedNumber` cho điểm rủi ro và 4 KPI giám sát

**Files:**
- Create: `frontend/src/components/motion/AnimatedNumber.tsx`
- Modify: `frontend/src/components/workbench/VerdictDashboard.tsx:209-210`, `frontend/src/app/radar/page.tsx:349,357-359,369-371,381-383`

**Interfaces:**
- Consumes: `interpolateCount`, `countDurationMs` (Task 1).
- Produces: `AnimatedNumber(props: { value: number; animateOnMount?: boolean; format?: (n: number) => string; className?: string }): JSX.Element`

- [ ] **Step 1: Implement `AnimatedNumber.tsx` (`"use client"`)**

Quyết định cố định:
- `useState(value)` cho giá trị hiển thị ⇒ SSR và lần render đầu luôn là giá trị thật (không lệch hydration, không nhấp nháy).
- Khi `value` đổi (hoặc mount với `animateOnMount` = true thì từ `0`): nếu `matchMedia("(prefers-reduced-motion: reduce)").matches` → set ngay. Ngược lại chạy rAF từ **giá trị đang hiển thị** tới `value` trong `countDurationMs(...)`; huỷ rAF cũ khi đổi đích và khi unmount.
- Markup: `<span className={className}><span aria-hidden="true">{format(display)}</span><span className="sr-only">{format(value)}</span></span>`. `format` mặc định `n.toLocaleString("vi-VN")`.

- [ ] **Step 2: Áp dụng**

- `VerdictDashboard.tsx` dòng 210: `{report.risk_score}` → `<AnimatedNumber value={report.risk_score} animateOnMount />`. Giữ nguyên `aria-valuenow`, `aria-valuetext`, độ rộng thanh (`style.width`) dùng giá trị thật. Nhãn verdict, icon và màu không đổi, hiển thị tức thì.
- `radar/page.tsx`: 4 số `{totalCases}`, `{totalCampaigns}`, `{totalIocs}`, `{activeBlocks}` → `<AnimatedNumber value={...} />` (không `animateOnMount`; chỉ chạy khi số thay đổi sau tạo/thu hồi quy tắc).

- [ ] **Step 3: Kiểm tra** — `npm run typecheck; npm test` PASS. Dev: chạy demo "CRITICAL_SCAM" → điểm chạy tới 93 trong ≤600ms, nhãn đỏ hiện ngay; trên `/radar` thêm quy tắc → KPI "Quy tắc đang áp dụng" chạy từ n → n+1.
- [ ] **Step 4: Commit** — `git commit -m "feat(frontend): animate risk score and radar KPIs with accessible AnimatedNumber"`

---

### Task 4: `SpotlightGroup` cho thẻ demo và KPI

**Files:**
- Create: `frontend/src/components/motion/SpotlightGroup.tsx`
- Modify: `frontend/src/app/globals.css` (thêm khối `.vs-spotlight`), `frontend/src/components/workbench/DemoScenarioBar.tsx:59-115`, `frontend/src/app/radar/page.tsx:346-388`

**Interfaces:**
- Consumes: `spotlightPosition` (Task 1).
- Produces: `SpotlightGroup(props: { className?: string; children: React.ReactNode }): JSX.Element` — render `<div className={className}>`; mọi phần tử con có class `vs-spotlight` nhận hiệu ứng.

- [ ] **Step 1: Implement**

- Một listener `onPointerMove` trên div bọc; tìm `(event.target as Element).closest(".vs-spotlight")` nằm trong nhóm; throttle bằng một rAF; set `--spot-x`/`--spot-y` (`"<xPct>%"`) trên thẻ đó. Bỏ qua nếu `event.pointerType !== "mouse"`.
- CSS trong `globals.css`:
  - `.vs-spotlight { position: relative; isolation: isolate; }`
  - `.vs-spotlight::before` — `pointer-events:none; inset:0; border-radius:inherit; opacity:0; transition: opacity 160ms ease-out; background: radial-gradient(220px circle at var(--spot-x,50%) var(--spot-y,50%), rgba(245,158,11,0.10), transparent 70%); z-index:-1`
  - `.vs-spotlight:hover::before, .vs-spotlight:focus-visible::before { opacity: 1; }`
  - `@media (hover: none) { .vs-spotlight::before { display: none; } }`

- [ ] **Step 2: Áp dụng** — `DemoScenarioBar`: thay `<div className="grid ...">` bằng `<SpotlightGroup className="grid ...">` và thêm `vs-spotlight` vào class mỗi `<button>`. `/radar`: lưới 4 KPI tương tự, dùng biến thể màu cyan (`.vs-spotlight-cyan` đổi màu gradient sang `rgba(14,165,233,0.10)`).
- [ ] **Step 3: Kiểm tra** — typecheck + test PASS; dev: rê chuột trên thẻ demo thấy quầng sáng nhẹ theo con trỏ; Tab bằng bàn phím thấy quầng ở tâm; viền focus amber vẫn hiển thị.
- [ ] **Step 4: Commit** — `git commit -m "feat(frontend): add delegated pointer spotlight to demo and KPI cards"`

---

### Task 5: Nhịp xuất hiện kết quả + shimmer tiến trình + tự cuộn tới kết quả

**Files:**
- Modify: `frontend/src/components/workbench/LiveTracePanel.tsx`, `frontend/src/components/workbench/VerdictDashboard.tsx`, `frontend/src/app/page.tsx:365-367`, `frontend/src/app/globals.css` (thêm `.vs-shimmer-text`)

**Interfaces:**
- Consumes: `staggerDelaysMs`, `shouldAutoScrollIntoView`, `ANCHOR_OFFSET_PX` (Task 1); `useSmoothScroll` (Task 2); `m` từ `motion/react` (đã có `LazyMotion` từ Task 2).

- [ ] **Step 1: `LiveTracePanel`**

- Mỗi bước trong danh sách mở rộng render bằng `m.li` với `initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.22 }}` (key = `step_id`, nên chỉ bước mới xuất hiện mới animate).
- Nhãn "Đang kiểm tra..." (dòng ~111) thêm class `vs-shimmer-text`. CSS: chữ gradient `text-amber-300` → `amber-100` → `amber-300`, `background-size: 200% 100%`, `background-clip: text`, `color: transparent`, `animation: vs-shimmer 1.6s linear infinite`; khối reduced-motion phải loại trừ shimmer khỏi lặp vô hạn nhưng giữ chữ đọc được (fallback `color: var(--accent-amber)` khi `@media (prefers-reduced-motion: reduce)`).

- [ ] **Step 2: `VerdictDashboard`**

- **Không** animate: banner `role="alert"` (dòng 148-170), khối tiêu đề verdict + điểm + thanh rủi ro.
- Các khối phụ phía dưới (đồng thuận các tầng, chiến thuật thao túng, quick actions trợ lý) bọc `m.div` với `initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}` và `transition={{ duration: 0.24, delay: staggerDelaysMs(n, 60, 180)[i] / 1000 }}`.

- [ ] **Step 3: Tự cuộn tới kết quả trong `page.tsx`**

- `const scrolledCaseRef = useRef<string | null>(null)`; gắn `id="verdict-result"` cho div bọc kết quả (dòng 366).
- `useEffect` phụ thuộc `report?.case_id`: nếu có report, đọc `getBoundingClientRect().top` của `#verdict-result`, gọi `shouldAutoScrollIntoView({ targetTop, viewportHeight: innerHeight, headerHeight: ANCHOR_OFFSET_PX, alreadyScrolledForCase: scrolledCaseRef.current === report.case_id })`; nếu `true` thì `scrollToElement(el, { offset: -ANCHOR_OFFSET_PX })`; luôn gán `scrolledCaseRef.current = report.case_id`. Không đổi focus (tránh cướp focus khi người dùng đang gõ).

- [ ] **Step 4: Kiểm tra** — typecheck + test PASS. Dev: chạy demo → từng bước tiến trình hiện dần; khi có kết quả, trang tự cuộn nhẹ tới verdict một lần; banner tiểu thương (demo biên lai) hiện ngay không fade; bấm demo khác → cuộn lại một lần cho case mới.
- [ ] **Step 5: Commit** — `git commit -m "feat(frontend): stagger trace/verdict secondary blocks and auto-scroll to result once per case"`

---

### Task 6: Vẽ luồng dữ liệu trên 3 sơ đồ SVG kỹ thuật

**Files:**
- Create: `frontend/src/components/motion/DrawOnView.tsx`
- Modify: `frontend/src/app/technical/page.tsx:118,200`, `frontend/src/app/privacy/page.tsx:191`, `frontend/src/app/globals.css` (thêm `.vs-draw`)

**Interfaces:**
- Consumes: `staggerDelaysMs` (Task 1).
- Produces: `DrawOnView(props: { children: React.ReactNode; maxTotalMs?: number }): JSX.Element` — `maxTotalMs` mặc định `900`.

- [ ] **Step 1: Implement `DrawOnView.tsx` (`"use client"`)**

- Render `<div ref className="vs-draw">{children}</div>`; children là SVG server component hiện có (không sửa nội dung SVG).
- Sau mount, nếu reduced-motion hoặc thiếu `IntersectionObserver` → không làm gì (đường luôn hiển thị).
- Ngược lại: chọn `line[marker-end], path[marker-end], polyline[marker-end]` (24 phần tử: 12 + 4 + 8), với từng phần tử set `style.setProperty("--len", String(el.getTotalLength()))` và `--delay` = `staggerDelaysMs(count, 45, maxTotalMs)[i] + "ms"` theo thứ tự DOM; rồi set `data-draw-ready="true"` trên wrapper.
- `IntersectionObserver` threshold `0.2`: lần đầu giao cắt → set `data-drawn="true"` và `disconnect()`.
- CSS:
  - `.vs-draw[data-draw-ready="true"] :is(line,path,polyline)[marker-end]:not([stroke-dasharray]) { stroke-dasharray: var(--len); stroke-dashoffset: var(--len); opacity: 0; }`
  - `.vs-draw[data-drawn="true"] :is(line,path,polyline)[marker-end]:not([stroke-dasharray]) { stroke-dashoffset: 0; opacity: 1; transition: stroke-dashoffset 520ms ease-out var(--delay), opacity 160ms ease-out var(--delay); }`
  - `:not([stroke-dasharray])` giữ nguyên các mũi tên nét đứt gốc (không vẽ lại chúng). JS cũng bỏ qua chúng khi gán `--len`/`--delay`.

- [ ] **Step 2: Áp dụng** — bọc `<SystemArchitectureSvg />`, `<ThreeTierFusionSvg />` (technical) và `<DataLifecycleSvg />` (privacy) bằng `<DrawOnView>`. Hai page vẫn là Server Component (giữ `export const metadata`).
- [ ] **Step 3: Kiểm tra** — typecheck + test + build PASS. Dev: cuộn tới sơ đồ kiến trúc → mũi tên được vẽ lần lượt trong ≤ ~1,4s; bật "Reduce motion" trong DevTools Rendering → sơ đồ hiển thị đầy đủ ngay; tắt JS → sơ đồ vẫn đầy đủ.
- [ ] **Step 4: Commit** — `git commit -m "feat(frontend): draw architecture/data-flow arrows on scroll into view"`

---

### Task 7: Khai báo giấy phép, QA toàn diện, verify gate

**Files:**
- Modify: `frontend/src/app/technical/page.tsx:1192-1197`, `README.md` (mục thư viện mã nguồn mở)

- [ ] **Step 1: Cập nhật khai báo**

- `/technical` §18 hàng "Thư viện Frontend": thêm `Lenis (MIT) · Motion (MIT)` vào cột thành phần; cột giấy phép giữ `MIT / Apache-2.0 / ISC`.
- `README.md`: thêm `lenis` (MIT, cuộn mượt) và `motion` (MIT, hiệu ứng xuất hiện) vào danh sách thư viện mã nguồn mở; ghi chú các micro-UI tự viết, không sao chép mã nguồn bên thứ ba.

- [ ] **Step 2: Đo bundle** — `npm run build`; ghi "First Load JS" mới vào phần "Kết quả đo". Ngưỡng chấp nhận: `/` tăng `<= 30 kB`; `/technical`, `/privacy` tăng `<= 12 kB`. Vượt ngưỡng → dừng và báo cáo trước khi tiếp tục.

- [ ] **Step 3: QA thủ công bằng trình duyệt (skill `agent-browser`) trên `npm run build && npm start`**

Đánh dấu từng mục:
- [ ] Review Focus 1: DevTools → Rendering → `prefers-reduced-motion: reduce` khi trang đang mở → cuộn native, số hiện ngay, SVG đầy đủ, không shimmer.
- [ ] Review Focus 2: wheel trên đồ thị `/radar` chỉ zoom; mở `CampaignDetailDrawer` rồi `RuleActionModal` chồng lên, đóng modal → trang vẫn khóa; đóng drawer → trang cuộn lại được.
- [ ] Review Focus 3: mục lục `/technical`, skip-link, nút Back trình duyệt sau khi nhảy neo.
- [ ] Review Focus 4: bấm 3 demo liên tiếp nhanh → không còn số "kẹt", không cuộn lặp.
- [ ] Review Focus 5: đang cuộn quán tính ở `/radar` bấm sang `/technical` → mở ở đầu trang.
- [ ] Console không có lỗi hydration / CSP violation.
- [ ] Mobile viewport 390×844: cuộn cảm ứng native, không có spotlight.

- [ ] **Step 4: Verify gate** — từ thư mục gốc: `powershell -ExecutionPolicy Bypass -File scripts/verify.ps1` → Expected: exit 0 (ruff, mypy, pytest 425 passed, tsc 0 lỗi, toàn bộ Node test PASS, `next build` 8/8 route).

- [ ] **Step 5: Commit** — `git commit -m "docs: declare MIT motion libraries and record motion UX QA"`

---

## Ngoài phạm vi (cố ý không làm)

- Không dùng hiệu ứng layout/FLIP cho thu gọn form (`domMax` nặng hơn `domAnimation`); giữ hành vi hiện tại.
- Không background WebGL/shader, hiệu ứng con trỏ, chữ glitch/decrypt.
- Không deploy lên VPS trong plan này; deploy là bước riêng sau khi người dùng duyệt.

## Kết quả đo (điền khi thực thi)

| Route | First Load JS trước | Sau | Chênh lệch |
| :--- | :--- | :--- | :--- |
| `/` | | | |
| `/radar` | | | |
| `/technical` | | | |
| `/privacy` | | | |
