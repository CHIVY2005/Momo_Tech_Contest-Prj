/**
 * Pure-TS Command Palette registry & Vietnamese diacritic-insensitive search filter.
 * Strictly zero PII, zero cross-case history exposure, zero React/JSX, zero `@/` imports.
 */

export type CommandGroup = "quick" | "navigation" | "workspace" | "safety";

export const COMMAND_GROUP_ORDER: readonly CommandGroup[] = [
  "quick",
  "workspace",
  "navigation",
  "safety",
];

export const COMMAND_PALETTE_PLACEHOLDER = "Tìm kiếm lệnh hoặc chức năng...";

export interface PaletteCommand {
  id: string;
  label: string;
  description: string;
  group: CommandGroup;
  keywords: readonly string[];
  shortcutHint?: string;
  requiresActiveCase?: boolean;
  disabled?: boolean;
  action:
    | { type: "navigate"; href: string }
    | { type: "external_official"; href: string }
    | { type: "event"; name: string; detail?: Record<string, string> };
}

export const COMMAND_GROUP_LABELS: Record<CommandGroup, string> = {
  quick: "Hành động nhanh",
  workspace: "Hồ sơ đang mở",
  navigation: "Điều hướng trang",
  safety: "Hướng dẫn & Kênh chính thức",
};

export function normalizeVietnameseSearch(input: string): string {
  return input
    .normalize("NFC")
    .toLowerCase()
    .replace(/đ/g, "d")
    .normalize("NFD")
    .replace(/\p{Mn}+/gu, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function buildPaletteCommands(context: {
  hasActiveCase: boolean;
  maskedCaseId: string | null;
  pathname: string;
}): PaletteCommand[] {
  const commands: PaletteCommand[] = [
    {
      id: "new-analysis",
      label: "Bắt đầu phân tích mới",
      description: "Mở khung nhập liệu kiểm tra tin nhắn, đường dẫn, biên lai hoặc mã QR.",
      group: "quick",
      keywords: ["moi", "phan tich", "kiem tra", "new", "scan", "workbench"],
      action:
        context.pathname === "/"
          ? { type: "event", name: "verishield:new-analysis" }
          : { type: "navigate", href: "/" },
    },
  ];

  if (context.hasActiveCase && context.pathname === "/") {
    const caseBadge = context.maskedCaseId ? ` (${context.maskedCaseId})` : "";
    commands.push(
      {
        id: "open-assistant",
        label: `Mở Trợ lý VeriShield${caseBadge}`,
        description: "Mở khung hỏi đáp ngữ cảnh an toàn cho hồ sơ hiện tại.",
        group: "workspace",
        keywords: ["tro ly", "chat", "ai", "assistant", "hoi dap"],
        requiresActiveCase: true,
        action: { type: "event", name: "verishield:open-assistant" },
      },
      {
        id: "ws-xai",
        label: "Mở Giải thích AI (Explainable AI)",
        description: "Xem đồng hồ rủi ro, tín hiệu phát hiện, phân bố E5 ONNX & dòng thời gian.",
        group: "workspace",
        keywords: ["xai", "giai thich", "bieu do", "gauge", "onnx", "risk"],
        requiresActiveCase: true,
        action: {
          type: "event",
          name: "verishield:workspace-tab",
          detail: { tab: "xai" },
        },
      },
      {
        id: "ws-graph",
        label: "Mở Sơ đồ mối liên hệ thực thể",
        description: "Khám phá đồ thị URL, tên miền, STK, SĐT và trạng thái xác minh.",
        group: "workspace",
        keywords: ["so do", "do thi", "graph", "lien ket", "thuc the", "flow"],
        requiresActiveCase: true,
        action: {
          type: "event",
          name: "verishield:workspace-tab",
          detail: { tab: "graph" },
        },
      },
      {
        id: "ws-overview",
        label: "Mở Bằng chứng & Hướng dẫn ứng phó",
        description: "Quay lại danh sách bằng chứng, ELA, VietQR, URL và gợi ý trả lời.",
        group: "workspace",
        keywords: ["bang chung", "evidence", "ela", "vietqr", "bien lai", "ung pho"],
        requiresActiveCase: true,
        action: {
          type: "event",
          name: "verishield:workspace-tab",
          detail: { tab: "overview" },
        },
      },
    );
  }

  commands.push(
    {
      id: "nav-home",
      label: "Kiểm tra lừa đảo (Trang chính)",
      description: "Chuyển tới không gian kiểm tra đa phương thức VeriShield AI.",
      group: "navigation",
      keywords: ["trang chu", "home", "kiem tra", "lua dao"],
      action: { type: "navigate", href: "/" },
    },
    {
      id: "nav-radar",
      label: "Mở Trung tâm Giám sát gian lận (Radar)",
      description: "Xem mạng lưới chiến dịch IOC, hàng đợi xử lý và quản lý quy tắc chặn TTL.",
      group: "navigation",
      keywords: ["radar", "giam sat", "chien dich", "ioc", "chan", "block"],
      action: { type: "navigate", href: "/radar" },
    },
    {
      id: "nav-technical",
      label: "Công nghệ & Kiến trúc hệ thống",
      description: "Đọc tài liệu phân tích 3 tầng, E5 INT8 ONNX, RAG lai và giấy phép nguồn mở.",
      group: "navigation",
      keywords: ["cong nghe", "ky thuat", "technical", "kien truc", "onnx", "giay phep"],
      action: { type: "navigate", href: "/technical" },
    },
    {
      id: "nav-privacy",
      label: "Chính sách quyền riêng tư",
      description: "Xem cách VeriShield che giấu PII, xử lý cục bộ và không lưu tệp media gốc.",
      group: "navigation",
      keywords: ["quyen rieng tu", "privacy", "bao mat", "pii", "du lieu"],
      action: { type: "navigate", href: "/privacy" },
    },
    {
      id: "safety-receipt-rule",
      label: "Hướng dẫn xác minh biên lai người bán",
      description: "Nguyên tắc đối chiếu số dư thực tế & Soundbox — không giao hàng chỉ từ ảnh chụp.",
      group: "safety",
      keywords: ["bien lai", "nguoi ban", "soundbox", "so du", "an toan"],
      action: { type: "navigate", href: "/technical#ocr-phan-tich-anh" },
    },
    {
      id: "safety-security-controls",
      label: "Biện pháp phòng thủ bảo mật & chống SSRF",
      description: "Xem cơ chế phòng chống SSRF, Prompt Injection và kiểm soát truy cập phiên.",
      group: "safety",
      keywords: ["bao mat", "ssrf", "xss", "an toan", "security"],
      action: { type: "navigate", href: "/technical#bien-phap-bao-mat" },
    },
    {
      id: "safety-ncsc",
      label: "Mở Cổng Cảnh báo An toàn thông tin (NCSC)",
      description: "Trang chính thức canhbao.khonggianmang.vn để tra cứu & phản ánh lừa đảo.",
      group: "safety",
      keywords: ["ncsc", "cong canh bao", "khong gian mang", "chinh thuc", "trinh bao"],
      action: { type: "external_official", href: "https://canhbao.khonggianmang.vn" },
    },
  );

  return commands;
}

export function filterPaletteCommands(
  commands: readonly PaletteCommand[],
  query: string,
): PaletteCommand[] {
  const normQuery = normalizeVietnameseSearch(query);
  if (!normQuery) return [...commands];
  const tokens = normQuery.split(" ").filter(Boolean);

  return commands.filter((cmd) => {
    const haystack = normalizeVietnameseSearch(
      [cmd.label, cmd.description, ...cmd.keywords].join(" "),
    );
    return tokens.every((tok) => haystack.includes(tok));
  });
}

export interface GroupedPaletteCommands {
  groups: Array<{ group: CommandGroup; items: PaletteCommand[] }>;
  flat: PaletteCommand[];
}

export function groupPaletteCommands(
  commands: readonly PaletteCommand[],
): GroupedPaletteCommands {
  const groups: Array<{ group: CommandGroup; items: PaletteCommand[] }> = [];
  for (const grp of COMMAND_GROUP_ORDER) {
    const items = commands.filter((cmd) => cmd.group === grp);
    if (items.length > 0) {
      groups.push({ group: grp, items });
    }
  }
  return {
    groups,
    flat: groups.flatMap((g) => g.items),
  };
}

export function resolveActiveCommandId(
  commands: readonly PaletteCommand[],
  currentActiveId: string | null,
): string | null {
  if (currentActiveId !== null) {
    const match = commands.find((cmd) => cmd.id === currentActiveId && !cmd.disabled);
    if (match) return match.id;
  }
  const firstEnabled = commands.find((cmd) => !cmd.disabled);
  return firstEnabled ? firstEnabled.id : null;
}

export type CommandNavDirection = "next" | "prev" | "first" | "last";

export function getNextActiveCommandId(
  commands: readonly PaletteCommand[],
  currentActiveId: string | null,
  direction: CommandNavDirection,
): string | null {
  const enabled = commands.filter((cmd) => !cmd.disabled);
  if (enabled.length === 0) return null;

  if (direction === "first") {
    return enabled[0]!.id;
  }
  if (direction === "last") {
    return enabled[enabled.length - 1]!.id;
  }

  const currentIdx = enabled.findIndex((cmd) => cmd.id === currentActiveId);
  if (direction === "next") {
    if (currentIdx === -1) return enabled[0]!.id;
    return enabled[(currentIdx + 1) % enabled.length]!.id;
  }

  if (currentIdx === -1) return enabled[enabled.length - 1]!.id;
  return enabled[(currentIdx - 1 + enabled.length) % enabled.length]!.id;
}

export interface MinimalScrollParams {
  containerTop: number;
  containerBottom: number;
  scrollTop: number;
  scrollHeight: number;
  clientHeight: number;
  itemTop: number;
  itemBottom: number;
  paddingTop?: number;
  paddingBottom?: number;
  snapToTop?: boolean;
}

const SCROLL_SUBPIXEL_EPSILON = 0.05;

export function computeMinimalScrollTop(params: MinimalScrollParams): number {
  const maxScroll = Math.max(0, params.scrollHeight - params.clientHeight);
  if (maxScroll === 0) return 0;
  if (params.snapToTop) return 0;

  const padTop = Math.max(0, params.paddingTop ?? 0);
  const padBottom = Math.max(0, params.paddingBottom ?? 0);
  const visibleTop = params.containerTop + padTop;
  const visibleBottom = params.containerBottom - padBottom;
  const itemHeight = params.itemBottom - params.itemTop;
  const visibleHeight = Math.max(0, visibleBottom - visibleTop);

  if (params.itemTop < visibleTop - SCROLL_SUBPIXEL_EPSILON || itemHeight > visibleHeight) {
    const target = params.scrollTop + (params.itemTop - visibleTop);
    return Math.min(maxScroll, Math.max(0, Math.floor(target)));
  }

  if (params.itemBottom > visibleBottom + SCROLL_SUBPIXEL_EPSILON) {
    const target = params.scrollTop + (params.itemBottom - visibleBottom);
    return Math.min(maxScroll, Math.max(0, Math.ceil(target)));
  }

  return Math.min(maxScroll, Math.max(0, params.scrollTop));
}

export interface PointerPoint {
  x: number;
  y: number;
}

export function hasPointerMoved(
  previous: PointerPoint | null,
  next: PointerPoint,
  thresholdPx = 2,
): boolean {
  if (previous === null) return true;
  const dx = next.x - previous.x;
  const dy = next.y - previous.y;
  return dx * dx + dy * dy >= thresholdPx * thresholdPx;
}
