/**
 * Pure-TS Explainable AI (XAI) derivations from real backend AnalysisReport fields.
 * Strictly zero React/JSX, zero `@/` imports, and ZERO fabricated weights or scores.
 */

import type {
  AnalysisReport,
  EvidenceItem,
  ScamClassifierOutput,
  SeverityLevel,
  TraceStep,
} from "./types";

export type EvidenceTabKey = "all" | "ela" | "receipt" | "vietqr" | "url";

export interface DetectedSignal {
  id: string;
  label: string;
  category: "security" | "forensics" | "behavior" | "classifier" | "advisory";
  severity: SeverityLevel;
  detail: string;
  evidenceTab: EvidenceTabKey;
  evidenceSource?: string;
  verified: boolean;
}

export interface MeasuredSignalFactor {
  id: string;
  label: string;
  score: number;
  unit: "points_100" | "raw_score_pct";
  note: string;
  evidenceTab: EvidenceTabKey;
}

export interface ClassifierClassItem {
  key: string;
  labelVi: string;
  probability: number;
  percent: number;
  isPredicted: boolean;
  tone: "safe" | "advisory" | "risk" | "injection";
}

export interface EvidenceSeverityCount {
  severity: SeverityLevel;
  count: number;
  sharePct: number;
}

export interface EvidenceSourceCount {
  source: string;
  count: number;
  highestSeverity: SeverityLevel;
  evidenceTab: EvidenceTabKey;
}

export interface TraceTimelineEntry {
  step_id: string;
  title: string;
  status: TraceStep["status"];
  detail: string;
  duration_ms: number;
  sharePct: number;
}

export interface HighlightedTextSegment {
  text: string;
  highlighted: boolean;
  matchedPhrase?: string;
}

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

const SEVERITY_ORDER: readonly SeverityLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const E5_CLASS_LABELS: Record<
  string,
  { labelVi: string; tone: ClassifierClassItem["tone"] }
> = {
  SAFE_NORMAL: { labelVi: "Bình thường", tone: "safe" },
  SAFE_ADVISORY: { labelVi: "Khuyến cáo an toàn", tone: "advisory" },
  SCAM_IMPERSONATION: { labelVi: "Giả mạo cơ quan / tổ chức", tone: "risk" },
  SCAM_TASK_INVEST_LOAN: { labelVi: "Việc nhẹ / Đầu tư / Vay", tone: "risk" },
  SCAM_PHISHING_APK_OTP: { labelVi: "Link giả / APK / OTP", tone: "risk" },
  SCAM_URGENT_BORROW: { labelVi: "Vay tiền khẩn cấp", tone: "risk" },
  PROMPT_INJECTION: { labelVi: "Chèn chỉ thị AI", tone: "injection" },
};

export function mapEvidenceSourceToTab(source: string): EvidenceTabKey {
  switch (source) {
    case "image_forensics":
    case "ocr_engine":
      return "ela";
    case "receipt_validator":
      return "receipt";
    case "vietqr_parser":
      return "vietqr";
    case "url_inspector":
    case "phishing_sandbox":
      return "url";
    default:
      return "all";
  }
}

/**
 * Build real, evidence-linked detected signals directly from report fields.
 * Never invents signals absent from the backend AnalysisReport.
 */
export function buildDetectedSignals(report: AnalysisReport): DetectedSignal[] {
  const signals: DetectedSignal[] = [];
  const seen = new Set<string>();

  function pushSignal(signal: DetectedSignal) {
    if (seen.has(signal.id)) return;
    seen.add(signal.id);
    signals.push(signal);
  }

  if (report.active_block_rule_hit) {
    pushSignal({
      id: "block-rule-hit",
      label: "Trùng danh sách chặn hệ thống",
      category: "security",
      severity: "CRITICAL",
      detail: "Dấu hiệu trong hồ sơ khớp với quy tắc chặn đang có hiệu lực trên hệ thống giám sát.",
      evidenceTab: "all",
      evidenceSource: "fraud_ops_radar",
      verified: true,
    });
  }

  if (report.prompt_injection_detected) {
    pushSignal({
      id: "prompt-injection",
      label: "Phát hiện nỗ lực chèn chỉ thị đánh lừa AI",
      category: "security",
      severity: "HIGH",
      detail: "Nội dung chứa mẫu câu tìm cách ghi đè chỉ dẫn phân tích của hệ thống.",
      evidenceTab: "all",
      evidenceSource: "guardrails",
      verified: true,
    });
  }

  for (const uf of report.url_findings) {
    if (uf.is_blocked_ssrf) {
      pushSignal({
        id: `url-ssrf-${uf.domain}`,
        label: "Địa chỉ mạng nội bộ bị chặn (SSRF)",
        category: "security",
        severity: "CRITICAL",
        detail: `Hệ thống đã chặn truy cập tới ${uf.domain} theo chính sách an toàn mạng.`,
        evidenceTab: "url",
        evidenceSource: "url_inspector",
        verified: true,
      });
    }
    if (uf.spoofed_brand) {
      pushSignal({
        id: `url-spoof-${uf.spoofed_brand}`,
        label: `Tên miền có dấu hiệu giả mạo ${uf.spoofed_brand}`,
        category: "security",
        severity: "CRITICAL",
        detail: `Tên miền ${uf.normalized_ascii_domain || uf.domain} gần giống thương hiệu chính thống ${uf.spoofed_brand}.`,
        evidenceTab: "url",
        evidenceSource: "url_inspector",
        verified: true,
      });
    }
    if (uf.is_idn_homoglyph) {
      pushSignal({
        id: `url-idn-${uf.domain}`,
        label: "Tên miền dùng ký tự đồng hình (IDN)",
        category: "security",
        severity: "HIGH",
        detail: `Tên miền sử dụng ký tự dễ nhầm lẫn: ${uf.normalized_ascii_domain || uf.domain}.`,
        evidenceTab: "url",
        evidenceSource: "url_inspector",
        verified: true,
      });
    } else if (uf.risk_points >= 40) {
      pushSignal({
        id: `url-risk-${uf.domain}`,
        label: "Đường dẫn bất thường",
        category: "security",
        severity: uf.risk_points >= 75 ? "CRITICAL" : "HIGH",
        detail: uf.reasons[0] ?? `Tên miền ${uf.domain} đạt mức rủi ro ${uf.risk_points}/100.`,
        evidenceTab: "url",
        evidenceSource: "url_inspector",
        verified: true,
      });
    }
  }

  if (report.sandbox) {
    if (report.sandbox.has_otp_field) {
      pushSignal({
        id: "sandbox-otp",
        label: "Trang web yêu cầu nhập mã OTP / PIN",
        category: "security",
        severity: "CRITICAL",
        detail: "Môi trường trình duyệt cách ly phát hiện biểu mẫu thu thập mã OTP hoặc mã PIN.",
        evidenceTab: "url",
        evidenceSource: "phishing_sandbox",
        verified: true,
      });
    }
    if (report.sandbox.has_password_field) {
      pushSignal({
        id: "sandbox-password",
        label: "Trang web yêu cầu đăng nhập mật khẩu",
        category: "security",
        severity: "HIGH",
        detail: "Môi trường cách ly ghi nhận ô nhập mật khẩu trên trang đích đáng ngờ.",
        evidenceTab: "url",
        evidenceSource: "phishing_sandbox",
        verified: true,
      });
    }
    if (report.sandbox.has_apk_download) {
      pushSignal({
        id: "sandbox-apk",
        label: "Phát hiện liên kết tải tệp cài đặt .APK",
        category: "security",
        severity: "CRITICAL",
        detail: "Trang đích có dấu hiệu phát tán tệp cài đặt Android (.APK) ngoài kho ứng dụng.",
        evidenceTab: "url",
        evidenceSource: "phishing_sandbox",
        verified: true,
      });
    }
  }

  for (const vqr of report.vietqr_findings) {
    if (vqr.receive_scam_detected) {
      pushSignal({
        id: "vietqr-receive-scam",
        label: "Bẫy quét mã VietQR để nhận / hoàn tiền",
        category: "forensics",
        severity: "CRITICAL",
        detail: "Mã VietQR thực chất là lệnh chuyển tiền đi, không thể dùng để nhận tiền hoàn.",
        evidenceTab: "vietqr",
        evidenceSource: "vietqr_parser",
        verified: true,
      });
    }
    if (vqr.beneficiary_mismatch) {
      pushSignal({
        id: "vietqr-mismatch",
        label: "Lệch số tài khoản thụ hưởng trên mã VietQR",
        category: "forensics",
        severity: "CRITICAL",
        detail: "Tài khoản giải mã từ VietQR không trùng khớp với số tài khoản cửa hàng đã nhập.",
        evidenceTab: "vietqr",
        evidenceSource: "vietqr_parser",
        verified: true,
      });
    }
    if (vqr.kind === "INVALID_CRC_VIETQR" || !vqr.crc_valid) {
      pushSignal({
        id: "vietqr-invalid-crc",
        label: "Mã VietQR sai mã kiểm tra toàn vẹn CRC-16",
        category: "forensics",
        severity: "HIGH",
        detail: "Chuỗi EMVCo VietQR không vượt qua kiểm định CRC-16 hoặc sai cấu trúc TLV.",
        evidenceTab: "vietqr",
        evidenceSource: "vietqr_parser",
        verified: true,
      });
    }
  }

  if (report.receipt_logic) {
    if (report.receipt_logic.is_replayed) {
      pushSignal({
        id: "receipt-replayed",
        label: "Ảnh biên lai hoặc mã giao dịch bị gửi lặp lại",
        category: "forensics",
        severity: "CRITICAL",
        detail: "Hệ thống ghi nhận vân tay ảnh hoặc mã tham chiếu này đã xuất hiện trước đó.",
        evidenceTab: "receipt",
        evidenceSource: "receipt_validator",
        verified: true,
      });
    }
    if (report.receipt_logic.beneficiary_mismatch) {
      pushSignal({
        id: "receipt-beneficiary-mismatch",
        label: "Sai lệch tài khoản nhận trên biên lai",
        category: "forensics",
        severity: "CRITICAL",
        detail: "Số tài khoản đọc được trên ảnh biên lai không khớp tài khoản của cửa hàng.",
        evidenceTab: "receipt",
        evidenceSource: "receipt_validator",
        verified: true,
      });
    }
    if (
      report.receipt_logic.amount_format_anomaly ||
      report.receipt_logic.geometry_anomaly ||
      report.receipt_logic.timestamp_anomaly ||
      !report.receipt_logic.reference_valid
    ) {
      pushSignal({
        id: "receipt-logic-anomaly",
        label: "Bất thường cấu trúc nghiệp vụ biên lai",
        category: "forensics",
        severity: report.receipt_logic.logic_risk_points >= 40 ? "HIGH" : "MEDIUM",
        detail:
          report.receipt_logic.reasons[0] ??
          "Phát hiện sai lệch về định dạng số tiền, thời gian, mã tham chiếu hoặc bố cục chữ.",
        evidenceTab: "receipt",
        evidenceSource: "receipt_validator",
        verified: true,
      });
    }
  }

  const allForensics =
    report.image_forensics_list && report.image_forensics_list.length > 0
      ? report.image_forensics_list
      : report.image_forensics
        ? [report.image_forensics]
        : [];
  const maxTamper = allForensics.reduce((acc, item) => Math.max(acc, item.tamper_score), 0);
  const hasEditSoftware = allForensics.some((item) => item.editing_software_detected);
  if (maxTamper >= 35 || hasEditSoftware) {
    pushSignal({
      id: "image-tamper",
      label: hasEditSoftware
        ? "Phát hiện dấu vết phần mềm chỉnh sửa ảnh"
        : "Bất thường sai số nén ảnh (ELA)",
      category: "forensics",
      severity: maxTamper >= 50 ? "HIGH" : "MEDIUM",
      detail: `Mức nghi vấn chỉnh sửa hình ảnh đạt ${maxTamper}/100.`,
      evidenceTab: "ela",
      evidenceSource: "image_forensics",
      verified: true,
    });
  }

  for (const tactic of report.manipulation_tactics) {
    const clean = tactic.trim();
    if (!clean) continue;
    pushSignal({
      id: `tactic-${clean.toLowerCase()}`,
      label: clean,
      category: "behavior",
      severity: report.risk_score >= 75 ? "HIGH" : "MEDIUM",
      detail: "Dấu hiệu thao túng tâm lý hoặc gây áp lực ghi nhận từ nội dung hội thoại.",
      evidenceTab: "all",
      evidenceSource: "gemini_vision",
      verified: false,
    });
  }

  for (const playbook of report.matched_playbooks) {
    const clean = playbook.trim();
    if (!clean) continue;
    pushSignal({
      id: `playbook-${clean.toLowerCase()}`,
      label: `Khớp kịch bản: ${clean}`,
      category: "classifier",
      severity: report.risk_score >= 75 ? "HIGH" : "MEDIUM",
      detail: "Nội dung có điểm tương đồng với kịch bản cảnh báo trong kho tri thức Việt Nam.",
      evidenceTab: "all",
      evidenceSource: "pipeline",
      verified: false,
    });
  }

  if (report.safety_advisory_detected && report.verdict === "SAFE") {
    pushSignal({
      id: "safety-advisory",
      label: "Nội dung dạng khuyến cáo phòng chống lừa đảo",
      category: "advisory",
      severity: "INFO",
      detail: "Bộ lọc nhận diện đây là thông điệp tuyên truyền/cảnh báo phòng tránh rủi ro.",
      evidenceTab: "all",
      evidenceSource: "guardrails",
      verified: true,
    });
  }

  return signals.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}

/**
 * Extract ONLY real numeric measurements returned by backend components for this case.
 * Does NOT fabricate weights or missing scores.
 */
export function buildMeasuredSignalFactors(report: AnalysisReport): MeasuredSignalFactor[] {
  const factors: MeasuredSignalFactor[] = [];

  if (report.active_block_rule_hit) {
    factors.push({
      id: "factor-block-rule",
      label: "Danh sách chặn vận hành (Radar)",
      score: 96,
      unit: "points_100",
      note: "Áp dụng ngưỡng sàn tối thiểu 96/100 khi khớp quy tắc chặn đang hiệu lực.",
      evidenceTab: "all",
    });
  }

  if (report.url_findings.length > 0) {
    const maxUrl = Math.max(...report.url_findings.map((u) => u.risk_points));
    factors.push({
      id: "factor-url",
      label: "Kiểm tra đường dẫn & tên miền",
      score: maxUrl,
      unit: "points_100",
      note: `Điểm cao nhất trên ${report.url_findings.length} đường dẫn đã phân tích.`,
      evidenceTab: "url",
    });
  }

  if (report.sandbox && (report.sandbox.available || report.sandbox.blocked_ssrf)) {
    factors.push({
      id: "factor-sandbox",
      label: "Trình duyệt cách ly (Sandbox)",
      score: report.sandbox.risk_points,
      unit: "points_100",
      note: report.sandbox.blocked_ssrf
        ? "Đã chặn truy cập địa chỉ nội bộ (SSRF)."
        : "Đánh giá biểu mẫu đăng nhập, OTP và tệp tải về trên trang đích.",
      evidenceTab: "url",
    });
  }

  const allForensics =
    report.image_forensics_list && report.image_forensics_list.length > 0
      ? report.image_forensics_list
      : report.image_forensics
        ? [report.image_forensics]
        : [];
  if (allForensics.length > 0) {
    const maxTamper = Math.max(...allForensics.map((f) => f.tamper_score));
    factors.push({
      id: "factor-ela",
      label: "Phân tích chỉnh sửa ảnh (ELA / EXIF)",
      score: maxTamper,
      unit: "points_100",
      note: `Điểm nghi vấn chỉnh sửa cao nhất trên ${allForensics.length} hình ảnh.`,
      evidenceTab: "ela",
    });
  }

  if (report.receipt_logic && report.receipt_logic.is_receipt_candidate) {
    factors.push({
      id: "factor-receipt",
      label: "Đối chiếu nghiệp vụ biên lai",
      score: report.receipt_logic.logic_risk_points,
      unit: "points_100",
      note: "Kiểm tra mã tham chiếu, định dạng tiền, thời gian, hình học chữ và lặp lại.",
      evidenceTab: "receipt",
    });
  }

  if (report.classifier?.available) {
    factors.push({
      id: "factor-onnx",
      label: "Bộ phân loại cục bộ (E5 INT8 ONNX)",
      score: Math.round(report.classifier.scam_probability * 100),
      unit: "raw_score_pct",
      note: `Điểm thô nhóm rủi ro từ E5 ONNX (${report.classifier.latency_ms} ms) — không phải xác suất thống kê đã hiệu chuẩn.`,
      evidenceTab: "all",
    });
  }

  return factors.sort((a, b) => b.score - a.score);
}

/**
 * Convert real E5 ONNX `class_probabilities` into sorted Vietnamese chart items.
 * Returns empty array if classifier is unavailable or class probabilities were not provided.
 */
export function buildClassifierDistribution(
  classifier: ScamClassifierOutput | null | undefined,
): ClassifierClassItem[] {
  if (!classifier?.available) return [];
  const entries = Object.entries(classifier.class_probabilities ?? {}).filter(
    ([, val]) => typeof val === "number" && Number.isFinite(val) && val >= 0,
  );
  if (entries.length === 0) return [];

  return entries
    .map(([key, prob]) => {
      const clamped = Math.max(0, Math.min(1, prob));
      const meta = E5_CLASS_LABELS[key] ?? { labelVi: key, tone: "risk" as const };
      return {
        key,
        labelVi: meta.labelVi,
        probability: clamped,
        percent: Math.round(clamped * 1000) / 10,
        isPredicted: key === classifier.predicted_label,
        tone: meta.tone,
      };
    })
    .sort((a, b) => b.probability - a.probability);
}

export function buildEvidenceDistribution(evidence: readonly EvidenceItem[]): {
  bySeverity: EvidenceSeverityCount[];
  bySource: EvidenceSourceCount[];
  total: number;
} {
  const total = evidence.length;
  const sevMap = new Map<SeverityLevel, number>();
  const srcMap = new Map<string, { count: number; highestSeverity: SeverityLevel }>();

  for (const item of evidence) {
    sevMap.set(item.severity, (sevMap.get(item.severity) ?? 0) + 1);
    const prev = srcMap.get(item.source);
    if (!prev) {
      srcMap.set(item.source, { count: 1, highestSeverity: item.severity });
    } else {
      prev.count += 1;
      if (SEVERITY_RANK[item.severity] > SEVERITY_RANK[prev.highestSeverity]) {
        prev.highestSeverity = item.severity;
      }
    }
  }

  const bySeverity: EvidenceSeverityCount[] = SEVERITY_ORDER.map((severity) => {
    const count = sevMap.get(severity) ?? 0;
    return {
      severity,
      count,
      sharePct: total > 0 ? Math.round((count / total) * 100) : 0,
    };
  }).filter((item) => item.count > 0);

  const bySource: EvidenceSourceCount[] = Array.from(srcMap.entries())
    .map(([source, info]) => ({
      source,
      count: info.count,
      highestSeverity: info.highestSeverity,
      evidenceTab: mapEvidenceSourceToTab(source),
    }))
    .sort(
      (a, b) =>
        SEVERITY_RANK[b.highestSeverity] - SEVERITY_RANK[a.highestSeverity] ||
        b.count - a.count,
    );

  return { bySeverity, bySource, total };
}

export function buildTraceTimeline(trace: readonly TraceStep[]): {
  entries: TraceTimelineEntry[];
  totalMs: number;
} {
  const totalMs = trace.reduce(
    (sum, step) => sum + (step.status !== "running" ? Math.max(0, step.duration_ms) : 0),
    0,
  );
  const safeDenom = Math.max(1, totalMs);

  const entries: TraceTimelineEntry[] = trace.map((step) => {
    const ms = Math.max(0, step.duration_ms);
    return {
      step_id: step.step_id,
      title: step.title,
      status: step.status,
      detail: step.detail,
      duration_ms: ms,
      sharePct: step.status === "skipped" ? 0 : Math.max(2, Math.round((ms / safeDenom) * 100)),
    };
  });

  return { entries, totalMs };
}

/**
 * Pure-TS suspicious phrase highlighter for submitted & OCR-extracted text.
 * Produces plain text segments (zero HTML) for safe React <mark> rendering.
 */
export function highlightSuspiciousText(
  text: string,
  phrases: readonly string[],
): HighlightedTextSegment[] {
  if (!text) return [];
  const cleanedPhrases = Array.from(
    new Set(
      phrases
        .map((p) => p.trim())
        .filter((p) => p.length >= 2 && p.length <= 240),
    ),
  ).sort((a, b) => b.length - a.length);

  if (cleanedPhrases.length === 0) {
    return [{ text, highlighted: false }];
  }

  const lowerText = text.toLowerCase();
  const lowerPhrases = cleanedPhrases.map((p) => ({
    raw: p,
    lower: p.toLowerCase(),
  }));

  const segments: HighlightedTextSegment[] = [];
  let cursor = 0;
  let plainStart = 0;

  while (cursor < text.length) {
    let matched: { raw: string; len: number } | null = null;
    for (const item of lowerPhrases) {
      if (lowerText.startsWith(item.lower, cursor)) {
        matched = { raw: item.raw, len: item.lower.length };
        break;
      }
    }

    if (matched) {
      if (cursor > plainStart) {
        segments.push({ text: text.slice(plainStart, cursor), highlighted: false });
      }
      segments.push({
        text: text.slice(cursor, cursor + matched.len),
        highlighted: true,
        matchedPhrase: matched.raw,
      });
      cursor += matched.len;
      plainStart = cursor;
    } else {
      cursor += 1;
    }
  }

  if (plainStart < text.length) {
    segments.push({ text: text.slice(plainStart), highlighted: false });
  }

  return segments;
}
