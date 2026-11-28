/**
 * Pure cybersecurity motion state & classification helpers (no DOM, no JSX).
 * Unit-tested directly via `node --test`.
 */
import type {
  AnalysisReport,
  DemoScenario,
  RadarGraphResponse,
  ReceiptVerificationStatus,
  TraceStep,
  VerdictLevel,
} from "../types";

export type ScenarioIconKind = "message" | "receipt" | "vietqr" | "call";

export type PipelineStageKind =
  | "text_analysis"
  | "url_scanning"
  | "ocr_processing"
  | "qr_analysis"
  | "ai_inference"
  | "risk_assessment";

export type VerdictMotionTone =
  | "safe"
  | "safe_unverified"
  | "suspicious"
  | "high_risk"
  | "critical";

export interface AmbientMotionConditions {
  inViewport: boolean;
  documentVisible: boolean;
  reducedMotion: boolean;
  pausedByInteraction?: boolean;
}

export function shouldRunAmbientMotion({
  inViewport,
  documentVisible,
  reducedMotion,
  pausedByInteraction = false,
}: AmbientMotionConditions): boolean {
  return inViewport && documentVisible && !reducedMotion && !pausedByInteraction;
}

export function resolveScenarioIconKind(
  demo: Pick<DemoScenario, "demo_id" | "category_badge" | "image_filename" | "audio_filename">,
): ScenarioIconKind {
  const badge = demo.category_badge.toLowerCase();
  const id = demo.demo_id.toLowerCase();

  if (demo.audio_filename || id.includes("call") || badge.includes("cuộc gọi")) {
    return "call";
  }
  if (id.includes("vietqr") || id.includes("qr") || badge.includes("qr")) {
    return "vietqr";
  }
  if (
    id.includes("bill") ||
    id.includes("receipt") ||
    badge.includes("biên lai") ||
    Boolean(demo.image_filename)
  ) {
    return "receipt";
  }
  return "message";
}

export function classifyTraceStageVisual(
  step: Pick<TraceStep, "step_id" | "title" | "detail">,
): PipelineStageKind {
  const id = step.step_id.trim().toLowerCase();

  if (id === "text_analysis") return "text_analysis";
  if (id === "url_scanning") return "url_scanning";
  if (id === "ocr_processing") return "ocr_processing";
  if (id === "qr_analysis") return "qr_analysis";
  if (id === "ai_inference") return "ai_inference";
  if (id === "risk_assessment") return "risk_assessment";

  if (id === "media_forensics") {
    const hasQrHit = /[1-9]\d*\s*mã\s*qr|vietqr/i.test(step.detail);
    return hasQrHit ? "qr_analysis" : "ocr_processing";
  }
  if (id === "cyber_guardrails") return "url_scanning";
  if (id === "onnx_and_kb") return "ai_inference";
  if (id === "multimodal_calibration") return "risk_assessment";

  const haystack = `${id} ${step.title} ${step.detail}`.toLowerCase();
  if (/\bqr\b|vietqr/.test(haystack)) return "qr_analysis";
  if (/\bocr\b|hình ảnh|biên lai/.test(haystack)) return "ocr_processing";
  if (/\burl\b|đường dẫn|tên miền|sandbox/.test(haystack)) return "url_scanning";
  if (/văn bản|tin nhắn|text/.test(haystack)) return "text_analysis";
  if (/onnx|ai|mô hình|kịch bản/.test(haystack)) return "ai_inference";
  return "risk_assessment";
}

export interface VisibleBackendTracePartition {
  activeSteps: TraceStep[];
  skippedSteps: TraceStep[];
}

/**
 * Preserves backend emission order, deduplicates updated step IDs (latest status wins),
 * and separates `skipped` steps so non-applicable stages are never shown as active work.
 */
export function selectVisibleBackendTraceSteps(
  steps: readonly TraceStep[],
): VisibleBackendTracePartition {
  const order: string[] = [];
  const latestById = new Map<string, TraceStep>();

  for (const step of steps) {
    if (!latestById.has(step.step_id)) {
      order.push(step.step_id);
    }
    latestById.set(step.step_id, step);
  }

  const activeSteps: TraceStep[] = [];
  const skippedSteps: TraceStep[] = [];

  for (const id of order) {
    const step = latestById.get(id);
    if (!step) continue;
    if (step.status === "skipped") {
      skippedSteps.push(step);
    } else {
      activeSteps.push(step);
    }
  }

  return { activeSteps, skippedSteps };
}

export function buildVerdictTransitionKey(
  report: Pick<
    AnalysisReport,
    "case_id" | "verdict" | "risk_score" | "receipt_verification_status"
  >,
): string {
  return `${report.case_id}:${report.verdict}:${report.risk_score}:${report.receipt_verification_status}`;
}

export interface VerdictMotionProfile {
  tone: VerdictMotionTone;
  shouldDrawCheck: boolean;
  emphasizeHonestyGuard: boolean;
}

export function resolveVerdictMotionProfile(
  verdict: VerdictLevel,
  receiptStatus: ReceiptVerificationStatus,
): VerdictMotionProfile {
  if (verdict === "SAFE") {
    const unverifiedReceipt = receiptStatus === "UNVERIFIED_SCREENSHOT";
    return {
      tone: unverifiedReceipt ? "safe_unverified" : "safe",
      shouldDrawCheck: true,
      emphasizeHonestyGuard: unverifiedReceipt,
    };
  }
  if (verdict === "SUSPICIOUS") {
    return { tone: "suspicious", shouldDrawCheck: false, emphasizeHonestyGuard: false };
  }
  if (verdict === "HIGH_RISK") {
    return { tone: "high_risk", shouldDrawCheck: false, emphasizeHonestyGuard: false };
  }
  return { tone: "critical", shouldDrawCheck: false, emphasizeHonestyGuard: false };
}

export interface RadarMotionScope {
  mode: "live" | "demo_mixed" | "demo_only";
  allowLiveAlertPulse: boolean;
  sweepTone: "live_cyan" | "demo_slate";
  scopeAriaNote: string;
}

export function resolveRadarMotionScope(
  dataScope: RadarGraphResponse["data_scope"] | undefined,
  hasDemoData: boolean,
): RadarMotionScope {
  if (dataScope === "live" && !hasDemoData) {
    return {
      mode: "live",
      allowLiveAlertPulse: true,
      sweepTone: "live_cyan",
      scopeAriaNote: "Chế độ quét dữ liệu vận hành thực tế",
    };
  }
  if (dataScope === "mixed_with_demo") {
    return {
      mode: "demo_mixed",
      allowLiveAlertPulse: false,
      sweepTone: "demo_slate",
      scopeAriaNote: "Chế độ hỗn hợp có kèm dữ liệu mẫu minh họa",
    };
  }
  return {
    mode: "demo_only",
    allowLiveAlertPulse: false,
    sweepTone: "demo_slate",
    scopeAriaNote: "Môi trường dữ liệu mẫu minh họa, không phải cảnh báo khẩn cấp thực tế",
  };
}

export interface RadarEdgeAnimationDecision {
  animated: boolean;
  variant: "none" | "inspect_cyan" | "live_blocked_amber" | "demo_inspect_cyan";
}

export function shouldAnimateRadarEdge(opts: {
  isDirectEdge: boolean;
  isDemoEdge: boolean;
  isBlockedEdge: boolean;
  isDense: boolean;
  selectedNodeId: string | null;
  allowLiveAlertPulse: boolean;
}): RadarEdgeAnimationDecision {
  if (!opts.selectedNodeId || !opts.isDirectEdge) {
    return { animated: false, variant: "none" };
  }
  if (opts.isDemoEdge || !opts.allowLiveAlertPulse) {
    return { animated: true, variant: "demo_inspect_cyan" };
  }
  if (opts.isBlockedEdge) {
    return { animated: true, variant: "live_blocked_amber" };
  }
  return { animated: true, variant: "inspect_cyan" };
}
