import {
  isValidAnalysisReport,
  isValidTraceStep,
  sanitizeValidationErrorDetail,
} from "./formatters.ts";
import { consumeUtf8SseStream } from "./sse.ts";
import type {
  AnalysisReport,
  AssistantChatPayload,
  AssistantCitationItem,
  AssistantDoneEvent,
  AssistantErrorEvent,
  AssistantEvidenceReportEvent,
  AssistantSafetyNoticeEvent,
  AssistantStatusEvent,
  AssistantStreamHandlers,
  AssistantToolStatusEvent,
  BlockRule,
  CaseSessionInfo,
  CreateBlockRuleRequest,
  DemoScenario,
  PersistEvidenceResponse,
  RadarGraphResponse,
  SystemHealthResponse,
  TraceStep,
} from "./types";

export {
  formatVietQrAmount,
  isValidAnalysisReport,
  isValidTraceStep,
  maskDisplayIoc,
  sanitizeValidationErrorDetail,
  shouldShowReceiptCard,
  validateAnalystPinInput,
} from "./formatters.ts";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "").replace(/\/+$/, "");

function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

export async function fetchAssistantCase(caseId: string, token: string, signal?: AbortSignal): Promise<AnalysisReport | null> {
  const response = await fetch(apiUrl(`/api/v1/cases/${encodeURIComponent(caseId)}`), {
    headers: { "X-Case-Access-Token": token },
    cache: "no-store",
    signal,
  });
  if (response.status === 401 || response.status === 403 || response.status === 404) return null;
  if (!response.ok) throw new Error("Không thể kiểm tra quyền truy cập hồ sơ lúc này.");
  const report: unknown = await response.json();
  return isValidAnalysisReport(report) && report.case_id === caseId ? report : null;
}

async function extractErrorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string" && body.detail.trim()) {
      return body.detail;
    }
    if (Array.isArray(body.detail) && body.detail.length > 0) {
      return sanitizeValidationErrorDetail(body.detail);
    }
  } catch {
    // Ignore non-JSON error bodies
  }
  if (res.status === 413) {
    return "Tệp tải lên vượt quá dung lượng tối đa 10 MB.";
  }
  if (res.status === 429) {
    return "Bạn thao tác quá nhanh. Vui lòng thử lại sau ít giây.";
  }
  return "Không thể hoàn thành yêu cầu lúc này. Vui lòng thử lại sau.";
}

export async function fetchHealth(signal?: AbortSignal): Promise<SystemHealthResponse> {
  const res = await fetch(apiUrl("/api/v1/health"), { cache: "no-store", signal });
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  return (await res.json()) as SystemHealthResponse;
}

export async function fetchDemos(signal?: AbortSignal): Promise<DemoScenario[]> {
  const res = await fetch(apiUrl("/api/v1/demos"), { cache: "no-store", signal });
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  return (await res.json()) as DemoScenario[];
}

const PDF_SESSION_EXPIRED_ERROR =
  "Phiên tải báo cáo đã hết hạn hoặc không hợp lệ. Vui lòng phân tích lại tình huống để tải báo cáo PDF mới.";

function parseCaseSessionInfo(data: unknown): CaseSessionInfo | null {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return null;
  }
  const rec = data as Record<string, unknown>;
  if (typeof rec.case_id !== "string" || !rec.case_id.trim()) {
    return null;
  }
  if (typeof rec.case_access_token !== "string" || !rec.case_access_token.trim()) {
    return null;
  }
  if (
    rec.expires_at !== undefined &&
    rec.expires_at !== null &&
    typeof rec.expires_at !== "string"
  ) {
    return null;
  }
  const session: CaseSessionInfo = {
    case_id: rec.case_id.trim(),
    case_access_token: rec.case_access_token.trim(),
  };
  if (typeof rec.expires_at === "string" && rec.expires_at.trim()) {
    session.expires_at = rec.expires_at.trim();
  }
  return session;
}

function extractPdfFilename(contentDisposition: string | null, caseId: string): string {
  if (contentDisposition) {
    const utf8Match = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(contentDisposition);
    const rawEncoded = utf8Match?.[1]?.trim();
    if (rawEncoded) {
      try {
        const decoded = decodeURIComponent(rawEncoded)
          .replace(/[/\\?%*:|"<>]/g, "_")
          .replace(/\.\.+/g, ".")
          .trim();
        if (decoded) {
          return decoded;
        }
      } catch {
        // Ignore malformed percent-encoding and fall through
      }
    }
    const quotedMatch = /filename\s*=\s*"([^"]+)"/i.exec(contentDisposition);
    const unquotedMatch = /filename\s*=\s*([^;\s]+)/i.exec(contentDisposition);
    const candidate = (quotedMatch?.[1] ?? unquotedMatch?.[1] ?? "")
      .replace(/[/\\?%*:|"<>]/g, "_")
      .replace(/\.\.+/g, ".")
      .trim();
    if (candidate) {
      return candidate;
    }
  }
  const safeCaseId = caseId.replace(/[^a-zA-Z0-9_-]/g, "") || "report";
  return `VeriShield_${safeCaseId}.pdf`;
}

export async function analyzeSyncWithSession(
  formData: FormData,
  signal?: AbortSignal,
): Promise<{ report: AnalysisReport; caseAccessToken: string | null }> {
  const res = await fetch(apiUrl("/api/v1/analyze"), {
    method: "POST",
    body: formData,
    signal,
  });
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  const parsed: unknown = await res.json();
  if (!isValidAnalysisReport(parsed)) {
    throw new Error("Hệ thống chưa nhận được dữ liệu phản hồi hợp lệ. Vui lòng thử lại.");
  }
  const rawToken = res.headers.get("X-Case-Access-Token");
  const caseAccessToken = rawToken && rawToken.trim() ? rawToken.trim() : null;
  return { report: parsed, caseAccessToken };
}

export async function analyzeSync(
  formData: FormData,
  signal?: AbortSignal,
): Promise<AnalysisReport> {
  const { report } = await analyzeSyncWithSession(formData, signal);
  return report;
}

export async function analyzeStream(
  formData: FormData,
  handlers: {
    onTrace?: (step: TraceStep) => void;
    onResult?: (report: AnalysisReport) => void;
    onSession?: (session: CaseSessionInfo) => void;
  },
  signal?: AbortSignal,
): Promise<AnalysisReport> {
  const res = await fetch(apiUrl("/api/v1/analyze/stream"), {
    method: "POST",
    body: formData,
    signal,
  });
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  if (!res.body) {
    const { report, caseAccessToken } = await analyzeSyncWithSession(formData, signal);
    handlers.onResult?.(report);
    if (caseAccessToken) {
      handlers.onSession?.({
        case_id: report.case_id,
        case_access_token: caseAccessToken,
      });
    }
    return report;
  }

  let finalReport: AnalysisReport | null = null;
  await consumeUtf8SseStream(res.body, (ev) => {
    if (ev.event === "trace") {
      if (isValidTraceStep(ev.data)) {
        handlers.onTrace?.(ev.data);
      }
    } else if (ev.event === "result") {
      if (!isValidAnalysisReport(ev.data)) {
        throw new Error("Dữ liệu kết quả nhận về chưa hợp lệ. Vui lòng thử lại.");
      }
      finalReport = ev.data;
      handlers.onResult?.(finalReport);
    } else if (ev.event === "session") {
      const session = parseCaseSessionInfo(ev.data);
      if (session) {
        handlers.onSession?.(session);
      }
    }
  });

  if (!finalReport) {
    throw new Error("Quá trình kiểm tra đã dừng nhưng chưa nhận được kết quả cuối cùng. Vui lòng thử lại.");
  }
  return finalReport;
}

export async function fetchReportPdfBlob(
  caseId: string,
  caseAccessToken: string | null,
): Promise<{ blob: Blob; filename: string }> {
  const trimmedToken = caseAccessToken?.trim() ?? "";
  if (!trimmedToken) {
    throw new Error(PDF_SESSION_EXPIRED_ERROR);
  }
  const trimmedCaseId = caseId.trim();
  if (!trimmedCaseId) {
    throw new Error("Mã hồ sơ không hợp lệ. Vui lòng phân tích lại tình huống.");
  }
  const res = await fetch(
    apiUrl(`/api/v1/cases/${encodeURIComponent(trimmedCaseId)}/report.pdf`),
    {
      method: "GET",
      cache: "no-store",
      headers: {
        "X-Case-Access-Token": trimmedToken,
      },
    },
  );
  if (res.status === 403) {
    throw new Error(PDF_SESSION_EXPIRED_ERROR);
  }
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  const filename = extractPdfFilename(res.headers.get("Content-Disposition"), trimmedCaseId);
  const blob = await res.blob();
  return { blob, filename };
}

export async function downloadReportPdf(
  caseId: string,
  caseAccessToken: string | null,
): Promise<void> {
  const { blob, filename } = await fetchReportPdfBlob(caseId, caseAccessToken);
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.rel = "noopener noreferrer";
  anchor.style.display = "none";
  try {
    document.body.appendChild(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
  }
}

export async function fetchRadarGraph(signal?: AbortSignal): Promise<RadarGraphResponse> {
  const res = await fetch(apiUrl("/api/v1/radar/graph"), { cache: "no-store", signal });
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  return (await res.json()) as RadarGraphResponse;
}

export async function createBlockRule(payload: CreateBlockRuleRequest): Promise<BlockRule> {
  const res = await fetch(apiUrl("/api/v1/radar/block-rules"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  return (await res.json()) as BlockRule;
}

export async function revokeBlockRule(
  ruleId: string,
  analystPin: string,
): Promise<{ ok: boolean; revoked: boolean }> {
  const res = await fetch(
    apiUrl(`/api/v1/radar/block-rules/${encodeURIComponent(ruleId)}/revoke`),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_pin: analystPin }),
    },
  );
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  return (await res.json()) as { ok: boolean; revoked: boolean };
}

export async function resetBlockRules(
  analystPin: string,
): Promise<{ ok: boolean; cleared_rules: number }> {
  const res = await fetch(apiUrl("/api/v1/radar/block-rules/reset"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analyst_pin: analystPin }),
  });
  if (!res.ok) {
    throw new Error(await extractErrorMessage(res));
  }
  return (await res.json()) as { ok: boolean; cleared_rules: number };
}

export type AssistantApiErrorCode =
  | "CASE_AUTH_FAILED"
  | "RATE_LIMITED"
  | "TURN_CAP_REACHED"
  | "VALIDATION_ERROR"
  | "NOT_FOUND"
  | "REQUEST_FAILED";

export class AssistantApiError extends Error {
  readonly status: number;
  readonly code: AssistantApiErrorCode;
  readonly retryAfterSeconds?: number;

  constructor(
    message: string,
    options: {
      status: number;
      code: AssistantApiErrorCode;
      retryAfterSeconds?: number;
    },
  ) {
    super(message);
    this.name = "AssistantApiError";
    this.status = options.status;
    this.code = options.code;
    if (options.retryAfterSeconds !== undefined) {
      this.retryAfterSeconds = options.retryAfterSeconds;
    }
  }
}

const ASSISTANT_SESSION_EXPIRED_ERROR =
  "Phiên truy cập hồ sơ đã hết hạn hoặc không hợp lệ. Vui lòng phân tích lại tình huống hoặc chuyển sang hỏi đáp chung về phòng chống lừa đảo.";

function isRecord(val: unknown): val is Record<string, unknown> {
  return Boolean(val && typeof val === "object" && !Array.isArray(val));
}

function parseRetryAfterHeader(raw: string | null): number | undefined {
  if (!raw) return undefined;
  const parsed = Number.parseInt(raw.trim(), 10);
  if (Number.isFinite(parsed) && parsed > 0 && parsed <= 3600) {
    return parsed;
  }
  return undefined;
}

async function buildAssistantHttpError(res: Response): Promise<AssistantApiError> {
  if (res.status === 401 || res.status === 403) {
    return new AssistantApiError(ASSISTANT_SESSION_EXPIRED_ERROR, {
      status: res.status,
      code: "CASE_AUTH_FAILED",
    });
  }

  if (res.status === 429) {
    const retryAfterSeconds = parseRetryAfterHeader(res.headers.get("Retry-After"));
    let isTurnCap = false;
    try {
      const body = (await res.json()) as { detail?: unknown; code?: unknown };
      const detailText = typeof body.detail === "string" ? body.detail : "";
      const codeText = typeof body.code === "string" ? body.code : "";
      if (/turn|lượt|20\s*lượt|turn_cap/i.test(`${detailText} ${codeText}`)) {
        isTurnCap = true;
      }
    } catch {
      // Ignore non-JSON error payloads
    }
    if (isTurnCap) {
      return new AssistantApiError(
        "Bạn đã đạt giới hạn số lượt hỏi đáp cho hồ sơ này. Vui lòng kiểm tra tình huống mới hoặc chuyển sang hỏi đáp chung.",
        { status: 429, code: "TURN_CAP_REACHED", retryAfterSeconds },
      );
    }
    const msg = retryAfterSeconds
      ? `Bạn đang gửi câu hỏi quá nhanh. Vui lòng thử lại sau ${retryAfterSeconds} giây.`
      : "Bạn đang gửi câu hỏi quá nhanh hoặc Trợ lý đang quá tải. Vui lòng chờ ít giây rồi thử lại.";
    return new AssistantApiError(msg, {
      status: 429,
      code: "RATE_LIMITED",
      retryAfterSeconds,
    });
  }

  if (res.status === 413) {
    return new AssistantApiError("Tệp tải lên vượt quá dung lượng tối đa 10 MB.", {
      status: 413,
      code: "VALIDATION_ERROR",
    });
  }

  if (res.status === 404) {
    return new AssistantApiError(
      "Bản phân tích tạm thời không tồn tại, đã hết hạn (15 phút) hoặc đã được lưu trước đó.",
      { status: 404, code: "NOT_FOUND" },
    );
  }

  if (res.status === 400 || res.status === 422) {
    return new AssistantApiError(
      "Câu hỏi hoặc tệp đính kèm chưa đúng định dạng hay vượt quá giới hạn cho phép. Vui lòng kiểm tra lại.",
      { status: res.status, code: "VALIDATION_ERROR" },
    );
  }

  return new AssistantApiError(
    "Trợ lý VeriShield tạm thời gián đoạn kết nối. Vui lòng thử gửi lại sau ít giây.",
    { status: res.status, code: "REQUEST_FAILED" },
  );
}

function parseAssistantCitations(data: unknown): AssistantCitationItem[] | null {
  const rawItems = Array.isArray(data)
    ? data
    : isRecord(data) && Array.isArray(data.items)
      ? data.items
      : null;
  if (!rawItems) return null;
  const valid: AssistantCitationItem[] = [];
  for (const item of rawItems) {
    if (
      isRecord(item) &&
      typeof item.id === "string" &&
      item.id.trim() &&
      typeof item.source_type === "string" &&
      typeof item.title === "string" &&
      item.title.trim()
    ) {
      valid.push({
        id: item.id,
        source_type: item.source_type,
        title: item.title,
      });
    }
  }
  return valid;
}

function parseAssistantDone(data: unknown): AssistantDoneEvent | null {
  if (!isRecord(data)) return null;
  const degraded = typeof data.degraded_mode === "boolean" ? data.degraded_mode : false;
  const rawTier = data.output_tier;
  const outputTier: 0 | 1 | 2 = rawTier === 0 || rawTier === 1 || rawTier === 2 ? rawTier : 1;
  const suggestedFollowups = Array.isArray(data.suggested_followups)
    ? data.suggested_followups.filter(
        (item): item is string => typeof item === "string" && item.trim().length > 0,
      )
    : [];
  return {
    degraded_mode: degraded,
    output_tier: outputTier,
    suggested_followups: suggestedFollowups,
  };
}

function parseAssistantEvidenceReport(data: unknown): AssistantEvidenceReportEvent | null {
  if (!isRecord(data)) return null;
  if (
    typeof data.draft_id !== "string" ||
    !data.draft_id.trim() ||
    typeof data.can_contribute_radar !== "boolean" ||
    typeof data.risk_score !== "number" ||
    !Number.isFinite(data.risk_score) ||
    typeof data.verdict !== "string" ||
    typeof data.receipt_verification_status !== "string" ||
    typeof data.summary_vi !== "string"
  ) {
    return null;
  }
  return {
    draft_id: data.draft_id,
    can_contribute_radar: data.can_contribute_radar,
    risk_score: data.risk_score,
    verdict: data.verdict,
    receipt_verification_status: data.receipt_verification_status,
    summary_vi: data.summary_vi,
  };
}

async function consumeAssistantSseStream(
  body: ReadableStream<Uint8Array>,
  handlers: AssistantStreamHandlers,
): Promise<void> {
  await consumeUtf8SseStream(body, (ev) => {
    switch (ev.event) {
      case "status": {
        if (
          isRecord(ev.data) &&
          typeof ev.data.phase === "string" &&
          typeof ev.data.label === "string"
        ) {
          const event: AssistantStatusEvent = {
            phase: ev.data.phase,
            label: ev.data.label,
          };
          handlers.onStatus?.(event);
        }
        break;
      }
      case "tool_status": {
        if (
          isRecord(ev.data) &&
          typeof ev.data.tool === "string" &&
          typeof ev.data.state === "string" &&
          typeof ev.data.label === "string"
        ) {
          const event: AssistantToolStatusEvent = {
            tool: ev.data.tool,
            state: ev.data.state,
            label: ev.data.label,
          };
          handlers.onToolStatus?.(event);
        }
        break;
      }
      case "safety_notice": {
        if (
          isRecord(ev.data) &&
          typeof ev.data.code === "string" &&
          typeof ev.data.message === "string" &&
          ev.data.message.trim()
        ) {
          const event: AssistantSafetyNoticeEvent = {
            code: ev.data.code,
            message: ev.data.message,
          };
          handlers.onSafetyNotice?.(event);
        }
        break;
      }
      case "delta": {
        if (isRecord(ev.data) && typeof ev.data.text === "string" && ev.data.text.length > 0) {
          handlers.onDelta?.(ev.data.text);
        }
        break;
      }
      case "citation": {
        const items = parseAssistantCitations(ev.data);
        if (items && items.length > 0) {
          handlers.onCitation?.(items);
        }
        break;
      }
      case "evidence_report": {
        const parsed = parseAssistantEvidenceReport(ev.data);
        if (parsed) {
          handlers.onEvidenceReport?.(parsed);
        }
        break;
      }
      case "done": {
        const parsed = parseAssistantDone(ev.data);
        if (parsed) {
          handlers.onDone?.(parsed);
        }
        break;
      }
      case "error": {
        if (
          isRecord(ev.data) &&
          typeof ev.data.code === "string" &&
          typeof ev.data.message === "string"
        ) {
          const event: AssistantErrorEvent = {
            code: ev.data.code,
            message: ev.data.message,
          };
          handlers.onError?.(event);
        }
        break;
      }
      default:
        break;
    }
  });
}

export async function streamAssistantChat(
  payload: AssistantChatPayload,
  caseAccessToken: string | null,
  handlers: AssistantStreamHandlers,
  signal?: AbortSignal,
): Promise<void> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "text/event-stream",
  };
  const trimmedToken = caseAccessToken?.trim() ?? "";
  if (trimmedToken) {
    headers["X-Case-Access-Token"] = trimmedToken;
  }

  const res = await fetch(apiUrl("/api/v1/assistant/chat/stream"), {
    method: "POST",
    cache: "no-store",
    headers,
    body: JSON.stringify(payload),
    signal,
  });

  if (!res.ok) {
    throw await buildAssistantHttpError(res);
  }

  if (!res.body) {
    throw new AssistantApiError(
      "Kết nối luồng phản hồi từ Trợ lý VeriShield bị gián đoạn. Vui lòng thử lại.",
      { status: 502, code: "REQUEST_FAILED" },
    );
  }

  await consumeAssistantSseStream(res.body, handlers);
}

export async function streamAssistantEvidenceChat(
  formData: FormData,
  caseAccessToken: string | null,
  handlers: AssistantStreamHandlers,
  signal?: AbortSignal,
): Promise<void> {
  const headers: Record<string, string> = {
    Accept: "text/event-stream",
  };
  const trimmedToken = caseAccessToken?.trim() ?? "";
  if (trimmedToken) {
    headers["X-Case-Access-Token"] = trimmedToken;
  }

  const res = await fetch(apiUrl("/api/v1/assistant/chat/evidence/stream"), {
    method: "POST",
    cache: "no-store",
    headers,
    body: formData,
    signal,
  });

  if (!res.ok) {
    throw await buildAssistantHttpError(res);
  }

  if (!res.body) {
    throw new AssistantApiError(
      "Kết nối luồng phân tích bằng chứng bổ sung bị gián đoạn. Vui lòng thử lại.",
      { status: 502, code: "REQUEST_FAILED" },
    );
  }

  await consumeAssistantSseStream(res.body, handlers);
}

export async function persistAssistantEvidence(
  draftId: string,
  caseId: string,
  contributeToRadar: boolean,
  caseAccessToken: string | null,
): Promise<PersistEvidenceResponse> {
  const trimmedToken = caseAccessToken?.trim() ?? "";
  if (!trimmedToken) {
    throw new AssistantApiError(ASSISTANT_SESSION_EXPIRED_ERROR, {
      status: 403,
      code: "CASE_AUTH_FAILED",
    });
  }
  const trimmedDraft = draftId.trim();
  const trimmedCase = caseId.trim();
  if (!trimmedDraft || !trimmedCase) {
    throw new AssistantApiError("Thông tin bản phân tích bổ sung không hợp lệ.", {
      status: 400,
      code: "VALIDATION_ERROR",
    });
  }

  const res = await fetch(
    apiUrl(`/api/v1/assistant/evidence/${encodeURIComponent(trimmedDraft)}/persist`),
    {
      method: "POST",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-Case-Access-Token": trimmedToken,
      },
      body: JSON.stringify({
        case_id: trimmedCase,
        contribute_to_radar: Boolean(contributeToRadar),
      }),
    },
  );

  if (!res.ok) {
    throw await buildAssistantHttpError(res);
  }

  const parsed: unknown = await res.json();
  if (
    !isRecord(parsed) ||
    typeof parsed.child_case_id !== "string" ||
    typeof parsed.child_case_access_token !== "string" ||
    typeof parsed.expires_at !== "string" ||
    typeof parsed.contributed_to_radar !== "boolean" ||
    typeof parsed.parent_case_id !== "string"
  ) {
    throw new AssistantApiError(
      "Phản hồi lưu hồ sơ bổ sung chưa hợp lệ. Vui lòng thử lại.",
      { status: 502, code: "REQUEST_FAILED" },
    );
  }

  return {
    child_case_id: parsed.child_case_id,
    child_case_access_token: parsed.child_case_access_token,
    expires_at: parsed.expires_at,
    contributed_to_radar: parsed.contributed_to_radar,
    parent_case_id: parsed.parent_case_id,
  };
}
