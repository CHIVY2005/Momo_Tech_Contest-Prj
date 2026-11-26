import {
  isValidAnalysisReport,
  isValidTraceStep,
  sanitizeValidationErrorDetail,
} from "./formatters.ts";
import { consumeUtf8SseStream } from "./sse.ts";
import type {
  AnalysisReport,
  BlockRule,
  CreateBlockRuleRequest,
  DemoScenario,
  RadarGraphResponse,
  SystemHealthResponse,
  TraceStep,
} from "./types";

export {
  isValidAnalysisReport,
  isValidTraceStep,
  maskDisplayIoc,
  sanitizeValidationErrorDetail,
} from "./formatters.ts";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "").replace(/\/+$/, "");

function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
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
    return "Tệp tải lên vượt quá giới hạn an toàn 10 MB.";
  }
  if (res.status === 429) {
    return "Quá giới hạn số lượt yêu cầu mỗi phút. Vui lòng thử lại sau ít giây.";
  }
  return `Yêu cầu thất bại (HTTP ${res.status}).`;
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

export async function analyzeSync(
  formData: FormData,
  signal?: AbortSignal,
): Promise<AnalysisReport> {
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
    throw new Error("Phản hồi phân tích từ máy chủ không đúng định dạng chuẩn.");
  }
  return parsed;
}

export async function analyzeStream(
  formData: FormData,
  handlers: {
    onTrace?: (step: TraceStep) => void;
    onResult?: (report: AnalysisReport) => void;
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
    return analyzeSync(formData, signal);
  }

  let finalReport: AnalysisReport | null = null;
  await consumeUtf8SseStream(res.body, (ev) => {
    if (ev.event === "trace") {
      if (isValidTraceStep(ev.data)) {
        handlers.onTrace?.(ev.data);
      }
    } else if (ev.event === "result") {
      if (!isValidAnalysisReport(ev.data)) {
        throw new Error("Khung kết quả SSE không hợp lệ.");
      }
      finalReport = ev.data;
      handlers.onResult?.(finalReport);
    }
  });

  if (!finalReport) {
    throw new Error("Luồng phân tích kết thúc nhưng chưa nhận được kết quả cuối cùng.");
  }
  return finalReport;
}

export function getReportPdfUrl(caseId: string): string {
  return apiUrl(`/api/v1/cases/${encodeURIComponent(caseId)}/report.pdf`);
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
