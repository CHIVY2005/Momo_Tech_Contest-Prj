import type { AnalysisReport, VerdictLevel } from "./types";

const VALID_VERDICTS = new Set<VerdictLevel>([
  "SAFE",
  "SUSPICIOUS",
  "HIGH_RISK",
  "CRITICAL_SCAM",
]);

/**
 * Format FastAPI validation error array without echoing rejected raw user inputs (e.g. PIN or STK).
 */
export function sanitizeValidationErrorDetail(detail: unknown): string {
  if (!Array.isArray(detail) || detail.length === 0) {
    return "Dữ liệu đầu vào không hợp lệ.";
  }
  const first = detail[0] as Record<string, unknown> | null;
  if (!first || typeof first !== "object") {
    return "Dữ liệu đầu vào không hợp lệ.";
  }
  const locArr = Array.isArray(first.loc) ? first.loc : [];
  const field = String(locArr[locArr.length - 1] ?? "payload").replace(/[^a-zA-Z0-9_.-]/g, "");
  const msg = typeof first.msg === "string" ? first.msg : "Không đúng định dạng yêu cầu";
  return `Lỗi trường '${field}': ${msg}.`;
}

/**
 * Mask raw phone/account identifiers for UI display while leaving already-masked values intact.
 */
export function maskDisplayIoc(raw: string | null | undefined): string {
  if (!raw) return "N/A";
  const trimmed = raw.trim();
  if (!trimmed || trimmed.includes("****")) {
    return trimmed || "N/A";
  }
  const digits = trimmed.replace(/\D/g, "");
  if (/^0[35789]\d{8}$/.test(digits)) {
    return `${digits.slice(0, 3)}****${digits.slice(-3)}`;
  }
  if (digits.length >= 10) {
    return `${digits.slice(0, 4)}****${digits.slice(-4)}`;
  }
  if (digits.length >= 6) {
    return `${digits.slice(0, 2)}****${digits.slice(-2)}`;
  }
  if (/^\d+$/.test(trimmed)) {
    return "****";
  }
  return trimmed;
}

function isObjectRecord(val: unknown): val is Record<string, unknown> {
  return Boolean(val && typeof val === "object" && !Array.isArray(val));
}

function isStringArray(val: unknown): val is string[] {
  return Array.isArray(val) && val.every((item) => typeof item === "string");
}

function isNullableString(val: unknown): boolean {
  return val === undefined || val === null || typeof val === "string";
}

function isValidEvidenceArray(val: unknown): boolean {
  return (
    Array.isArray(val) &&
    val.every(
      (ev) =>
        isObjectRecord(ev) &&
        typeof ev.source === "string" &&
        typeof ev.severity === "string" &&
        typeof ev.title === "string" &&
        typeof ev.detail === "string" &&
        isNullableString(ev.snippet),
    )
  );
}

function isValidVietQrArray(val: unknown): boolean {
  return (
    Array.isArray(val) &&
    val.every(
      (qr) =>
        isObjectRecord(qr) &&
        typeof qr.raw === "string" &&
        typeof qr.kind === "string" &&
        typeof qr.crc_valid === "boolean" &&
        isNullableString(qr.bank_bin) &&
        isNullableString(qr.bank_name) &&
        isNullableString(qr.account_number) &&
        isNullableString(qr.service_code) &&
        isNullableString(qr.amount) &&
        isNullableString(qr.note) &&
        typeof qr.receive_scam_detected === "boolean" &&
        typeof qr.beneficiary_mismatch === "boolean",
    )
  );
}

function isValidUrlFindingsArray(val: unknown): boolean {
  return (
    Array.isArray(val) &&
    val.every(
      (uf) =>
        isObjectRecord(uf) &&
        typeof uf.url === "string" &&
        typeof uf.domain === "string" &&
        typeof uf.normalized_ascii_domain === "string" &&
        isNullableString(uf.final_url) &&
        isNullableString(uf.spoofed_brand) &&
        typeof uf.redirect_hops === "number" &&
        typeof uf.is_blocked_ssrf === "boolean" &&
        typeof uf.is_idn_homoglyph === "boolean" &&
        typeof uf.risk_points === "number" &&
        isStringArray(uf.reasons),
    )
  );
}

function isValidTraceArray(val: unknown): boolean {
  return (
    Array.isArray(val) &&
    val.every(
      (st) =>
        isObjectRecord(st) &&
        typeof st.step_id === "string" &&
        typeof st.title === "string" &&
        typeof st.status === "string" &&
        typeof st.detail === "string" &&
        typeof st.duration_ms === "number",
    )
  );
}

/**
 * Runtime contract guard verifying AnalysisReport shape & nested entries before rendering.
 */
export function isValidAnalysisReport(data: unknown): data is AnalysisReport {
  if (!isObjectRecord(data)) return false;
  if (typeof data.case_id !== "string" || !data.case_id) return false;
  if (typeof data.created_at !== "string" || typeof data.mode !== "string") return false;
  if (typeof data.summary_vi !== "string" || !isNullableString(data.transcript)) return false;
  if (typeof data.risk_score !== "number" || !Number.isFinite(data.risk_score)) return false;
  if (typeof data.verdict !== "string" || !VALID_VERDICTS.has(data.verdict as VerdictLevel)) {
    return false;
  }

  for (const key of ["matched_playbooks", "manipulation_tactics", "highlighted_phrases"] as const) {
    if (!isStringArray(data[key])) return false;
  }
  if (!isValidVietQrArray(data.vietqr_findings)) return false;
  if (!isValidUrlFindingsArray(data.url_findings)) return false;
  if (!isValidEvidenceArray(data.evidence)) return false;
  if (!isValidTraceArray(data.trace)) return false;

  if (data.sandbox != null) {
    if (
      !isObjectRecord(data.sandbox) ||
      typeof data.sandbox.available !== "boolean" ||
      typeof data.sandbox.visited_url !== "string" ||
      !isNullableString(data.sandbox.final_url) ||
      !isNullableString(data.sandbox.page_title) ||
      !isNullableString(data.sandbox.impersonated_brand) ||
      !isNullableString(data.sandbox.screenshot_base64) ||
      typeof data.sandbox.risk_points !== "number" ||
      !isStringArray(data.sandbox.reasons)
    ) {
      return false;
    }
  }
  if (data.image_forensics != null) {
    if (
      !isObjectRecord(data.image_forensics) ||
      typeof data.image_forensics.filename !== "string" ||
      typeof data.image_forensics.format !== "string" ||
      typeof data.image_forensics.dhash_hex !== "string" ||
      typeof data.image_forensics.ocr_text !== "string" ||
      !isNullableString(data.image_forensics.exif_software) ||
      !isNullableString(data.image_forensics.ela_heatmap_base64) ||
      typeof data.image_forensics.tamper_score !== "number" ||
      !isStringArray(data.image_forensics.qr_payloads) ||
      !isStringArray(data.image_forensics.reasons)
    ) {
      return false;
    }
  }
  if (data.receipt_logic != null) {
    if (
      !isObjectRecord(data.receipt_logic) ||
      typeof data.receipt_logic.is_receipt_candidate !== "boolean" ||
      !isNullableString(data.receipt_logic.bank_detected) ||
      !isNullableString(data.receipt_logic.reference_code) ||
      typeof data.receipt_logic.reference_valid !== "boolean" ||
      typeof data.receipt_logic.verification_status !== "string" ||
      typeof data.receipt_logic.logic_risk_points !== "number" ||
      !isStringArray(data.receipt_logic.reasons)
    ) {
      return false;
    }
  }

  if (!isObjectRecord(data.iocs)) return false;
  for (const iocKey of ["phones", "bank_accounts", "urls", "domains", "brands"] as const) {
    if (!isStringArray(data.iocs[iocKey])) return false;
  }

  if (!isObjectRecord(data.actions)) return false;
  if (
    !isStringArray(data.actions.counter_replies) ||
    !isStringArray(data.actions.urgent_steps) ||
    typeof data.actions.family_shield_message !== "string" ||
    !isNullableString(data.actions.merchant_balance_warning)
  ) {
    return false;
  }
  if (!isObjectRecord(data.actions.pre_transfer)) return false;
  const pre = data.actions.pre_transfer;
  return (
    typeof pre.should_hold_transfer === "boolean" &&
    typeof pre.cooling_off_seconds === "number" &&
    (pre.warning_headline === undefined || typeof pre.warning_headline === "string") &&
    isStringArray(pre.verification_questions)
  );
}
