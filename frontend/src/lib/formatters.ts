import type { AnalysisReport, TraceStep, VerdictLevel } from "./types";

const VALID_VERDICTS = new Set<VerdictLevel>([
  "SAFE",
  "SUSPICIOUS",
  "HIGH_RISK",
  "CRITICAL_SCAM",
]);

const VALIDATION_FIELD_LABELS: Record<string, string> = {
  analyst_pin: "mã PIN xác thực",
  value: "giá trị cần chặn",
  ioc_type: "loại dấu hiệu",
  ioc_hash: "mã nhận diện dấu hiệu",
  reason: "lý do chặn",
  text: "nội dung cần kiểm tra",
  url: "đường dẫn",
  mode: "chế độ kiểm tra",
  transfer_amount: "số tiền dự kiến chuyển",
  expected_merchant_account: "số tài khoản cửa hàng",
};

/**
 * Format FastAPI validation error array without echoing rejected raw user inputs (e.g. PIN or STK)
 * or leaking internal field identifiers to end users.
 */
export function sanitizeValidationErrorDetail(detail: unknown): string {
  if (!Array.isArray(detail) || detail.length === 0) {
    return "Dữ liệu đầu vào chưa đúng định dạng. Vui lòng kiểm tra lại.";
  }
  const first = detail[0] as Record<string, unknown> | null;
  if (!first || typeof first !== "object") {
    return "Dữ liệu đầu vào chưa đúng định dạng. Vui lòng kiểm tra lại.";
  }
  const locArr = Array.isArray(first.loc) ? first.loc : [];
  const rawField = String(locArr[locArr.length - 1] ?? "").replace(/[^a-zA-Z0-9_.-]/g, "");
  const fieldLabel = VALIDATION_FIELD_LABELS[rawField];
  if (fieldLabel) {
    return `Thông tin ${fieldLabel} chưa đúng định dạng yêu cầu. Vui lòng kiểm tra lại.`;
  }
  return "Dữ liệu đầu vào chưa đúng định dạng yêu cầu. Vui lòng kiểm tra lại.";
}

/**
 * Mask raw phone/account identifiers for UI display while leaving already-masked values intact.
 */
export function maskDisplayIoc(raw: string | null | undefined): string {
  if (!raw) return "Chưa có";
  const trimmed = raw.trim();
  if (!trimmed || trimmed.includes("****")) {
    return trimmed || "Chưa có";
  }
  const digits = trimmed.replace(/\D/g, "");
  if (/^0[35789]\d{8}$/.test(digits)) {
    return `${digits.slice(0, 3)}****${digits.slice(-3)}`;
  }
  if (digits.length >= 6) {
    return `${digits.slice(0, 2)}****${digits.slice(-2)}`;
  }
  if (/^\d+$/.test(trimmed)) {
    return "****";
  }
  return trimmed;
}

/**
 * Neutralize URLs/domains for safe forensic display and copy (never clickable phishing links).
 */
export function defangUrlForDisplay(raw: string): string {
  return raw
    .trim()
    .replace(/^https?:\/\//i, (match) => match.replace("http", "hxxp"))
    .replace(/\./g, "[.]");
}

export function formatVietQrAmount(amount?: string | null): string {
  if (!amount || !amount.trim()) {
    return "QR tĩnh (tự nhập số tiền)";
  }
  const trimmed = amount.trim();
  const parsed = Number(trimmed);
  if (Number.isFinite(parsed)) {
    return `${parsed.toLocaleString("vi-VN")} VND`;
  }
  return trimmed;
}

/**
 * Extract raw integer digits for backend transfer_amount submission while stripping formatting dots/spaces.
 */
export function parseRawAmountDigits(input: string): string {
  const digits = input.replace(/\D/g, "").slice(0, 15);
  if (!digits) return "";
  const stripped = digits.replace(/^0+/, "");
  return stripped || "0";
}

/**
 * Format raw integer digits with Vietnamese dot thousands separators for display in numeric inputs.
 */
export function formatVndInputDisplay(rawDigits: string): string {
  const clean = parseRawAmountDigits(rawDigits);
  if (!clean) return "";
  return clean.replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

export function shouldShowReceiptCard(report: {
  receipt_verification_status: string;
  receipt_logic?: { is_receipt_candidate: boolean } | null;
}): boolean {
  return Boolean(
    report.receipt_logic?.is_receipt_candidate ||
      report.receipt_verification_status !== "NOT_APPLICABLE",
  );
}

export function validateAnalystPinInput(pin: string): string | null {
  if (pin.trim().length < 4) {
    return "Vui lòng nhập mã PIN xác thực (tối thiểu 4 ký tự) trước khi thao tác.";
  }
  return null;
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

function isOptionalBoolean(val: unknown): boolean {
  return val === undefined || typeof val === "boolean";
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
        isOptionalBoolean(qr.tlv_valid) &&
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

function isValidImageForensicsRecord(val: unknown): boolean {
  return (
    isObjectRecord(val) &&
    typeof val.filename === "string" &&
    typeof val.format === "string" &&
    typeof val.dhash_hex === "string" &&
    typeof val.ocr_text === "string" &&
    isNullableString(val.exif_software) &&
    isNullableString(val.ela_heatmap_base64) &&
    typeof val.width === "number" &&
    Number.isFinite(val.width) &&
    typeof val.height === "number" &&
    Number.isFinite(val.height) &&
    typeof val.tamper_score === "number" &&
    Number.isFinite(val.tamper_score) &&
    typeof val.ocr_height_cv === "number" &&
    Number.isFinite(val.ocr_height_cv) &&
    isNullableString(val.ocr_provider) &&
    (val.ocr_confidence === undefined ||
      (typeof val.ocr_confidence === "number" && Number.isFinite(val.ocr_confidence))) &&
    (val.ocr_status === undefined || typeof val.ocr_status === "string") &&
    isStringArray(val.qr_payloads) &&
    isStringArray(val.reasons)
  );
}

export function isValidTraceStep(st: unknown): st is TraceStep {
  return (
    isObjectRecord(st) &&
    typeof st.step_id === "string" &&
    Boolean(st.step_id) &&
    typeof st.title === "string" &&
    typeof st.status === "string" &&
    ["running", "done", "warning", "skipped"].includes(st.status) &&
    typeof st.detail === "string" &&
    typeof st.duration_ms === "number" &&
    Number.isFinite(st.duration_ms)
  );
}

function isValidTraceArray(val: unknown): boolean {
  return Array.isArray(val) && val.every((st) => isValidTraceStep(st));
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
      typeof data.sandbox.blocked_ssrf !== "boolean" ||
      typeof data.sandbox.has_password_field !== "boolean" ||
      typeof data.sandbox.has_otp_field !== "boolean" ||
      typeof data.sandbox.has_apk_download !== "boolean" ||
      typeof data.sandbox.risk_points !== "number" ||
      !isStringArray(data.sandbox.reasons)
    ) {
      return false;
    }
  }
  if (data.image_forensics != null && !isValidImageForensicsRecord(data.image_forensics)) {
    return false;
  }
  if (
    data.image_forensics_list !== undefined &&
    (!Array.isArray(data.image_forensics_list) ||
      !data.image_forensics_list.every((item) => isValidImageForensicsRecord(item)))
  ) {
    return false;
  }
  if (data.receipt_logic != null) {
    if (
      !isObjectRecord(data.receipt_logic) ||
      typeof data.receipt_logic.is_receipt_candidate !== "boolean" ||
      !isNullableString(data.receipt_logic.bank_detected) ||
      !isNullableString(data.receipt_logic.reference_code) ||
      !isNullableString(data.receipt_logic.extracted_recipient_account) ||
      typeof data.receipt_logic.reference_valid !== "boolean" ||
      !isOptionalBoolean(data.receipt_logic.timestamp_checked) ||
      typeof data.receipt_logic.timestamp_anomaly !== "boolean" ||
      !isOptionalBoolean(data.receipt_logic.amount_checked) ||
      typeof data.receipt_logic.amount_format_anomaly !== "boolean" ||
      !isOptionalBoolean(data.receipt_logic.geometry_checked) ||
      typeof data.receipt_logic.geometry_anomaly !== "boolean" ||
      !isOptionalBoolean(data.receipt_logic.beneficiary_checked) ||
      typeof data.receipt_logic.beneficiary_mismatch !== "boolean" ||
      !isOptionalBoolean(data.receipt_logic.replay_checked) ||
      typeof data.receipt_logic.is_replayed !== "boolean" ||
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
  if (
    typeof pre.should_hold_transfer !== "boolean" ||
    typeof pre.cooling_off_seconds !== "number" ||
    (pre.blocked_by_ops_rule !== undefined && typeof pre.blocked_by_ops_rule !== "boolean") ||
    (pre.warning_headline !== undefined && typeof pre.warning_headline !== "string") ||
    !isStringArray(pre.verification_questions)
  ) {
    return false;
  }
  if (data.active_block_rule_hit === true) {
    if (pre.blocked_by_ops_rule !== true || pre.should_hold_transfer !== true) {
      return false;
    }
  }
  if (data.active_block_rule_hit !== undefined && typeof data.active_block_rule_hit !== "boolean") {
    return false;
  }
  return typeof pre.blocked_by_ops_rule === "boolean";
}
