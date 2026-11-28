import assert from "node:assert/strict";
import test from "node:test";

import {
  buildClassifierDistribution,
  buildDetectedSignals,
  buildEvidenceDistribution,
  buildMeasuredSignalFactors,
  buildTraceTimeline,
  highlightSuspiciousText,
  mapEvidenceSourceToTab,
} from "../explainableAi.ts";
import type { AnalysisReport } from "../types";

function makeBaseReport(overrides: Partial<AnalysisReport> = {}): AnalysisReport {
  return {
    case_id: "vs_test_xai_001",
    created_at: "2026-11-28T09:00:00Z",
    mode: "personal",
    in_active_call: false,
    risk_score: 88,
    verdict: "CRITICAL_SCAM",
    confidence: 0.93,
    degraded_mode: false,
    safety_advisory_detected: false,
    prompt_injection_detected: false,
    active_block_rule_hit: false,
    receipt_verification_status: "NOT_APPLICABLE",
    summary_vi: "Phát hiện trang web giả mạo yêu cầu nhập mã OTP.",
    transcript: null,
    classifier: {
      available: true,
      predicted_label: "SCAM_PHISHING_APK_OTP",
      scam_probability: 0.91,
      advisory_probability: 0.02,
      injection_probability: 0.01,
      class_probabilities: {
        SCAM_PHISHING_APK_OTP: 0.91,
        SCAM_IMPERSONATION: 0.04,
        SAFE_NORMAL: 0.02,
        SAFE_ADVISORY: 0.02,
        PROMPT_INJECTION: 0.01,
      },
      latency_ms: 14,
    },
    matched_playbooks: ["Giả mạo đổi điểm ngân hàng"],
    manipulation_tactics: ["Tạo áp lực thời gian khẩn cấp"],
    highlighted_phrases: ["nhập mã OTP", "hết hạn sau 30 phút"],
    iocs: {
      phones: ["0912345678"],
      bank_accounts: ["190384756201"],
      urls: ["https://vcb-diemthuong-247.top/otp"],
      domains: ["vcb-diemthuong-247.top"],
      brands: ["Vietcombank"],
    },
    vietqr_findings: [],
    url_findings: [
      {
        url: "https://vcb-diemthuong-247.top/otp",
        domain: "vcb-diemthuong-247.top",
        normalized_ascii_domain: "vcb-diemthuong-247.top",
        final_url: "https://vcb-diemthuong-247.top/login",
        redirect_hops: 1,
        is_blocked_ssrf: false,
        is_idn_homoglyph: false,
        spoofed_brand: "Vietcombank",
        domain_age_days: null,
        urlhaus_listed: false,
        risk_points: 85,
        reasons: ["Tên miền gần giống thương hiệu Vietcombank"],
      },
    ],
    sandbox: {
      available: true,
      visited_url: "https://vcb-diemthuong-247.top/otp",
      final_url: "https://vcb-diemthuong-247.top/login",
      page_title: "Xác thực nhận điểm",
      blocked_ssrf: false,
      has_password_field: true,
      has_otp_field: true,
      has_apk_download: false,
      impersonated_brand: "Vietcombank",
      screenshot_base64: null,
      risk_points: 80,
      reasons: ["Trang yêu cầu nhập mật khẩu và mã OTP"],
    },
    image_forensics: null,
    image_forensics_list: [],
    receipt_logic: null,
    evidence: [
      {
        source: "url_inspector",
        severity: "CRITICAL",
        title: "Phát hiện rủi ro từ đường dẫn trang web",
        detail: "Tên miền gần giống thương hiệu Vietcombank",
      },
      {
        source: "phishing_sandbox",
        severity: "CRITICAL",
        title: "Phát hiện trang web giả mạo trong môi trường cách ly",
        detail: "Trang yêu cầu nhập mã OTP",
      },
    ],
    actions: {
      counter_replies: [],
      family_shield_message: "",
      urgent_steps: [],
      merchant_balance_warning: null,
      pre_transfer: {
        should_hold_transfer: false,
        cooling_off_seconds: 0,
        triggered_by_active_call: false,
        blocked_by_ops_rule: false,
        warning_headline: "",
        verification_questions: [],
      },
    },
    trace: [
      {
        step_id: "media_forensics",
        title: "Phân tích hình ảnh, mã QR và ghi âm",
        status: "skipped",
        detail: "Không có tệp media.",
        duration_ms: 0,
      },
      {
        step_id: "cyber_guardrails",
        title: "Kiểm tra đường dẫn và danh sách chặn",
        status: "warning",
        detail: "Ghi nhận 1 đường dẫn.",
        duration_ms: 420,
      },
      {
        step_id: "onnx_and_kb",
        title: "Phân loại E5 ONNX & kho tri thức",
        status: "done",
        detail: "Khớp 1 kịch bản.",
        duration_ms: 18,
      },
    ],
    community_hits: 0,
    ...overrides,
  };
}

test("buildDetectedSignals links real backend threats to accurate evidence tabs sorted by severity", () => {
  const report = makeBaseReport();
  const signals = buildDetectedSignals(report);
  assert.ok(signals.length >= 4);
  assert.equal(signals[0]?.severity, "CRITICAL");
  assert.ok(signals.some((s) => s.id === "sandbox-otp" && s.evidenceTab === "url" && s.verified));
  assert.ok(signals.some((s) => s.id === "url-spoof-Vietcombank" && s.evidenceTab === "url"));
  assert.ok(signals.some((s) => s.category === "behavior" && s.verified === false));
});

test("buildMeasuredSignalFactors emits ONLY components actually measured by backend (no fake scores)", () => {
  const report = makeBaseReport({
    url_findings: [],
    sandbox: null,
    classifier: null,
    image_forensics: null,
    image_forensics_list: [],
    receipt_logic: null,
    active_block_rule_hit: false,
  });
  assert.deepEqual(buildMeasuredSignalFactors(report), []);

  const richFactors = buildMeasuredSignalFactors(makeBaseReport());
  assert.deepEqual(
    richFactors.map((f) => f.id),
    ["factor-onnx", "factor-url", "factor-sandbox"],
  );
  assert.equal(richFactors[0]?.score, 91);
  assert.equal(richFactors[1]?.score, 85);
});

test("buildClassifierDistribution maps Vietnamese labels and returns empty when classifier unavailable", () => {
  assert.deepEqual(buildClassifierDistribution(null), []);
  assert.deepEqual(
    buildClassifierDistribution({
      available: false,
      predicted_label: "SAFE_NORMAL",
      scam_probability: 0,
      advisory_probability: 0,
      injection_probability: 0,
      class_probabilities: { SAFE_NORMAL: 1 },
      latency_ms: 0,
    }),
    [],
  );

  const dist = buildClassifierDistribution(makeBaseReport().classifier);
  assert.equal(dist.length, 5);
  assert.equal(dist[0]?.key, "SCAM_PHISHING_APK_OTP");
  assert.equal(dist[0]?.isPredicted, true);
  assert.equal(dist[0]?.percent, 91);
  assert.ok(dist[0]?.labelVi.includes("OTP"));
});

test("buildEvidenceDistribution and buildTraceTimeline aggregate counts and durations accurately", () => {
  const report = makeBaseReport();
  const dist = buildEvidenceDistribution(report.evidence);
  assert.equal(dist.total, 2);
  assert.equal(dist.bySeverity[0]?.severity, "CRITICAL");
  assert.equal(dist.bySeverity[0]?.count, 2);
  assert.equal(mapEvidenceSourceToTab("vietqr_parser"), "vietqr");
  assert.equal(mapEvidenceSourceToTab("image_forensics"), "ela");

  const timeline = buildTraceTimeline(report.trace);
  assert.equal(timeline.totalMs, 438);
  assert.equal(timeline.entries[0]?.sharePct, 0);
  assert.ok((timeline.entries[1]?.sharePct ?? 0) > 90);
});

test("highlightSuspiciousText splits phrases case-insensitively with zero HTML execution", () => {
  const input = "Cảnh báo: NHẬP MÃ OTP trước khi hết hạn sau 30 phút <script>alert(1)</script>";
  const segments = highlightSuspiciousText(input, ["nhập mã OTP", "hết hạn sau 30 phút"]);
  const highlighted = segments.filter((s) => s.highlighted).map((s) => s.text);
  assert.deepEqual(highlighted, ["NHẬP MÃ OTP", "hết hạn sau 30 phút"]);
  assert.equal(
    segments.map((s) => s.text).join(""),
    input,
  );
});
