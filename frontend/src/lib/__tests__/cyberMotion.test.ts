import assert from "node:assert/strict";
import test from "node:test";

import {
  buildVerdictTransitionKey,
  classifyTraceStageVisual,
  resolveRadarMotionScope,
  resolveScenarioIconKind,
  resolveVerdictMotionProfile,
  selectVisibleBackendTraceSteps,
  shouldAnimateRadarEdge,
  shouldRunAmbientMotion,
} from "../motion/cyberMotion.ts";

test("shouldRunAmbientMotion pauses when off-screen, hidden tab, reduced motion, or interacting", () => {
  assert.equal(
    shouldRunAmbientMotion({
      inViewport: true,
      documentVisible: true,
      reducedMotion: false,
      pausedByInteraction: false,
    }),
    true,
  );
  assert.equal(
    shouldRunAmbientMotion({
      inViewport: false,
      documentVisible: true,
      reducedMotion: false,
    }),
    false,
  );
  assert.equal(
    shouldRunAmbientMotion({
      inViewport: true,
      documentVisible: false,
      reducedMotion: false,
    }),
    false,
  );
  assert.equal(
    shouldRunAmbientMotion({
      inViewport: true,
      documentVisible: true,
      reducedMotion: true,
    }),
    false,
  );
  assert.equal(
    shouldRunAmbientMotion({
      inViewport: true,
      documentVisible: true,
      reducedMotion: false,
      pausedByInteraction: true,
    }),
    false,
  );
});

test("resolveScenarioIconKind maps the 4 Vietnamese demo categories accurately", () => {
  assert.equal(
    resolveScenarioIconKind({
      demo_id: "demo_napas_sms",
      category_badge: "Tin nhắn",
      image_filename: null,
      audio_filename: null,
    }),
    "message",
  );
  assert.equal(
    resolveScenarioIconKind({
      demo_id: "demo_zalo_fake_bill",
      category_badge: "Biên lai",
      image_filename: "fake_bill_zalo.jpg",
      audio_filename: null,
    }),
    "receipt",
  );
  assert.equal(
    resolveScenarioIconKind({
      demo_id: "demo_vietqr_refund",
      category_badge: "Mã VietQR",
      image_filename: "vietqr_refund_trap.png",
      audio_filename: null,
    }),
    "vietqr",
  );
  assert.equal(
    resolveScenarioIconKind({
      demo_id: "demo_active_call_police",
      category_badge: "Cuộc gọi",
      image_filename: null,
      audio_filename: "scam_call_police.wav",
    }),
    "call",
  );
});

test("classifyTraceStageVisual maps both live 4-stage IDs and granular 6-stage IDs accurately", () => {
  assert.equal(
    classifyTraceStageVisual({
      step_id: "text_analysis",
      title: "Text Analysis",
      detail: "Tokenizing Vietnamese message",
    }),
    "text_analysis",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "url_scanning",
      title: "URL Scanning",
      detail: "Inspecting redirects",
    }),
    "url_scanning",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "ocr_processing",
      title: "OCR Processing",
      detail: "RapidOCR box geometry",
    }),
    "ocr_processing",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "qr_analysis",
      title: "QR Analysis",
      detail: "VietQR CRC-16",
    }),
    "qr_analysis",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "ai_inference",
      title: "AI Inference",
      detail: "E5 ONNX",
    }),
    "ai_inference",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "risk_assessment",
      title: "Risk Assessment",
      detail: "Calibrating score",
    }),
    "risk_assessment",
  );

  // Current live backend step IDs
  assert.equal(
    classifyTraceStageVisual({
      step_id: "media_forensics",
      title: "Phân tích tính xác thực của hình ảnh, mã QR và ghi âm",
      detail: "Đã kiểm tra 1 hình ảnh, 0 tệp ghi âm và 1 mã QR.",
    }),
    "qr_analysis",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "media_forensics",
      title: "Phân tích tính xác thực của hình ảnh, mã QR và ghi âm",
      detail: "Đã kiểm tra 1 hình ảnh, 0 tệp ghi âm và 0 mã QR.",
    }),
    "ocr_processing",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "cyber_guardrails",
      title: "Kiểm tra đường dẫn đáng ngờ và danh sách chặn",
      detail: "Ghi nhận 0 số điện thoại, 0 số tài khoản và 1 đường dẫn.",
    }),
    "url_scanning",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "onnx_and_kb",
      title: "Đối chiếu nội dung với các kịch bản lừa đảo phổ biến",
      detail: "Đã phân loại ngữ cảnh và ghi nhận 2 kịch bản tương tự.",
    }),
    "ai_inference",
  );
  assert.equal(
    classifyTraceStageVisual({
      step_id: "multimodal_calibration",
      title: "Tổng hợp bằng chứng và đánh giá mức độ rủi ro",
      detail: "Mức độ rủi ro: 88/100 (Rủi ro rất cao)",
    }),
    "risk_assessment",
  );
});

test("selectVisibleBackendTraceSteps keeps only real backend steps and separates skipped stages", () => {
  const result = selectVisibleBackendTraceSteps([
    {
      step_id: "media_forensics",
      title: "Media",
      status: "skipped",
      detail: "Không có hình ảnh hoặc tệp ghi âm đính kèm.",
      duration_ms: 0,
    },
    {
      step_id: "cyber_guardrails",
      title: "Cyber",
      status: "running",
      detail: "Đang quét URL",
      duration_ms: 0,
    },
    {
      step_id: "cyber_guardrails",
      title: "Cyber",
      status: "warning",
      detail: "Ghi nhận 1 đường dẫn đáng ngờ",
      duration_ms: 42,
    },
    {
      step_id: "onnx_and_kb",
      title: "ONNX",
      status: "done",
      detail: "Hoàn tất",
      duration_ms: 18,
    },
  ]);

  assert.deepEqual(
    result.activeSteps.map((s) => `${s.step_id}:${s.status}`),
    ["cyber_guardrails:warning", "onnx_and_kb:done"],
  );
  assert.deepEqual(
    result.skippedSteps.map((s) => s.step_id),
    ["media_forensics"],
  );
});

test("buildVerdictTransitionKey and resolveVerdictMotionProfile enforce merchant honesty guardrail", () => {
  const keyA = buildVerdictTransitionKey({
    case_id: "vs_1",
    verdict: "SAFE",
    risk_score: 10,
    receipt_verification_status: "NOT_APPLICABLE",
  });
  const keyB = buildVerdictTransitionKey({
    case_id: "vs_1",
    verdict: "SAFE",
    risk_score: 10,
    receipt_verification_status: "UNVERIFIED_SCREENSHOT",
  });
  assert.notEqual(keyA, keyB);

  const safeNormal = resolveVerdictMotionProfile("SAFE", "NOT_APPLICABLE");
  assert.equal(safeNormal.tone, "safe");
  assert.equal(safeNormal.emphasizeHonestyGuard, false);

  const safeReceipt = resolveVerdictMotionProfile("SAFE", "UNVERIFIED_SCREENSHOT");
  assert.equal(safeReceipt.tone, "safe_unverified");
  assert.equal(safeReceipt.emphasizeHonestyGuard, true);

  assert.equal(resolveVerdictMotionProfile("SUSPICIOUS", "NOT_APPLICABLE").tone, "suspicious");
  assert.equal(resolveVerdictMotionProfile("HIGH_RISK", "NOT_APPLICABLE").tone, "high_risk");
  assert.equal(resolveVerdictMotionProfile("CRITICAL_SCAM", "NOT_APPLICABLE").tone, "critical");
});

test("resolveRadarMotionScope and shouldAnimateRadarEdge prevent alarming demo alerts and global edge autoplay", () => {
  const demoOnly = resolveRadarMotionScope("demo_only", true);
  assert.equal(demoOnly.mode, "demo_only");
  assert.equal(demoOnly.allowLiveAlertPulse, false);
  assert.equal(demoOnly.sweepTone, "demo_slate");

  const mixed = resolveRadarMotionScope("mixed_with_demo", true);
  assert.equal(mixed.mode, "demo_mixed");
  assert.equal(mixed.allowLiveAlertPulse, false);
  assert.equal(mixed.sweepTone, "demo_slate");

  const live = resolveRadarMotionScope("live", false);
  assert.equal(live.mode, "live");
  assert.equal(live.allowLiveAlertPulse, true);
  assert.equal(live.sweepTone, "live_cyan");

  // Idle graph (no selected node) does not autoplay animations on all edges
  assert.deepEqual(
    shouldAnimateRadarEdge({
      isDirectEdge: false,
      isDemoEdge: false,
      isBlockedEdge: true,
      isDense: false,
      selectedNodeId: null,
      allowLiveAlertPulse: true,
    }),
    { animated: false, variant: "none" },
  );

  // Selected demo edge uses calm demo inspection cyan beam, never red emergency alert
  assert.deepEqual(
    shouldAnimateRadarEdge({
      isDirectEdge: true,
      isDemoEdge: true,
      isBlockedEdge: true,
      isDense: false,
      selectedNodeId: "camp_1",
      allowLiveAlertPulse: false,
    }),
    { animated: true, variant: "demo_inspect_cyan" },
  );

  // Selected real blocked edge in live mode uses distinct live blocked beam
  assert.deepEqual(
    shouldAnimateRadarEdge({
      isDirectEdge: true,
      isDemoEdge: false,
      isBlockedEdge: true,
      isDense: false,
      selectedNodeId: "camp_live",
      allowLiveAlertPulse: true,
    }),
    { animated: true, variant: "live_blocked_amber" },
  );

  // Selected real normal edge uses cyan inspection beam
  assert.deepEqual(
    shouldAnimateRadarEdge({
      isDirectEdge: true,
      isDemoEdge: false,
      isBlockedEdge: false,
      isDense: false,
      selectedNodeId: "camp_live",
      allowLiveAlertPulse: true,
    }),
    { animated: true, variant: "inspect_cyan" },
  );
});
