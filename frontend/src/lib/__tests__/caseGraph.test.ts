import assert from "node:assert/strict";
import test from "node:test";

import {
  buildCaseRelationshipGraph,
  defangUrlForDisplay,
  maskEmailForDisplay,
} from "../caseGraph.ts";
import type { AnalysisReport } from "../types";

function makeCaseReport(overrides: Partial<AnalysisReport> = {}): AnalysisReport {
  return {
    case_id: "vs_graph_case_01",
    created_at: "2026-11-28T09:30:00Z",
    mode: "personal",
    in_active_call: false,
    risk_score: 86,
    verdict: "CRITICAL_SCAM",
    confidence: 0.92,
    degraded_mode: false,
    safety_advisory_detected: false,
    prompt_injection_detected: false,
    active_block_rule_hit: false,
    receipt_verification_status: "NOT_APPLICABLE",
    summary_vi: "Phát hiện liên kết giả mạo ngân hàng và yêu cầu chuyển tiền.",
    transcript: null,
    classifier: null,
    matched_playbooks: ["Giả mạo đổi điểm ngân hàng"],
    manipulation_tactics: ["Tạo áp lực thời gian"],
    highlighted_phrases: [],
    iocs: {
      phones: ["0912345678"],
      bank_accounts: ["190384756201"],
      urls: ["https://vcb-gift.top/claim"],
      domains: ["vcb-gift.top"],
      brands: ["Vietcombank"],
    },
    vietqr_findings: [],
    url_findings: [
      {
        url: "https://vcb-gift.top/claim",
        domain: "vcb-gift.top",
        normalized_ascii_domain: "vcb-gift.top",
        final_url: "https://evil-redirect.xyz/otp",
        redirect_hops: 2,
        is_blocked_ssrf: false,
        is_idn_homoglyph: false,
        spoofed_brand: "Vietcombank",
        domain_age_days: null,
        urlhaus_listed: false,
        risk_points: 85,
        reasons: ["Tên miền giả mạo Vietcombank"],
      },
    ],
    sandbox: null,
    image_forensics: null,
    image_forensics_list: [],
    receipt_logic: null,
    evidence: [
      {
        source: "url_inspector",
        severity: "CRITICAL",
        title: "Rủi ro tên miền",
        detail: "Giả mạo Vietcombank",
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
    trace: [],
    community_hits: 0,
    ...overrides,
  };
}

test("buildCaseRelationshipGraph masks PII, defangs suspicious URLs, and builds real redirect + spoof edges", () => {
  const graph = buildCaseRelationshipGraph(
    makeCaseReport(),
    "Liên hệ ho.tro.gia@example.org hoặc 0912345678 chuyển vào 190384756201",
  );

  // Zero raw phone, bank account, or full email leakage in any node label
  for (const node of graph.nodes) {
    assert.ok(!node.label.includes("0912345678"), `raw phone leaked: ${node.label}`);
    assert.ok(!node.label.includes("190384756201"), `raw bank account leaked: ${node.label}`);
    assert.ok(!node.label.includes("ho.tro.gia@example.org"), `raw email leaked: ${node.label}`);
    assert.ok(!node.label.startsWith("https://"), `live URL scheme should be defanged: ${node.label}`);
  }

  assert.ok(graph.nodes.some((n) => n.kind === "phone" && n.label === "091****678"));
  assert.ok(graph.nodes.some((n) => n.kind === "bank_account" && n.label === "19****01"));
  assert.ok(graph.nodes.some((n) => n.kind === "email" && n.label === "ho***@example.org"));
  assert.ok(graph.nodes.some((n) => n.kind === "domain" && n.label === "evil-redirect.xyz"));
  assert.ok(graph.nodes.some((n) => n.kind === "brand" && n.label === "Vietcombank"));

  // Redirect edge and spoof edge exist with honest verification states
  assert.ok(
    graph.edges.some(
      (e) => e.label === "chuyển hướng tới" && e.verificationState === "verified_evidence",
    ),
  );
  assert.ok(
    graph.edges.some(
      (e) => e.label === "nghi giả mạo" && e.verificationState === "suspected_relation",
    ),
  );

  // Never fabricates a direct link between unrelated phone & bank account
  const phoneNode = graph.nodes.find((n) => n.kind === "phone");
  const bankNode = graph.nodes.find((n) => n.kind === "bank_account");
  assert.ok(phoneNode && bankNode);
  assert.equal(
    graph.edges.some(
      (e) =>
        (e.source === phoneNode.id && e.target === bankNode.id) ||
        (e.source === bankNode.id && e.target === phoneNode.id),
    ),
    false,
  );
});

test("buildCaseRelationshipGraph preserves UNVERIFIED_SCREENSHOT honesty status on SAFE merchant receipts", () => {
  const safeReceipt = makeCaseReport({
    mode: "merchant",
    risk_score: 12,
    verdict: "SAFE",
    receipt_verification_status: "UNVERIFIED_SCREENSHOT",
    matched_playbooks: [],
    manipulation_tactics: [],
    url_findings: [],
    iocs: { phones: [], bank_accounts: [], urls: [], domains: [], brands: [] },
    evidence: [],
    receipt_logic: {
      is_receipt_candidate: true,
      bank_detected: "Vietcombank",
      reference_code: "FT12345",
      reference_valid: true,
      timestamp_anomaly: false,
      amount_format_anomaly: false,
      geometry_anomaly: false,
      beneficiary_mismatch: false,
      extracted_recipient_account: "190384756201",
      is_replayed: false,
      verification_status: "UNVERIFIED_SCREENSHOT",
      logic_risk_points: 0,
      reasons: [],
    },
  });
  const graph = buildCaseRelationshipGraph(safeReceipt);
  const verdictNode = graph.nodes.find((n) => n.kind === "verdict");
  assert.equal(verdictNode?.verificationState, "unverified_info");
  const acctNode = graph.nodes.find((n) => n.kind === "bank_account");
  assert.equal(acctNode?.verificationState, "unverified_info");
  assert.equal(acctNode?.label, "19****01");
});

test("defangUrlForDisplay and maskEmailForDisplay neutralize suspicious URLs and mask emails", () => {
  assert.equal(
    defangUrlForDisplay("https://evil-bank.top/login"),
    "hxxps://evil-bank[.]top/login",
  );
  assert.equal(maskEmailForDisplay("nguyenvana@bank.vn"), "ng***@bank.vn");
  assert.equal(maskEmailForDisplay("a@b.co"), "a***@b.co");
});
