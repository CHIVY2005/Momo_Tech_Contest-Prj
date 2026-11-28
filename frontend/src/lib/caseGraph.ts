/**
 * Pure-TS Case-Level Fraud Relationship Graph builder & deterministic auto-layout.
 * Strictly evidence-backed: zero fabricated links, masked PII only, neutral forensic framing.
 * Zero React/JSX and zero `@/` imports so Node's test runner tests it directly.
 */

import { defangUrlForDisplay, maskDisplayIoc } from "./formatters.ts";
import type { AnalysisReport, EvidenceItem, VerdictLevel } from "./types";

export { defangUrlForDisplay };

export type CaseEntityKind =
  | "case"
  | "url"
  | "domain"
  | "phone"
  | "bank_account"
  | "email"
  | "brand"
  | "signal"
  | "evidence_source"
  | "verdict";

export type VerificationState =
  | "verified_evidence"
  | "extracted_info"
  | "suspected_relation"
  | "unverified_info";

export type RiskTone = "safe" | "info" | "suspicious" | "high" | "critical";

export interface CaseGraphNode {
  id: string;
  kind: CaseEntityKind;
  label: string;
  subtitle: string;
  verificationState: VerificationState;
  riskTone: RiskTone;
  detail: string;
  evidenceSource?: string;
  copyValue?: string;
  column: number;
  x: number;
  y: number;
}

export interface CaseGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  verificationState: VerificationState;
  detail: string;
}

export interface CaseRelationshipGraph {
  nodes: CaseGraphNode[];
  edges: CaseGraphEdge[];
}

export const ENTITY_KIND_LABELS: Record<CaseEntityKind, string> = {
  case: "Hồ sơ đầu vào",
  url: "Đường dẫn (URL)",
  domain: "Tên miền",
  phone: "Số điện thoại",
  bank_account: "Tài khoản ngân hàng",
  email: "Địa chỉ email",
  brand: "Thương hiệu liên quan",
  signal: "Dấu hiệu rủi ro",
  evidence_source: "Nguồn bằng chứng",
  verdict: "Kết quả phân tích",
};

export const VERIFICATION_STATE_META: Record<
  VerificationState,
  { label: string; description: string }
> = {
  verified_evidence: {
    label: "Bằng chứng đã kiểm định",
    description: "Kết quả từ kiểm tra kỹ thuật xác định (URL, trình duyệt cách ly, CRC-16 VietQR, ELA/EXIF hoặc danh sách chặn).",
  },
  extracted_info: {
    label: "Thông tin trích xuất",
    description: "Thực thể được tách tự động từ văn bản, ảnh OCR hoặc mã QR; chưa tự động quy kết chủ sở hữu.",
  },
  suspected_relation: {
    label: "Liên hệ nghi vấn",
    description: "Mối liên hệ rủi ro suy luận từ dấu hiệu giả mạo thương hiệu, kịch bản lừa đảo hoặc chiến thuật gây áp lực.",
  },
  unverified_info: {
    label: "Chưa xác minh",
    description: "Thông tin chưa được kiểm chứng độc lập (ví dụ ảnh chụp biên lai chưa xác nhận tiền về hoặc URL chỉ xuất hiện trong OCR).",
  },
};

const EMAIL_RE = /\b([A-Za-z0-9._%+-]{1,40})@([A-Za-z0-9.-]+\.[A-Za-z]{2,16})\b/g;

export function maskEmailForDisplay(raw: string): string {
  const trimmed = raw.trim();
  const atIdx = trimmed.indexOf("@");
  if (atIdx <= 0) return trimmed;
  const local = trimmed.slice(0, atIdx);
  const domain = trimmed.slice(atIdx + 1);
  if (local.length <= 2) return `${local[0] ?? "*"}***@${domain}`;
  return `${local.slice(0, 2)}***@${domain}`;
}

function verdictToTone(verdict: VerdictLevel): RiskTone {
  switch (verdict) {
    case "CRITICAL_SCAM":
      return "critical";
    case "HIGH_RISK":
      return "high";
    case "SUSPICIOUS":
      return "suspicious";
    default:
      return "safe";
  }
}

function extractDomainHost(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function truncateText(value: string, max = 34): string {
  const clean = value.trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

const SOURCE_LABELS: Record<string, string> = {
  image_forensics: "Phân tích ảnh (ELA/EXIF)",
  vietqr_parser: "Kiểm định mã VietQR",
  url_inspector: "Kiểm tra URL & tên miền",
  phishing_sandbox: "Trình duyệt cách ly",
  receipt_validator: "Đối chiếu biên lai",
  fraud_ops_radar: "Danh sách chặn Radar",
  guardrails: "Bộ lọc an toàn nội dung",
  ocr_engine: "Trích xuất chữ OCR",
  gemini_vision: "Phân tích ngữ cảnh AI",
  pipeline: "Tổng hợp đa tầng",
};

/**
 * Compute deterministic layered auto-layout coordinates (left-to-right investigation flow)
 * so React Flow nodes never overlap on mount or after re-layout.
 */
export function computeCaseGraphLayout(
  nodes: CaseGraphNode[],
  columnGap = 285,
  rowGap = 112,
): CaseGraphNode[] {
  const byColumn = new Map<number, CaseGraphNode[]>();
  for (const node of nodes) {
    const bucket = byColumn.get(node.column) ?? [];
    bucket.push(node);
    byColumn.set(node.column, bucket);
  }

  const maxRows = Math.max(1, ...Array.from(byColumn.values(), (list) => list.length));
  const totalHeight = (maxRows - 1) * rowGap;

  const positioned = new Map<string, { x: number; y: number }>();
  for (const [col, list] of byColumn.entries()) {
    const colHeight = (list.length - 1) * rowGap;
    const startY = Math.round((totalHeight - colHeight) / 2);
    list.forEach((node, idx) => {
      positioned.set(node.id, {
        x: 24 + col * columnGap,
        y: 24 + startY + idx * rowGap,
      });
    });
  }

  return nodes.map((node) => {
    const pos = positioned.get(node.id);
    return pos ? { ...node, x: pos.x, y: pos.y } : node;
  });
}

/**
 * Construct a strictly evidence-backed case relationship graph from AnalysisReport.
 * Never fabricates links between unrelated entities and masks all PII.
 */
export function buildCaseRelationshipGraph(
  report: AnalysisReport,
  submittedText = "",
): CaseRelationshipGraph {
  const nodes: CaseGraphNode[] = [];
  const edges: CaseGraphEdge[] = [];
  const nodeIds = new Set<string>();
  const edgeIds = new Set<string>();

  function addNode(node: Omit<CaseGraphNode, "x" | "y">) {
    if (nodeIds.has(node.id)) return;
    nodeIds.add(node.id);
    nodes.push({ ...node, x: 0, y: 0 });
  }

  function addEdge(edge: Omit<CaseGraphEdge, "id">) {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return;
    const id = `${edge.source}__${edge.target}__${edge.label}`;
    if (edgeIds.has(id)) return;
    edgeIds.add(id);
    edges.push({ ...edge, id });
  }

  // Column 0: Root Case Input
  const caseNodeId = "case-root";
  const hasReceipt =
    report.receipt_verification_status !== "NOT_APPLICABLE" ||
    Boolean(report.receipt_logic?.is_receipt_candidate);
  addNode({
    id: caseNodeId,
    kind: "case",
    label: `Hồ sơ ${report.case_id.slice(0, 12)}`,
    subtitle:
      report.mode === "merchant"
        ? "Ngữ cảnh biên lai / bán hàng"
        : report.mode === "wallet_transfer"
          ? "Ngữ cảnh chuẩn bị chuyển tiền"
          : "Tin nhắn / đường dẫn đầu vào",
    verificationState:
      report.receipt_verification_status === "UNVERIFIED_SCREENSHOT"
        ? "unverified_info"
        : "extracted_info",
    riskTone: verdictToTone(report.verdict),
    detail: report.summary_vi,
    column: 0,
  });

  // Column 1: Extracted Entities (URLs, Phones, Bank Accounts, Emails)
  const domainNodeByHost = new Map<string, string>();
  const brandNodeByName = new Map<string, string>();

  for (const uf of report.url_findings) {
    const urlId = `url-${uf.url}`;
    const urlTone: RiskTone =
      uf.is_blocked_ssrf || uf.risk_points >= 75
        ? "critical"
        : uf.risk_points >= 45 || uf.is_idn_homoglyph || Boolean(uf.spoofed_brand)
          ? "high"
          : uf.risk_points >= 20
            ? "suspicious"
            : "info";

    addNode({
      id: urlId,
      kind: "url",
      label: truncateText(defangUrlForDisplay(uf.url), 30),
      subtitle: `Rủi ro URL: ${uf.risk_points}/100`,
      verificationState: "verified_evidence",
      riskTone: urlTone,
      detail:
        uf.reasons.length > 0
          ? uf.reasons.join(" · ")
          : `Đường dẫn đã được kiểm tra kỹ thuật (điểm ${uf.risk_points}/100). Không mở trực tiếp liên kết đáng ngờ.`,
      evidenceSource: "url_inspector",
      copyValue: defangUrlForDisplay(uf.url),
      column: 1,
    });
    addEdge({
      source: caseNodeId,
      target: urlId,
      label: "chứa đường dẫn",
      verificationState: "extracted_info",
      detail: "Đường dẫn được tách từ nội dung đầu vào hoặc mã QR.",
    });

    const host = (uf.normalized_ascii_domain || uf.domain || "").toLowerCase();
    if (host) {
      const domId = `domain-${host}`;
      domainNodeByHost.set(host, domId);
      addNode({
        id: domId,
        kind: "domain",
        label: truncateText(host, 28),
        subtitle: uf.is_idn_homoglyph
          ? "Tên miền đồng hình IDN"
          : uf.redirect_hops > 0
            ? `${uf.redirect_hops} bước chuyển hướng`
            : "Tên miền trích xuất",
        verificationState: "verified_evidence",
        riskTone: urlTone,
        detail: `Tên miền chuẩn hóa ASCII: ${host}${uf.final_url ? ` · Đích cuối: ${defangUrlForDisplay(uf.final_url)}` : ""}`,
        evidenceSource: "url_inspector",
        copyValue: host,
        column: 2,
      });
      addEdge({
        source: urlId,
        target: domId,
        label: "thuộc tên miền",
        verificationState: "verified_evidence",
        detail: `Đường dẫn phân giải về tên miền ${host}.`,
      });

      if (uf.final_url) {
        const finalHost = extractDomainHost(uf.final_url);
        if (finalHost && finalHost !== host) {
          const finalDomId = `domain-${finalHost}`;
          domainNodeByHost.set(finalHost, finalDomId);
          addNode({
            id: finalDomId,
            kind: "domain",
            label: truncateText(finalHost, 28),
            subtitle: "Đích chuyển hướng cuối",
            verificationState: "verified_evidence",
            riskTone: urlTone,
            detail: `Tên miền đích cuối sau khi theo dõi chuyển hướng ràng buộc IP công cộng.`,
            evidenceSource: "url_inspector",
            copyValue: finalHost,
            column: 2,
          });
          addEdge({
            source: urlId,
            target: finalDomId,
            label: "chuyển hướng tới",
            verificationState: "verified_evidence",
            detail: `Ghi nhận ${uf.redirect_hops} bước chuyển hướng tới ${finalHost}.`,
          });
        }
      }

      if (uf.spoofed_brand) {
        const brandKey = uf.spoofed_brand.trim().toLowerCase();
        const brandId = `brand-${brandKey}`;
        brandNodeByName.set(brandKey, brandId);
        addNode({
          id: brandId,
          kind: "brand",
          label: uf.spoofed_brand,
          subtitle: "Thương hiệu có dấu hiệu bị giả mạo",
          verificationState: "suspected_relation",
          riskTone: "high",
          detail: `Tên miền ${host} có cấu trúc gần giống thương hiệu chính thống ${uf.spoofed_brand}.`,
          evidenceSource: "url_inspector",
          column: 3,
        });
        addEdge({
          source: domId,
          target: brandId,
          label: "nghi giả mạo",
          verificationState: "suspected_relation",
          detail: `Bộ kiểm tra tên miền phát hiện độ tương đồng bất thường với ${uf.spoofed_brand}.`,
        });
      }
    }
  }

  for (const rawDomain of report.iocs.domains) {
    const cleanDom = rawDomain.trim().toLowerCase();
    if (!cleanDom || domainNodeByHost.has(cleanDom)) continue;
    const domId = `domain-${cleanDom}`;
    domainNodeByHost.set(cleanDom, domId);
    addNode({
      id: domId,
      kind: "domain",
      label: truncateText(cleanDom, 28),
      subtitle: "Tên miền trích xuất",
      verificationState: "extracted_info",
      riskTone: report.active_block_rule_hit ? "critical" : "suspicious",
      detail: `Tên miền được tách tự động từ văn bản hoặc ảnh OCR (không tự động mở trực tiếp).`,
      copyValue: cleanDom,
      column: 2,
    });
    addEdge({
      source: caseNodeId,
      target: domId,
      label: "nhắc tới tên miền",
      verificationState: "extracted_info",
      detail: "Tên miền xuất hiện trong nội dung kiểm tra.",
    });
  }

  for (const rawPhone of report.iocs.phones) {
    const masked = maskDisplayIoc(rawPhone);
    const phoneId = `phone-${masked}`;
    addNode({
      id: phoneId,
      kind: "phone",
      label: masked,
      subtitle: "SĐT trích xuất (đã che)",
      verificationState: report.active_block_rule_hit ? "verified_evidence" : "extracted_info",
      riskTone: report.active_block_rule_hit ? "critical" : "suspicious",
      detail:
        "Số điện thoại được trích xuất và che giấu một phần. Chỉ mang tính chỉ báo hồ sơ, không quy kết danh tính chủ thuê bao.",
      copyValue: masked,
      column: 1,
    });
    addEdge({
      source: caseNodeId,
      target: phoneId,
      label: "nhắc tới SĐT",
      verificationState: "extracted_info",
      detail: "Số điện thoại xuất hiện trong văn bản, lời thoại hoặc chữ ảnh OCR.",
    });
  }

  const seenAccounts = new Set<string>();
  const addBankAccount = (
    rawAccount: string,
    subtitle: string,
    state: VerificationState,
    riskTone: RiskTone,
    edgeLabel: string,
    evidenceSource?: string,
  ) => {
    const masked = maskDisplayIoc(rawAccount);
    if (!masked || seenAccounts.has(masked)) return;
    seenAccounts.add(masked);
    const acctId = `bank-${masked}`;
    addNode({
      id: acctId,
      kind: "bank_account",
      label: masked,
      subtitle,
      verificationState: state,
      riskTone,
      detail:
        "Số tài khoản đã được che giấu tự động để bảo vệ riêng tư. Không tự động quy kết chủ tài khoản là đối tượng lừa đảo nếu chưa có xác minh từ cơ quan chức năng.",
      evidenceSource,
      copyValue: masked,
      column: 1,
    });
    addEdge({
      source: caseNodeId,
      target: acctId,
      label: edgeLabel,
      verificationState: state,
      detail: subtitle,
    });
  };

  for (const vqr of report.vietqr_findings) {
    if (vqr.account_number) {
      const qrTone: RiskTone =
        vqr.receive_scam_detected || vqr.beneficiary_mismatch
          ? "critical"
          : vqr.crc_valid
            ? "info"
            : "high";
      addBankAccount(
        vqr.account_number,
        vqr.bank_name ? `VietQR · ${vqr.bank_name}` : "Giải mã từ mã VietQR",
        vqr.crc_valid ? "verified_evidence" : "unverified_info",
        qrTone,
        "mã VietQR trỏ tới STK",
        "vietqr_parser",
      );
    }
  }

  if (report.receipt_logic?.extracted_recipient_account) {
    addBankAccount(
      report.receipt_logic.extracted_recipient_account,
      report.receipt_logic.beneficiary_mismatch
        ? "STK trên ảnh biên lai (lệch tài khoản nhận)"
        : "STK đọc từ ảnh biên lai (chưa xác nhận tiền về)",
      report.receipt_logic.beneficiary_mismatch ? "verified_evidence" : "unverified_info",
      report.receipt_logic.beneficiary_mismatch ? "critical" : "suspicious",
      "biên lai ghi STK",
      "receipt_validator",
    );
  }

  for (const rawAcct of report.iocs.bank_accounts) {
    addBankAccount(
      rawAcct,
      "STK trích xuất (đã che)",
      report.active_block_rule_hit ? "verified_evidence" : "extracted_info",
      report.active_block_rule_hit ? "critical" : "suspicious",
      "nhắc tới STK",
    );
  }

  // Extract masked emails if present in submitted text or OCR text
  const combinedEmailSource = [
    submittedText,
    report.image_forensics?.ocr_text ?? "",
    report.transcript ?? "",
  ].join("\n");
  const seenEmails = new Set<string>();
  EMAIL_RE.lastIndex = 0;
  let emailMatch: RegExpExecArray | null = null;
  while ((emailMatch = EMAIL_RE.exec(combinedEmailSource)) !== null && seenEmails.size < 3) {
    const rawEmail = emailMatch[0];
    if (!rawEmail) continue;
    const masked = maskEmailForDisplay(rawEmail);
    if (seenEmails.has(masked)) continue;
    seenEmails.add(masked);
    const emailId = `email-${masked}`;
    addNode({
      id: emailId,
      kind: "email",
      label: truncateText(masked, 28),
      subtitle: "Email trích xuất (đã che)",
      verificationState: "extracted_info",
      riskTone: "info",
      detail: "Địa chỉ email tách từ nội dung văn bản/ảnh OCR và đã che phần định danh cục bộ.",
      copyValue: masked,
      column: 1,
    });
    addEdge({
      source: caseNodeId,
      target: emailId,
      label: "chứa email",
      verificationState: "extracted_info",
      detail: "Email xuất hiện trong nội dung gửi kiểm tra.",
    });
  }

  // Brands (from sandbox impersonation & iocs.brands)
  if (report.sandbox?.impersonated_brand) {
    const bKey = report.sandbox.impersonated_brand.trim().toLowerCase();
    if (!brandNodeByName.has(bKey)) {
      const brandId = `brand-${bKey}`;
      brandNodeByName.set(bKey, brandId);
      addNode({
        id: brandId,
        kind: "brand",
        label: report.sandbox.impersonated_brand,
        subtitle: "Thương hiệu bị mạo danh trên trang đích",
        verificationState: "verified_evidence",
        riskTone: "critical",
        detail: "Trình duyệt cách ly phát hiện trang đích hiển thị nhận diện giả mạo thương hiệu này.",
        evidenceSource: "phishing_sandbox",
        column: 3,
      });
      addEdge({
        source: caseNodeId,
        target: brandId,
        label: "trang đích mạo danh",
        verificationState: "verified_evidence",
        detail: "Ghi nhận từ phân tích DOM trong môi trường trình duyệt cách ly.",
      });
    }
  }

  for (const rawBrand of report.iocs.brands.slice(0, 4)) {
    const clean = rawBrand.trim();
    const bKey = clean.toLowerCase();
    if (!clean || brandNodeByName.has(bKey)) continue;
    const brandId = `brand-${bKey}`;
    brandNodeByName.set(bKey, brandId);
    addNode({
      id: brandId,
      kind: "brand",
      label: truncateText(clean, 26),
      subtitle: "Thương hiệu được nhắc tới",
      verificationState: "extracted_info",
      riskTone: "info",
      detail: `Thương hiệu ${clean} xuất hiện trong nội dung tin nhắn hoặc biên lai (cần tự xác minh qua kênh chính thức).`,
      column: 2,
    });
    addEdge({
      source: caseNodeId,
      target: brandId,
      label: "nhắc tới thương hiệu",
      verificationState: "extracted_info",
      detail: "Xuất hiện tên thương hiệu trong nội dung đầu vào.",
    });
  }

  // Column 3: Evidence Sources (real modules that produced evidence) & Scam Signals
  const evidenceBySource = new Map<string, EvidenceItem[]>();
  for (const item of report.evidence) {
    const list = evidenceBySource.get(item.source) ?? [];
    list.push(item);
    evidenceBySource.set(item.source, list);
  }

  const evidenceSourceNodeIds: string[] = [];
  for (const [source, items] of evidenceBySource.entries()) {
    const srcId = `source-${source}`;
    evidenceSourceNodeIds.push(srcId);
    const hasCritical = items.some((i) => i.severity === "CRITICAL");
    const hasHigh = items.some((i) => i.severity === "HIGH");
    const isUnverifiedReceipt =
      source === "receipt_validator" &&
      report.receipt_verification_status === "UNVERIFIED_SCREENSHOT";

    addNode({
      id: srcId,
      kind: "evidence_source",
      label: SOURCE_LABELS[source] ?? source,
      subtitle: `${items.length} mục bằng chứng`,
      verificationState: isUnverifiedReceipt
        ? "unverified_info"
        : source === "gemini_vision"
          ? "suspected_relation"
          : "verified_evidence",
      riskTone: hasCritical ? "critical" : hasHigh ? "high" : "suspicious",
      detail: items.map((i) => i.title).slice(0, 3).join(" · "),
      evidenceSource: source,
      column: 3,
    });

    // Connect evidence source ONLY to entities that truly relate to it
    let linkedSpecific = false;
    if (source === "url_inspector" || source === "phishing_sandbox") {
      for (const uf of report.url_findings) {
        const uid = `url-${uf.url}`;
        if (nodeIds.has(uid)) {
          addEdge({
            source: uid,
            target: srcId,
            label: "được kiểm định bởi",
            verificationState: "verified_evidence",
            detail: `Mô-đun ${SOURCE_LABELS[source] ?? source} ghi nhận ${items.length} bằng chứng.`,
          });
          linkedSpecific = true;
        }
      }
    } else if (source === "vietqr_parser") {
      for (const vqr of report.vietqr_findings) {
        if (vqr.account_number) {
          const aid = `bank-${maskDisplayIoc(vqr.account_number)}`;
          if (nodeIds.has(aid)) {
            addEdge({
              source: aid,
              target: srcId,
              label: "giải mã từ VietQR",
              verificationState: "verified_evidence",
              detail: "Kiểm định CRC-16 và cấu trúc TLV EMVCo.",
            });
            linkedSpecific = true;
          }
        }
      }
    } else if (source === "receipt_validator" && report.receipt_logic?.extracted_recipient_account) {
      const aid = `bank-${maskDisplayIoc(report.receipt_logic.extracted_recipient_account)}`;
      if (nodeIds.has(aid)) {
        addEdge({
          source: aid,
          target: srcId,
          label: "đối chiếu biên lai",
          verificationState: isUnverifiedReceipt ? "unverified_info" : "verified_evidence",
          detail: "Kiểm tra nghiệp vụ biên lai chuyển khoản.",
        });
        linkedSpecific = true;
      }
    }

    if (!linkedSpecific) {
      addEdge({
        source: caseNodeId,
        target: srcId,
        label: "phát hiện từ",
        verificationState: "verified_evidence",
        detail: `Mô-đun ${SOURCE_LABELS[source] ?? source} đóng góp ${items.length} mục bằng chứng.`,
      });
    }
  }

  // Scam Signals (playbooks + top manipulation tactics, capped cleanly for readability)
  const signalNodeIds: string[] = [];
  for (const pb of report.matched_playbooks.slice(0, 3)) {
    const clean = pb.trim();
    if (!clean) continue;
    const sigId = `signal-pb-${clean.toLowerCase()}`;
    signalNodeIds.push(sigId);
    addNode({
      id: sigId,
      kind: "signal",
      label: truncateText(clean, 28),
      subtitle: "Kịch bản tương đồng",
      verificationState: "suspected_relation",
      riskTone: report.risk_score >= 75 ? "critical" : "high",
      detail: `Nội dung hồ sơ có nét tương đồng với kịch bản "${clean}" trong kho tri thức phòng chống lừa đảo.`,
      evidenceSource: "pipeline",
      column: 3,
    });
    addEdge({
      source: caseNodeId,
      target: sigId,
      label: "khớp dấu hiệu kịch bản",
      verificationState: "suspected_relation",
      detail: "So khớp ngữ nghĩa và từ khóa trên kho tri thức Việt Nam.",
    });
  }

  for (const tac of report.manipulation_tactics.slice(0, 2)) {
    const clean = tac.trim();
    if (!clean) continue;
    const sigId = `signal-tac-${clean.toLowerCase()}`;
    signalNodeIds.push(sigId);
    addNode({
      id: sigId,
      kind: "signal",
      label: truncateText(clean, 28),
      subtitle: "Dấu hiệu thao túng tâm lý",
      verificationState: "suspected_relation",
      riskTone: "suspicious",
      detail: `Chiến thuật gây áp lực tâm lý được nhận diện trong nội dung hội thoại.`,
      evidenceSource: "gemini_vision",
      column: 3,
    });
    addEdge({
      source: caseNodeId,
      target: sigId,
      label: "có dấu hiệu thao túng",
      verificationState: "suspected_relation",
      detail: "Nhận diện tín hiệu gây áp lực thời gian, uy hiếp hoặc dụ dỗ.",
    });
  }

  // Column 4: Final Calibrated Verdict Node
  const verdictNodeId = "verdict-final";
  addNode({
    id: verdictNodeId,
    kind: "verdict",
    label: `Điểm rủi ro ${report.risk_score}/100`,
    subtitle: hasReceipt && report.verdict === "SAFE"
      ? "Chưa xác nhận tiền về từ ảnh"
      : `Độ tin cậy ${Math.round(report.confidence * 100)}%`,
    verificationState:
      hasReceipt && report.receipt_verification_status === "UNVERIFIED_SCREENSHOT"
        ? "unverified_info"
        : "verified_evidence",
    riskTone: verdictToTone(report.verdict),
    detail: report.summary_vi,
    column: 4,
  });

  // Connect active sources & signals into final verdict (or root case if minimal report)
  const incomingToVerdict = [...evidenceSourceNodeIds, ...signalNodeIds];
  if (incomingToVerdict.length === 0) {
    addEdge({
      source: caseNodeId,
      target: verdictNodeId,
      label: "đánh giá tổng hợp",
      verificationState: "verified_evidence",
      detail: "Kết luận hiệu chuẩn từ hệ thống phân tích đa tầng.",
    });
  } else {
    for (const srcId of incomingToVerdict) {
      addEdge({
        source: srcId,
        target: verdictNodeId,
        label: "đóng góp đánh giá",
        verificationState: srcId.startsWith("source-")
          ? "verified_evidence"
          : "suspected_relation",
        detail: "Tín hiệu được đưa vào tầng hiệu chuẩn rủi ro cuối cùng.",
      });
    }
  }

  return {
    nodes: computeCaseGraphLayout(nodes),
    edges,
  };
}
