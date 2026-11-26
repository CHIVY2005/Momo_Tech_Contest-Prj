export type VerdictLevel = "SAFE" | "SUSPICIOUS" | "HIGH_RISK" | "CRITICAL_SCAM";
export type AnalyzeMode = "personal" | "merchant" | "wallet_transfer";
export type SeverityLevel = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type TraceStatus = "running" | "done" | "warning" | "skipped";
export type IocType = "phone" | "bank_account" | "domain";
export type QrKind = "VALID_VIETQR" | "INVALID_CRC_VIETQR" | "URL_QR" | "TEXT_QR";

export type ReceiptVerificationStatus =
  | "NOT_APPLICABLE"
  | "UNVERIFIED_SCREENSHOT"
  | "TAMPER_OR_LOGIC_ANOMALY"
  | "REPLAYED_RECEIPT"
  | "BENEFICIARY_MISMATCH";

export interface TraceStep {
  step_id: string;
  title: string;
  status: TraceStatus;
  detail: string;
  duration_ms: number;
}

export interface EvidenceItem {
  source: string;
  severity: SeverityLevel;
  title: string;
  detail: string;
  snippet?: string | null;
}

export interface ExtractedIOCs {
  phones: string[];
  bank_accounts: string[];
  urls: string[];
  domains: string[];
  brands: string[];
}

export interface VietQRInfo {
  raw: string;
  kind: QrKind;
  crc_valid: boolean;
  tlv_valid?: boolean;
  bank_bin?: string | null;
  bank_name?: string | null;
  account_number?: string | null;
  service_code?: string | null;
  is_dynamic: boolean;
  amount?: string | null;
  note?: string | null;
  receive_scam_detected: boolean;
  beneficiary_mismatch: boolean;
}

export interface SandboxInspection {
  available: boolean;
  visited_url: string;
  final_url?: string | null;
  page_title?: string | null;
  blocked_ssrf: boolean;
  has_password_field: boolean;
  has_otp_field: boolean;
  has_apk_download: boolean;
  impersonated_brand?: string | null;
  screenshot_base64?: string | null;
  risk_points: number;
  reasons: string[];
}

export interface UrlFinding {
  url: string;
  domain: string;
  normalized_ascii_domain: string;
  final_url?: string | null;
  redirect_hops: number;
  is_blocked_ssrf: boolean;
  is_idn_homoglyph: boolean;
  spoofed_brand?: string | null;
  domain_age_days?: number | null;
  urlhaus_listed: boolean;
  risk_points: number;
  reasons: string[];
}

export interface ImageForensicsResult {
  filename: string;
  format: string;
  width: number;
  height: number;
  dhash_hex: string;
  exif_software?: string | null;
  editing_software_detected: boolean;
  tamper_score: number;
  ela_heatmap_base64?: string | null;
  qr_payloads: string[];
  ocr_text: string;
  ocr_height_cv: number;
  reasons: string[];
}

export interface ReceiptLogicResult {
  is_receipt_candidate: boolean;
  bank_detected?: string | null;
  reference_code?: string | null;
  reference_valid: boolean;
  timestamp_checked?: boolean;
  timestamp_anomaly: boolean;
  amount_checked?: boolean;
  amount_format_anomaly: boolean;
  geometry_checked?: boolean;
  geometry_anomaly: boolean;
  beneficiary_checked?: boolean;
  beneficiary_mismatch: boolean;
  extracted_recipient_account?: string | null;
  replay_checked?: boolean;
  is_replayed: boolean;
  verification_status: ReceiptVerificationStatus;
  logic_risk_points: number;
  reasons: string[];
}

export interface ScamClassifierOutput {
  available: boolean;
  predicted_label: string;
  scam_probability: number;
  advisory_probability: number;
  injection_probability: number;
  class_probabilities: Record<string, number>;
  latency_ms: number;
}

export interface PreTransferIntervention {
  should_hold_transfer: boolean;
  cooling_off_seconds: number;
  triggered_by_active_call: boolean;
  blocked_by_ops_rule: boolean;
  warning_headline: string;
  verification_questions: string[];
}

export interface ActionBundle {
  counter_replies: string[];
  family_shield_message: string;
  urgent_steps: string[];
  merchant_balance_warning?: string | null;
  pre_transfer: PreTransferIntervention;
}

export interface DemoScenario {
  demo_id: string;
  title_vi: string;
  subtitle_vi: string;
  category_badge: string;
  mode: AnalyzeMode;
  in_active_call: boolean;
  transfer_amount?: number | null;
  expected_merchant_account?: string | null;
  text: string;
  url?: string | null;
  image_filename?: string | null;
  audio_filename?: string | null;
  expected_verdict: VerdictLevel;
}

export interface AnalysisReport {
  case_id: string;
  created_at: string;
  mode: AnalyzeMode;
  in_active_call: boolean;
  risk_score: number;
  verdict: VerdictLevel;
  confidence: number;
  degraded_mode: boolean;
  safety_advisory_detected: boolean;
  prompt_injection_detected: boolean;
  active_block_rule_hit: boolean;
  receipt_verification_status: ReceiptVerificationStatus;
  summary_vi: string;
  transcript?: string | null;
  classifier?: ScamClassifierOutput | null;
  matched_playbooks: string[];
  manipulation_tactics: string[];
  highlighted_phrases: string[];
  iocs: ExtractedIOCs;
  vietqr_findings: VietQRInfo[];
  url_findings: UrlFinding[];
  sandbox?: SandboxInspection | null;
  image_forensics?: ImageForensicsResult | null;
  receipt_logic?: ReceiptLogicResult | null;
  evidence: EvidenceItem[];
  actions: ActionBundle;
  trace: TraceStep[];
  community_hits: number;
  llm_provider?: string;
  llm_model?: string | null;
  llm_latency_ms?: number | null;
  llm_error?: string | null;
}

export interface BlockRule {
  rule_id: string;
  ioc_type: IocType;
  masked_value: string;
  reason: string;
  created_at: string;
  expires_at?: string | null;
  active: boolean;
}

export interface CreateBlockRuleRequest {
  ioc_type: IocType;
  value?: string | null;
  ioc_hash?: string | null;
  masked_value?: string | null;
  reason: string;
  analyst_pin: string;
  ttl_minutes?: number | null;
}

export interface RadarNode {
  node_id: string;
  kind: "phone" | "bank_account" | "domain" | "campaign";
  label: string;
  hit_count: number;
  risk_level: VerdictLevel;
  blocked: boolean;
}

export interface RadarEdge {
  source: string;
  target: string;
  relation: string;
}

export interface EmergingCampaign {
  campaign_id: string;
  title_vi: string;
  playbook_id: string;
  case_count: number;
  primary_ioc_type: IocType;
  primary_ioc_masked: string;
  primary_ioc_hash: string;
  recommended_action: string;
  already_blocked: boolean;
}

export interface RadarGraphResponse {
  nodes: RadarNode[];
  edges: RadarEdge[];
  campaigns: EmergingCampaign[];
  active_block_rules: BlockRule[];
  stats: Record<string, number>;
}

export interface SystemHealthResponse {
  status: string;
  service: string;
  version: string;
  sqlite_wal_ready?: boolean;
  onnx_classifier_loaded: boolean;
  local_ocr_enabled?: boolean;
  local_stt_enabled?: boolean;
  gemini_configured: boolean;
  llm_provider?: string;
  llm_model?: string;
  llm_base_url_configured?: boolean;
  telegram_bot_configured?: boolean;
  telegram_bot_url?: string | null;
  playbooks_count: number;
}
