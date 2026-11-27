"use client";

import {
  AlertTriangle,
  BookOpen,
  FileWarning,
  HelpCircle,
  SearchCheck,
} from "lucide-react";

import type { AnalysisReport, AssistantQuickIntent } from "@/lib/types";

export interface AssistantQuickAction {
  id: string;
  label: string;
  prompt: string;
  intent: AssistantQuickIntent;
  tone: "default" | "urgent" | "merchant";
}

export function isMerchantOrReceiptContext(report: AnalysisReport): boolean {
  const receiptStatus: string = report.receipt_verification_status;
  return (
    report.mode === "merchant" ||
    Boolean(report.receipt_logic?.is_receipt_candidate) ||
    receiptStatus === "UNVERIFIED_SCREENSHOT" ||
    receiptStatus === "SUSPECTED_FAKE_RECEIPT" ||
    receiptStatus === "TAMPER_OR_LOGIC_ANOMALY" ||
    receiptStatus === "REPLAYED_RECEIPT" ||
    receiptStatus === "BENEFICIARY_MISMATCH" ||
    Boolean(report.actions.merchant_balance_warning)
  );
}

export function buildContextQuickActions(report: AnalysisReport): AssistantQuickAction[] {
  const isMerchant = isMerchantOrReceiptContext(report);
  const isHighOrCritical =
    report.verdict === "HIGH_RISK" ||
    report.verdict === "CRITICAL_SCAM" ||
    report.in_active_call;

  const actions: AssistantQuickAction[] = [
    {
      id: "explain_report",
      label: "Giải thích kết quả phân tích này",
      prompt:
        "Hãy giải thích dễ hiểu kết quả phân tích của hồ sơ này và những dấu hiệu rủi ro quan trọng nhất.",
      intent: "explain_report",
      tone: "default",
    },
  ];

  if (isHighOrCritical) {
    actions.push({
      id: "incident_response",
      label: "Tôi lỡ chuyển tiền / lộ OTP — cần làm gì ngay?",
      prompt:
        "Tôi lỡ chuyển tiền hoặc đã cung cấp mã OTP / thông tin nhạy cảm, tôi cần làm gì ngay lập tức?",
      intent: "incident_response",
      tone: "urgent",
    });
  }

  if (isMerchant) {
    actions.push({
      id: "merchant_receipt_verify",
      label: "Kiểm tra biên lai & cách xác minh tiền về",
      prompt:
        "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không? Hướng dẫn tôi cách tự xác minh tiền đã thực sự vào tài khoản.",
      intent: "verify_info",
      tone: "merchant",
    });
  } else {
    actions.push({
      id: "verify_info",
      label: "Cách tự kiểm chứng thông tin này",
      prompt:
        report.verdict === "SAFE"
          ? "Kết quả mức rủi ro thấp có nghĩa là chắc chắn an toàn không? Tôi nên tự kiểm chứng thêm những bước nào trước khi giao dịch?"
          : "Hướng dẫn tôi cách tự kiểm chứng thông tin, số tài khoản hoặc đường dẫn trong tình huống này qua kênh chính thức.",
      intent: "verify_info",
      tone: "default",
    });
  }

  const hasMatchedPlaybook =
    report.matched_playbooks.length > 0 || Boolean(report.classifier?.predicted_label);
  actions.push({
    id: "scam_education",
    label: "Thủ đoạn lừa đảo liên quan là gì?",
    prompt: isMerchant
      ? "Thủ đoạn lừa đảo biên lai giả hoặc giả mạo thanh toán liên quan đến hồ sơ này hoạt động như thế nào và cần phòng tránh ra sao?"
      : hasMatchedPlaybook
        ? "Thủ đoạn lừa đảo liên quan đến tình huống này hoạt động như thế nào và làm sao nhận biết sớm nếu đối phương đổi kịch bản?"
        : "Những thủ đoạn lừa đảo trực tuyến phổ biến nào có dấu hiệu tương tự và cách tự bảo vệ hiệu quả nhất là gì?",
    intent: "scam_education",
    tone: "default",
  });

  if (!isHighOrCritical && !isMerchant) {
    actions.push({
      id: "incident_response_safe",
      label: "Tôi lỡ chuyển tiền / lộ OTP — cần làm gì ngay?",
      prompt:
        "Nếu tôi lỡ chuyển tiền hoặc đã cung cấp mã OTP / thông tin cá nhân cho người lạ, tôi cần xử lý khẩn cấp theo các bước nào?",
      intent: "incident_response",
      tone: "urgent",
    });
  }

  return actions;
}

interface AssistantQuickActionsProps {
  report: AnalysisReport;
  disabled?: boolean;
  onSelect: (action: AssistantQuickAction) => void;
}

export function AssistantQuickActions({
  report,
  disabled = false,
  onSelect,
}: AssistantQuickActionsProps) {
  const actions = buildContextQuickActions(report);

  return (
    <div className="space-y-2" aria-label="Gợi ý câu hỏi nhanh theo hồ sơ">
      <p className="text-[11px] font-semibold text-ink-muted">Gợi ý câu hỏi theo hồ sơ hiện tại:</p>
      <div className="grid grid-cols-1 gap-2">
        {actions.map((action) => {
          const toneClass =
            action.tone === "urgent"
              ? "border-rose-500/40 bg-rose-500/10 text-rose-100 hover:border-rose-400/70 hover:bg-rose-500/18"
              : action.tone === "merchant"
                ? "border-amber-500/45 bg-amber-500/12 text-amber-100 hover:border-amber-400/75 hover:bg-amber-500/20"
                : "border-border-strong bg-surface-subtle text-ink-secondary hover:border-sky-400/60 hover:bg-surface-elevated hover:text-ink";

          const Icon =
            action.tone === "urgent"
              ? AlertTriangle
              : action.tone === "merchant"
                ? FileWarning
                : action.intent === "explain_report"
                  ? HelpCircle
                  : action.intent === "verify_info"
                    ? SearchCheck
                    : BookOpen;

          const iconColor =
            action.tone === "urgent"
              ? "text-rose-300"
              : action.tone === "merchant"
                ? "text-amber-300"
                : "text-sky-400";

          return (
            <button
              key={action.id}
              type="button"
              disabled={disabled}
              onClick={() => onSelect(action)}
              className={`flex min-h-[40px] w-full cursor-pointer items-center gap-2.5 rounded-xl border px-3 py-2 text-left text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-55 ${toneClass}`}
            >
              <Icon className={`h-4 w-4 shrink-0 ${iconColor}`} aria-hidden="true" />
              <span className="leading-snug">{action.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
