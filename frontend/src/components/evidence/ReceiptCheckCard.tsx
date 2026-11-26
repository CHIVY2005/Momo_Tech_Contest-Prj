"use client";

import { AlertTriangle, CheckCircle2, MinusCircle } from "lucide-react";

import type { ReceiptLogicResult } from "@/lib/types";

interface ReceiptCheckCardProps {
  receipt: ReceiptLogicResult;
}

type CheckState = "pass" | "fail" | "unchecked";

function StatusRow({
  state,
  label,
  detail,
}: {
  state: CheckState;
  label: string;
  detail: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-slate-800 bg-[#0b1120] px-3 py-2.5">
      <div className="flex items-start gap-2">
        {state === "pass" ? (
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
        ) : state === "fail" ? (
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
        ) : (
          <MinusCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
        )}
        <div>
          <p className="text-xs font-semibold text-slate-100">{label}</p>
          <p className="text-[11px] text-slate-400">{detail}</p>
        </div>
      </div>
      <span
        className={`shrink-0 rounded px-2 py-0.5 font-[family-name:var(--font-mono)] text-[10px] font-semibold ${
          state === "pass"
            ? "bg-emerald-500/15 text-emerald-300"
            : state === "fail"
              ? "bg-rose-500/15 text-rose-300"
              : "bg-slate-800 text-slate-300"
        }`}
      >
        {state === "pass" ? "KHÔNG BẤT THƯỜNG" : state === "fail" ? "BẤT THƯỜNG" : "CHƯA ĐỐI CHIẾU"}
      </span>
    </div>
  );
}

export function ReceiptCheckCard({ receipt }: ReceiptCheckCardProps) {
  const refState: CheckState = !receipt.reference_valid
    ? "fail"
    : receipt.reference_code
      ? "pass"
      : "unchecked";
  const timestampState: CheckState = receipt.timestamp_anomaly
    ? "fail"
    : receipt.timestamp_checked
      ? "pass"
      : "unchecked";
  const amountState: CheckState = receipt.amount_format_anomaly
    ? "fail"
    : receipt.amount_checked
      ? "pass"
      : "unchecked";
  const geometryState: CheckState = receipt.geometry_anomaly
    ? "fail"
    : receipt.geometry_checked
      ? "pass"
      : "unchecked";
  const beneficiaryState: CheckState = receipt.beneficiary_mismatch
    ? "fail"
    : receipt.beneficiary_checked
      ? "pass"
      : "unchecked";
  const replayState: CheckState = receipt.is_replayed
    ? "fail"
    : receipt.replay_checked
      ? "pass"
      : "unchecked";

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-800 bg-[#0b1120] px-3.5 py-2.5">
        <div className="text-xs">
          <span className="text-slate-400">Ngân hàng nhận diện: </span>
          <strong className="text-slate-100">{receipt.bank_detected ?? "Chưa xác định"}</strong>
          {receipt.reference_code && (
            <span className="ml-3 font-[family-name:var(--font-mono)] text-sky-300">
              Mã GD: {receipt.reference_code}
            </span>
          )}
        </div>
        <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] text-amber-200">
          Trạng thái: {receipt.verification_status} ({receipt.logic_risk_points} đ)
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <StatusRow
          state={refState}
          label="Cấu trúc Mã Giao dịch Ngân hàng"
          detail="Đối chiếu quy tắc sinh mã FT/MB/TCB/BIDV khi trích xuất được mã tham chiếu"
        />
        <StatusRow
          state={timestampState}
          label="Tính hợp lý Thời gian Giao dịch"
          detail="Kiểm tra ngày giờ tương lai hoặc sai định dạng lịch biểu khi đọc được thời gian"
        />
        <StatusRow
          state={amountState}
          label="Định dạng Dấu phân cách Tiền tệ VND"
          detail="Phát hiện lỗi ghép số tiền lẻ/dấu chấm phẩy sai quy chuẩn khi có trường số tiền"
        />
        <StatusRow
          state={geometryState}
          label="Hình học Dòng chữ Số tiền &amp; Tài khoản"
          detail="Đo phương sai chiều cao bounding-box OCR chống chèn chữ đè (cần >= 4 dòng chữ)"
        />
        <StatusRow
          state={beneficiaryState}
          label="Khớp Tài khoản Thụ hưởng Cửa hàng"
          detail="Chỉ xác nhận khi có STK chuẩn của chủ shop và đọc được STK nhận trên biên lai"
        />
        <StatusRow
          state={replayState}
          label="Chống Tái sử dụng Biên lai Cũ (Replay)"
          detail="Tra cứu dHash &amp; mã tham chiếu trên sổ cái khi có dấu vân tay biên lai"
        />
      </div>
    </div>
  );
}
