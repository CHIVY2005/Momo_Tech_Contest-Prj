"use client";

import { AlertTriangle, CheckCircle2, MinusCircle, ShieldAlert } from "lucide-react";

import { maskDisplayIoc } from "@/lib/api";
import type {
  ImageForensicsResult,
  ReceiptLogicResult,
  ReceiptVerificationStatus,
} from "@/lib/types";

interface ReceiptCheckCardProps {
  receipt?: ReceiptLogicResult | null;
  verificationStatus: ReceiptVerificationStatus;
  merchantBalanceWarning?: string | null;
  imageForensics?: ImageForensicsResult | null;
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
    <div className="flex flex-col justify-between gap-2 rounded-lg border border-border-subtle bg-surface-subtle px-3 py-2.5">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2">
          {state === "pass" ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
          ) : state === "fail" ? (
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
          ) : (
            <MinusCircle className="mt-0.5 h-4 w-4 shrink-0 text-ink-muted" aria-hidden="true" />
          )}
          <p className="text-xs font-semibold leading-snug text-ink">{label}</p>
        </div>
        <span
          className={`shrink-0 rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${
            state === "pass"
              ? "bg-emerald-500/15 text-emerald-300"
              : state === "fail"
                ? "bg-rose-500/15 text-rose-200"
                : "bg-surface-elevated text-ink-secondary"
          }`}
        >
          {state === "pass" ? "ỔN ĐỊNH" : state === "fail" ? "BẤT THƯỜNG" : "CHƯA ĐỐI CHIẾU"}
        </span>
      </div>
      <p className="pl-6 text-[11px] leading-relaxed text-ink-muted">{detail}</p>
    </div>
  );
}

export function ReceiptCheckCard({
  receipt,
  verificationStatus,
  merchantBalanceWarning,
  imageForensics,
}: ReceiptCheckCardProps) {
  const refState: CheckState = !receipt
    ? "unchecked"
    : !receipt.reference_valid
      ? "fail"
      : receipt.reference_code
        ? "pass"
        : "unchecked";
  const timestampState: CheckState = !receipt
    ? "unchecked"
    : receipt.timestamp_anomaly
      ? "fail"
      : receipt.timestamp_checked
        ? "pass"
        : "unchecked";
  const amountState: CheckState = !receipt
    ? "unchecked"
    : receipt.amount_format_anomaly
      ? "fail"
      : receipt.amount_checked
        ? "pass"
        : "unchecked";
  const geometryState: CheckState = !receipt
    ? "unchecked"
    : receipt.geometry_anomaly
      ? "fail"
      : receipt.geometry_checked
        ? "pass"
        : "unchecked";
  const beneficiaryState: CheckState = !receipt
    ? verificationStatus === "BENEFICIARY_MISMATCH"
      ? "fail"
      : "unchecked"
    : receipt.beneficiary_mismatch || verificationStatus === "BENEFICIARY_MISMATCH"
      ? "fail"
      : receipt.beneficiary_checked
        ? "pass"
        : "unchecked";
  const replayState: CheckState = !receipt
    ? "unchecked"
    : receipt.is_replayed
      ? "fail"
      : receipt.replay_checked
        ? "pass"
        : "unchecked";
  const elaExifState: CheckState = !imageForensics
    ? "unchecked"
    : imageForensics.tamper_score >= 35 || imageForensics.editing_software_detected
      ? "fail"
      : "pass";

  const isAlertStatus =
    verificationStatus === "TAMPER_OR_LOGIC_ANOMALY" ||
    verificationStatus === "BENEFICIARY_MISMATCH" ||
    verificationStatus === "REPLAYED_RECEIPT";
  const riskPoints = receipt?.logic_risk_points ?? 0;

  return (
    <div className="space-y-3">
      {(merchantBalanceWarning || verificationStatus !== "NOT_APPLICABLE") && (
        <div
          role="alert"
          className="flex items-start gap-2.5 rounded-xl border border-amber-500/50 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-100"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
          <p className="leading-relaxed">
            <strong className="text-amber-200">Rào chắn Trung thực Tiểu thương: </strong>
            {merchantBalanceWarning ??
              "Ảnh chụp biên lai không chứng minh tiền đã vào tài khoản. Luôn kiểm tra số dư ngân hàng thực tế hoặc Loa thông báo trước khi giao hàng."}
          </p>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border-subtle bg-surface-subtle px-3.5 py-2.5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <span>
            <span className="text-ink-muted">Ngân hàng nhận diện: </span>
            <strong className="text-ink">{receipt?.bank_detected ?? "Chưa xác định"}</strong>
          </span>
          {receipt?.reference_code && (
            <span className="tabular-num font-mono text-sky-300">
              Mã GD: {receipt.reference_code}
            </span>
          )}
          {receipt?.extracted_recipient_account && (
            <span className="tabular-num font-mono text-amber-300">
              STK nhận: {maskDisplayIoc(receipt.extracted_recipient_account)}
            </span>
          )}
        </div>
        <span
          className={`tabular-num rounded border px-2 py-0.5 font-mono text-[11px] font-semibold ${
            isAlertStatus
              ? "border-rose-500/50 bg-rose-500/15 text-rose-200"
              : "border-amber-500/40 bg-amber-500/10 text-amber-200"
          }`}
        >
          Trạng thái: {verificationStatus} ({riskPoints} đ)
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
        <StatusRow
          state={elaExifState}
          label="Pháp y Vật lý Ảnh (ELA & EXIF)"
          detail={
            imageForensics
              ? `Điểm ELA/EXIF: ${imageForensics.tamper_score}/100${
                  imageForensics.exif_software ? ` · Phần mềm: ${imageForensics.exif_software}` : ""
                }`
              : "Chưa có dữ liệu pháp y ảnh đính kèm"
          }
        />
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
          label="Hình học Dòng chữ Số tiền & Tài khoản"
          detail="Đo phương sai chiều cao bounding-box OCR chống chèn chữ đè (cần >= 4 dòng chữ)"
        />
        <StatusRow
          state={beneficiaryState}
          label="Khớp Tài khoản Thụ hưởng Cửa hàng"
          detail="Chỉ xác nhận khi có STK chuẩn của chủ shop và đọc được STK nhận trên biên lai/QR"
        />
        <StatusRow
          state={replayState}
          label="Chống Tái sử dụng Biên lai Cũ (Replay)"
          detail="Tra cứu dHash & mã tham chiếu trên sổ cái khi có dấu vân tay biên lai"
        />
      </div>

      {receipt && receipt.reasons.length > 0 && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-100">
          <p className="font-semibold text-rose-200">Lý do phát hiện bất thường biên lai:</p>
          <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[11px] leading-relaxed">
            {receipt.reasons.map((reason, idx) => (
              <li key={`rc-reason-${idx}`}>{reason}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
