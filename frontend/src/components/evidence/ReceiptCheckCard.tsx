"use client";

import { AlertTriangle, CheckCircle2, MinusCircle, ShieldAlert } from "lucide-react";

import { maskDisplayIoc } from "@/lib/api";
import { RECEIPT_STATUS_COPY, SHARED_DISCLAIMERS } from "@/lib/copy";
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
          className={`shrink-0 rounded px-2 py-0.5 text-[10px] font-semibold ${
            state === "pass"
              ? "bg-emerald-500/15 text-emerald-300"
              : state === "fail"
                ? "bg-rose-500/15 text-rose-200"
                : "bg-surface-elevated text-ink-secondary"
          }`}
        >
          {state === "pass" ? "Bình thường" : state === "fail" ? "Có bất thường" : "Chưa đủ thông tin"}
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
            <strong className="text-amber-200">Lưu ý dành cho người bán: </strong>
            {merchantBalanceWarning ?? SHARED_DISCLAIMERS.merchantHonestyFallback}
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
              Mã giao dịch: {receipt.reference_code}
            </span>
          )}
          {receipt?.extracted_recipient_account && (
            <span className="tabular-num font-mono text-amber-300">
              Số tài khoản nhận: {maskDisplayIoc(receipt.extracted_recipient_account)}
            </span>
          )}
        </div>
        <span
          className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${
            isAlertStatus
              ? "border-rose-500/50 bg-rose-500/15 text-rose-200"
              : "border-amber-500/40 bg-amber-500/10 text-amber-200"
          }`}
        >
          {RECEIPT_STATUS_COPY[verificationStatus]}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
        <StatusRow
          state={elaExifState}
          label="Phân tích tính xác thực của hình ảnh"
          detail={
            imageForensics
              ? `Mức nghi vấn chỉnh sửa: ${imageForensics.tamper_score}/100${
                  imageForensics.editing_software_detected
                    ? " · Phát hiện dấu vết phần mềm chỉnh sửa ảnh"
                    : ""
                }`
              : "Chưa có hình ảnh biên lai đính kèm."
          }
        />
        <StatusRow
          state={refState}
          label="Cấu trúc mã giao dịch ngân hàng"
          detail="Đối chiếu định dạng mã giao dịch phổ biến của ngân hàng khi đọc được từ biên lai."
        />
        <StatusRow
          state={timestampState}
          label="Thời gian giao dịch"
          detail="Kiểm tra ngày giờ sai định dạng hoặc vượt quá thời điểm hiện tại."
        />
        <StatusRow
          state={amountState}
          label="Định dạng số tiền"
          detail="Phát hiện lỗi ghép số hoặc dấu phân cách tiền tệ không đúng chuẩn."
        />
        <StatusRow
          state={geometryState}
          label="Bố cục chữ số tiền và tài khoản"
          detail="Kiểm tra độ đồng đều của kích thước chữ để nhận diện dấu hiệu chèn đè số tiền."
        />
        <StatusRow
          state={beneficiaryState}
          label="Khớp số tài khoản nhận của cửa hàng"
          detail="Đối chiếu số tài khoản trên biên lai hoặc mã QR với số tài khoản cửa hàng đã nhập."
        />
        <StatusRow
          state={replayState}
          label="Kiểm tra biên lai bị dùng lại"
          detail="Kiểm tra xem ảnh biên lai hoặc mã giao dịch này đã từng xuất hiện trước đó hay chưa."
        />
      </div>

      {receipt && receipt.reasons.length > 0 && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-100">
          <p className="font-semibold text-rose-200">Các điểm bất thường được phát hiện:</p>
          <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[11px] leading-relaxed">
            {receipt.reasons.map((reason, idx) => (
              <li key={`rc-reason-${idx}`}>{reason}</li>
            ))}
          </ul>
        </div>
      )}

      <details className="rounded-xl border border-border-subtle bg-surface-subtle/70 px-3.5 py-2.5 text-[11px] text-ink-muted">
        <summary className="cursor-pointer font-medium text-ink-secondary hover:text-ink">
          Thông tin kỹ thuật đối chiếu biên lai
        </summary>
        <p className="mt-1.5 font-mono">
          Điểm rủi ro nghiệp vụ: {riskPoints} · ELA/EXIF:{" "}
          {imageForensics ? `${imageForensics.tamper_score}/100` : "Chưa có"}
          {imageForensics?.exif_software ? ` · EXIF: ${imageForensics.exif_software}` : ""}
        </p>
      </details>
    </div>
  );
}
