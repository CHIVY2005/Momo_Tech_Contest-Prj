"use client";

import { AlertOctagon, CheckCircle2, Globe, QrCode } from "lucide-react";

import { maskDisplayIoc } from "@/lib/api";
import type { VietQRInfo } from "@/lib/types";

interface VietQrCardProps {
  items: VietQRInfo[];
}

export function VietQrCard({ items }: VietQrCardProps) {
  if (items.length === 0) {
    return (
      <p className="text-xs text-slate-400">Không phát hiện mã QR nào trong ảnh tải lên.</p>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((qr, idx) => {
        const isVietQrFrame = qr.kind === "VALID_VIETQR" || qr.kind === "INVALID_CRC_VIETQR";
        const hasTrap =
          qr.receive_scam_detected || qr.beneficiary_mismatch || qr.kind === "INVALID_CRC_VIETQR";

        return (
          <div
            key={`${qr.raw.slice(0, 24)}-${idx}`}
            className={`rounded-xl border p-4 ${
              hasTrap
                ? "border-rose-500/50 bg-rose-500/10"
                : "border-slate-800 bg-[#0b1120]"
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-100">
                {qr.kind === "URL_QR" ? (
                  <Globe className="h-4 w-4 text-sky-400" aria-hidden="true" />
                ) : (
                  <QrCode className="h-4 w-4 text-sky-400" aria-hidden="true" />
                )}
                <span>
                  {isVietQrFrame
                    ? `Giải mã Khung EMVCo / NAPAS VietQR #${idx + 1}`
                    : qr.kind === "URL_QR"
                      ? `Mã QR Đường dẫn Web (URL_QR) #${idx + 1}`
                      : `Mã QR Văn bản (TEXT_QR) #${idx + 1}`}
                </span>
              </div>

              {isVietQrFrame ? (
                <span
                  className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] font-semibold ${
                    qr.crc_valid
                      ? "bg-emerald-500/15 text-emerald-300"
                      : "bg-rose-500/20 text-rose-200"
                  }`}
                >
                  {qr.crc_valid ? (
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <AlertOctagon className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  <span>CRC-16/CCITT-FALSE: {qr.crc_valid ? "VALID" : "INVALID"}</span>
                </span>
              ) : (
                <span className="rounded bg-slate-800 px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] text-slate-300">
                  {qr.kind} (Không áp dụng CRC EMVCo)
                </span>
              )}
            </div>

            {qr.receive_scam_detected && (
              <p className="mt-2.5 rounded-lg border border-rose-500/50 bg-rose-950/70 px-3 py-2 text-xs font-semibold text-rose-200">
                BẪY LỪA QUÉT VIETQR: Mã VietQR thực chất là LỆNH CHUYỂN TIỀN ĐI từ ví của bạn sang tài
                khoản kẻ gian — tuyệt đối không có chức năng &ldquo;quét QR để nhận tiền hoàn&rdquo;!
              </p>
            )}

            {isVietQrFrame ? (
              <dl className="mt-3 grid grid-cols-2 gap-2.5 text-xs sm:grid-cols-4">
                <div className="rounded-lg bg-slate-900/90 p-2.5">
                  <dt className="text-[11px] text-slate-400">Ngân hàng / BIN</dt>
                  <dd className="mt-0.5 font-semibold text-slate-100">
                    {qr.bank_name ?? "Không rõ"} {qr.bank_bin ? `(${qr.bank_bin})` : ""}
                  </dd>
                </div>
                <div className="rounded-lg bg-slate-900/90 p-2.5">
                  <dt className="text-[11px] text-slate-400">Tài khoản Thụ hưởng</dt>
                  <dd className="mt-0.5 font-[family-name:var(--font-mono)] font-semibold text-amber-300">
                    {qr.account_number ? maskDisplayIoc(qr.account_number) : "N/A"}
                  </dd>
                </div>
                <div className="rounded-lg bg-slate-900/90 p-2.5">
                  <dt className="text-[11px] text-slate-400">Số tiền Ấn định sẵn</dt>
                  <dd className="mt-0.5 font-[family-name:var(--font-mono)] font-semibold text-slate-100">
                    {qr.amount ? `${Number(qr.amount).toLocaleString("vi-VN")} VND` : "QR tĩnh / Tự nhập"}
                  </dd>
                </div>
                <div className="rounded-lg bg-slate-900/90 p-2.5">
                  <dt className="text-[11px] text-slate-400">Mã Dịch vụ NAPAS</dt>
                  <dd className="mt-0.5 font-[family-name:var(--font-mono)] text-slate-200">
                    {qr.service_code ?? qr.kind}
                  </dd>
                </div>
              </dl>
            ) : (
              <p className="mt-2.5 break-all rounded-lg bg-slate-900/90 p-2.5 font-[family-name:var(--font-mono)] text-xs text-slate-200">
                Nội dung QR: {qr.raw}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}
