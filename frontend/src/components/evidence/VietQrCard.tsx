"use client";

import { AlertOctagon, CheckCircle2, Globe, QrCode } from "lucide-react";

import { formatVietQrAmount, maskDisplayIoc } from "@/lib/api";
import { QR_KIND_COPY } from "@/lib/copy";
import type { VietQRInfo } from "@/lib/types";

interface VietQrCardProps {
  items: VietQRInfo[];
}

export function VietQrCard({ items }: VietQrCardProps) {
  if (items.length === 0) {
    return (
      <p className="text-xs text-slate-400">Không tìm thấy mã QR nào trong ảnh đã tải lên.</p>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((qr, idx) => {
        const isVietQrFrame = qr.kind === "VALID_VIETQR" || qr.kind === "INVALID_CRC_VIETQR";
        const isStructurallyValid =
          qr.crc_valid && qr.tlv_valid !== false && qr.kind === "VALID_VIETQR";
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
                    ? `Mã chuyển khoản VietQR #${idx + 1}`
                    : qr.kind === "URL_QR"
                      ? `Mã QR dẫn tới trang web #${idx + 1}`
                      : `Mã QR chứa văn bản #${idx + 1}`}
                </span>
              </div>

              {isVietQrFrame ? (
                <span
                  className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-semibold ${
                    isStructurallyValid
                      ? "bg-emerald-500/15 text-emerald-300"
                      : "bg-rose-500/20 text-rose-200"
                  }`}
                >
                  {isStructurallyValid ? (
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <AlertOctagon className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  <span>{isStructurallyValid ? "Cấu trúc hợp lệ" : "Cấu trúc không hợp lệ"}</span>
                </span>
              ) : (
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300">
                  {QR_KIND_COPY[qr.kind]}
                </span>
              )}
            </div>

            {qr.receive_scam_detected && (
              <p className="mt-2.5 rounded-lg border border-rose-500/50 bg-rose-950/70 px-3 py-2 text-xs font-semibold text-rose-200">
                Cảnh báo bẫy quét mã QR: Mã VietQR chỉ dùng để chuyển tiền đi, không thể quét để
                nhận tiền hoàn hay nhận thưởng.
              </p>
            )}

            {qr.beneficiary_mismatch && (
              <p className="mt-2.5 rounded-lg border border-rose-500/50 bg-rose-950/70 px-3 py-2 text-xs font-semibold text-rose-200">
                Cảnh báo lệch tài khoản nhận: Số tài khoản trong mã QR không khớp với số tài khoản
                của cửa hàng. Hãy kiểm tra nguy cơ bị dán đè mã QR giả.
              </p>
            )}

            {isVietQrFrame ? (
              <div className="mt-3 space-y-2.5">
                <dl className="grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-3">
                  <div className="rounded-lg bg-slate-900/90 p-2.5">
                    <dt className="text-[11px] text-slate-400">Ngân hàng nhận</dt>
                    <dd className="mt-0.5 font-semibold text-slate-100">
                      {qr.bank_name ?? "Chưa xác định"}
                    </dd>
                  </div>
                  <div className="rounded-lg bg-slate-900/90 p-2.5">
                    <dt className="text-[11px] text-slate-400">Tài khoản nhận</dt>
                    <dd className="mt-0.5 font-mono font-semibold text-amber-300">
                      {qr.account_number ? maskDisplayIoc(qr.account_number) : "Chưa có"}
                    </dd>
                  </div>
                  <div className="rounded-lg bg-slate-900/90 p-2.5">
                    <dt className="text-[11px] text-slate-400">Số tiền ghi sẵn</dt>
                    <dd className="mt-0.5 font-mono font-semibold text-slate-100">
                      {formatVietQrAmount(qr.amount)}
                    </dd>
                  </div>
                </dl>
                {qr.note && (
                  <p className="rounded-lg bg-slate-900/90 px-3 py-2 text-xs text-slate-200">
                    <span className="text-slate-400">Nội dung chuyển khoản: </span>
                    <strong className="font-mono text-sky-300">{qr.note}</strong>
                  </p>
                )}
                <details className="rounded-lg bg-slate-900/70 px-3 py-2 text-[11px] text-slate-400">
                  <summary className="cursor-pointer font-medium text-slate-300 hover:text-slate-100">
                    Thông tin kỹ thuật mã QR
                  </summary>
                  <p className="mt-1.5 font-mono leading-relaxed">
                    Chuẩn: EMVCo / NAPAS VietQR · Mã BIN: {qr.bank_bin ?? "Chưa có"} · CRC-16:{" "}
                    {qr.crc_valid ? "Hợp lệ" : "Không hợp lệ"} · Cấu trúc TLV:{" "}
                    {qr.tlv_valid === false ? "Lỗi cấu trúc" : "Hợp lệ"}
                    {qr.service_code ? ` · Mã dịch vụ: ${qr.service_code}` : ""}
                  </p>
                </details>
              </div>
            ) : (
              <p className="mt-2.5 break-all rounded-lg bg-slate-900/90 p-2.5 font-mono text-xs text-slate-200">
                Nội dung mã QR: {qr.raw}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}
