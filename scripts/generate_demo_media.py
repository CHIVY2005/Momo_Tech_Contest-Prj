"""Deterministic synthetic demo media generator (Fake Bill Zalo JPEG, VietQR PNG, Call WAV)."""

from __future__ import annotations

import io
import math
import struct
import sys
import wave
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.vietqr_parser import build_vietqr_test_payload  # noqa: E402


def generate_all_demo_media(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    ttf_path = REPO_ROOT / "backend" / "app" / "data" / "fonts" / "DejaVuSans.ttf"
    font_title = ImageFont.truetype(str(ttf_path), 24)
    font_amount = ImageFont.truetype(str(ttf_path), 30)
    font_body = ImageFont.truetype(str(ttf_path), 19)

    # 1. Synthetic Fake Bill recompressed like Zalo (JPEG quality 72, EXIF stripped)
    bill = Image.new("RGB", (540, 720), color=(246, 249, 252))
    draw = ImageDraw.Draw(bill)
    draw.rectangle((0, 0, 540, 110), fill=(12, 92, 56))
    draw.text((28, 38), "VIETCOMBANK DIGIBANK", fill=(255, 255, 255), font=font_title)
    draw.text((28, 138), "Giao dịch thành công", fill=(16, 110, 62), font=font_title)
    # Mixed currency separator + spliced amount look
    draw.text((28, 195), "Số tiền: 5,000.000 VND", fill=(15, 23, 42), font=font_amount)
    details = [
        "STK nhận: 190399998888",
        "Tên người nhận: CUA HANG DIEN THOAI MINH TAM",
        "Ngân hàng nhận: Techcombank",
        "Mã GD: FAKE12",
        "Thời gian: 31/12/2027 23:55:10",
        "Nội dung: thanh toan don hang gap shipper doi",
    ]
    y_pos = 275
    for line in details:
        draw.text((28, y_pos), line, fill=(30, 41, 59), font=font_body)
        y_pos += 52

    zalo_buf = io.BytesIO()
    bill.save(zalo_buf, format="JPEG", quality=72)
    (out_dir / "fake_bill_zalo.jpg").write_bytes(zalo_buf.getvalue())

    # 2. Synthetic Valid VietQR Push-Transfer Code used in "Scan to Receive Refund" scam
    qr_payload = build_vietqr_test_payload(
        bin_code="970422",
        account="777666555444",
        amount="1850000",
        note="HOAN TIEN DON 882",
    )
    encoder = cv2.QRCodeEncoder_create()
    qr_mat = encoder.encode(qr_payload)
    padded = np.pad(qr_mat, 20, mode="constant", constant_values=255)
    rgb_qr = cv2.cvtColor(padded, cv2.COLOR_GRAY2RGB)
    qr_img = Image.fromarray(rgb_qr).resize((380, 380), Image.Resampling.NEAREST)
    qr_img.save(out_dir / "vietqr_refund_trap.png", format="PNG")

    # 3. Synthetic Call Recording WAV (valid 16-bit PCM mono 8kHz)
    wav_buf = io.BytesIO()
    sr = 8000
    n_samples = int(sr * 0.6)
    with wave.open(wav_buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        frames = bytearray()
        for i in range(n_samples):
            env = 0.6 if (i // 800) % 2 == 0 else 0.15
            val = int(14000 * env * math.sin(2 * math.pi * 520 * i / sr))
            frames.extend(struct.pack("<h", val))
        wf.writeframes(bytes(frames))
    (out_dir / "scam_call_police.wav").write_bytes(wav_buf.getvalue())


if __name__ == "__main__":
    target = REPO_ROOT / "backend" / "app" / "data" / "demo_media"
    generate_all_demo_media(target)
    print(f"Generated synthetic demo media in {target}")
