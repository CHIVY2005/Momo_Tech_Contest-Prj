"""Physical image forensics: ELA JPEG 90% heatmap, EXIF/XMP signatures, dHash, and OpenCV QR."""

from __future__ import annotations

import base64
import io
from typing import Final

import cv2
import numpy as np
from PIL import Image, ImageChops, ImageOps

from app.schemas import ImageForensicsResult
from app.services.local_ocr import run_local_ocr

_EDITING_SIGNATURES: Final[tuple[str, ...]] = (
    "photoshop",
    "canva",
    "picsart",
    "photopea",
    "gimp",
    "snapseed",
    "lightroom",
    "illustrator",
    "figma",
    "paint.net",
)


def compute_dhash_hex(img: Image.Image) -> str:
    """Compute 64-bit difference perceptual hash (16 hex chars) resilient to Zalo JPEG compression."""
    normalized = ImageOps.exif_transpose(img).convert("L").resize(
        (9, 8),
        Image.Resampling.BILINEAR,
    )
    pixels = np.asarray(normalized, dtype=np.int16)
    diff_bits = (pixels[:, :-1] > pixels[:, 1:]).flatten()
    value = 0
    for bit in diff_bits:
        value = (value << 1) | int(bool(bit))
    return f"{value:016x}"


def decode_qr_codes(image_bytes: bytes) -> list[str]:
    """Decode single or multiple QR codes from raw image bytes using OpenCV."""
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if bgr is None:
        return []

    detector = cv2.QRCodeDetector()
    found: list[str] = []
    try:
        ok_multi, decoded_info, _, _ = detector.detectAndDecodeMulti(bgr)
        if ok_multi and decoded_info:
            for item in decoded_info:
                cleaned = str(item).strip()
                if cleaned and cleaned not in found:
                    found.append(cleaned)
    except cv2.error:
        pass

    if not found:
        try:
            single, _, _ = detector.detectAndDecode(bgr)
            cleaned_single = str(single).strip()
            if cleaned_single:
                found.append(cleaned_single)
        except cv2.error:
            pass
    return found


def _extract_editing_software(img: Image.Image, raw_bytes: bytes) -> tuple[str | None, bool]:
    software_val: str | None = None
    try:
        exif = img.getexif()
        if exif:
            raw_sw = exif.get(0x0131) or exif.get(0x013B)
            if raw_sw:
                software_val = str(raw_sw).strip()
    except Exception:
        software_val = None

    for key in ("Software", "Creator", "XML:com.adobe.xmp"):
        if not software_val and key in img.info:
            software_val = str(img.info[key])[:160].strip()

    lower_header = raw_bytes[:16384].decode("latin-1", errors="ignore").lower()
    combined = f"{software_val or ''} {lower_header}".lower()
    for sig in _EDITING_SIGNATURES:
        if sig in combined:
            return software_val or sig.title(), True
    return software_val, False


def _compute_ela_and_tamper_score(rgb_img: Image.Image) -> tuple[int, str, list[str]]:
    jpeg_buf = io.BytesIO()
    rgb_img.save(jpeg_buf, format="JPEG", quality=90)
    jpeg_buf.seek(0)
    with Image.open(jpeg_buf) as recompressed:
        diff_img = ImageChops.difference(rgb_img, recompressed.convert("RGB"))

    diff_arr = np.asarray(diff_img, dtype=np.float32)
    gray_err = np.mean(diff_arr, axis=2)

    # Measure localized block variance dispersion on a 16x16 grid
    h, w = gray_err.shape
    bh, bw = max(1, h // 16), max(1, w // 16)
    block_means: list[float] = []
    for r in range(0, h - bh + 1, bh):
        for c in range(0, w - bw + 1, bw):
            block_means.append(float(np.mean(gray_err[r : r + bh, c : c + bw])))

    reasons: list[str] = []
    tamper_score = 0
    if len(block_means) >= 16:
        b_arr = np.asarray(block_means, dtype=np.float32)
        p98 = float(np.percentile(b_arr, 98))
        median = float(np.median(b_arr))
        ratio = p98 / (median + 1.5)
        if ratio >= 6.5 and p98 >= 12.0:
            tamper_score = min(65, int(25 + (ratio - 6.5) * 8))
            reasons.append(
                f"Bản đồ nhiệt ELA phát hiện vùng nén lệch chuẩn cục bộ (tỷ lệ {ratio:.1f}x)."
            )

    scaled = np.clip(gray_err * 14.0, 0, 255).astype(np.uint8)
    heatmap_bgr = cv2.applyColorMap(scaled, cv2.COLORMAP_JET)
    heatmap_rgb = cv2.cvtColor(heatmap_bgr, cv2.COLOR_BGR2RGB)
    preview = Image.fromarray(heatmap_rgb)
    preview.thumbnail((560, 560))
    out_buf = io.BytesIO()
    preview.save(out_buf, format="PNG")
    heatmap_b64 = base64.b64encode(out_buf.getvalue()).decode("ascii")
    return tamper_score, heatmap_b64, reasons


def analyze_image_forensics(
    image_bytes: bytes,
    filename: str,
    enable_ocr: bool = True,
) -> ImageForensicsResult:
    """Execute physical Layer-1 forensics (ELA, EXIF/XMP, dHash, QR, and optional local OCR)."""
    with Image.open(io.BytesIO(image_bytes)) as opened:
        img_format = opened.format or "UNKNOWN"
        software_tag, editing_detected = _extract_editing_software(opened, image_bytes)
        dhash = compute_dhash_hex(opened)
        rgb = ImageOps.exif_transpose(opened).convert("RGB")
        width, height = rgb.size

    ela_score, ela_b64, reasons = _compute_ela_and_tamper_score(rgb)
    tamper_score = ela_score
    if editing_detected:
        tamper_score = max(tamper_score + 45, 55)
        reasons.insert(
            0,
            f"Phát hiện chữ ký phần mềm chỉnh sửa ảnh trong metadata ({software_tag}).",
        )

    qr_list = decode_qr_codes(image_bytes)
    ocr_res = run_local_ocr(image_bytes, enabled=enable_ocr)

    return ImageForensicsResult(
        filename=filename,
        format=img_format,
        width=width,
        height=height,
        dhash_hex=dhash,
        exif_software=software_tag,
        editing_software_detected=editing_detected,
        tamper_score=min(100, tamper_score),
        ela_heatmap_base64=ela_b64,
        qr_payloads=qr_list,
        ocr_text=ocr_res.full_text,
        ocr_height_cv=ocr_res.height_cv,
        reasons=reasons,
    )
