"""Physical image forensics: ELA JPEG 90% heatmap, EXIF/XMP signatures, dHash, and OpenCV QR."""

from __future__ import annotations

import base64
import contextlib
import io
from typing import Final

import cv2
import numpy as np
from numpy.typing import NDArray
from PIL import Image, ImageChops, ImageOps

from app.core.media_security import InvalidMediaError, decode_image_to_rgb_array
from app.schemas import ImageForensicsResult
from app.services.local_ocr import run_local_ocr

MAX_QR_DIMENSION: Final[int] = 2048
MAX_ELA_DIMENSION: Final[int] = 1600

_EDITING_LABELS: Final[dict[str, str]] = {
    "photoshop": "Photoshop", "canva": "Canva", "picsart": "PicsArt", "photopea": "Photopea",
    "gimp": "GIMP", "snapseed": "Snapseed", "lightroom": "Lightroom", "illustrator": "Illustrator",
    "figma": "Figma", "paint.net": "Paint.NET",
}
_EDITING_SIGNATURES: Final[tuple[str, ...]] = tuple(_EDITING_LABELS)


def _downscale_pil(img: Image.Image, max_dim: int) -> Image.Image:
    w, h = img.size
    if max(w, h) <= max_dim:
        return img
    scale = max_dim / float(max(w, h))
    new_size = (min(max_dim, max(1, round(w * scale))), min(max_dim, max(1, round(h * scale))))
    return img.resize(new_size, Image.Resampling.BILINEAR)


def _downscale_bgr(bgr: NDArray[np.uint8], max_dim: int) -> NDArray[np.uint8]:
    h, w = bgr.shape[:2]
    if max(h, w) <= max_dim:
        return bgr
    scale = max_dim / float(max(h, w))
    new_size = (min(max_dim, max(1, round(w * scale))), min(max_dim, max(1, round(h * scale))))
    return np.asarray(cv2.resize(bgr, new_size, interpolation=cv2.INTER_AREA), dtype=np.uint8)


def _compute_dhash_from_transposed(img: Image.Image) -> str:
    normalized = img.convert("L").resize((9, 8), Image.Resampling.BILINEAR)
    pixels = np.asarray(normalized, dtype=np.int16)
    diff_bits = (pixels[:, :-1] > pixels[:, 1:]).flatten()
    value = 0
    for bit in diff_bits:
        value = (value << 1) | int(bool(bit))
    return f"{value:016x}"


def compute_dhash_hex(img: Image.Image) -> str:
    """Compute 64-bit difference perceptual hash (16 hex chars) resilient to Zalo JPEG compression."""
    return _compute_dhash_from_transposed(ImageOps.exif_transpose(img))


def _decode_qr_from_bgr(bgr: NDArray[np.uint8]) -> list[str]:
    bounded = _downscale_bgr(bgr, MAX_QR_DIMENSION)
    detector = cv2.QRCodeDetector()
    found: list[str] = []
    try:
        ok_multi, decoded_info, _, _ = detector.detectAndDecodeMulti(bounded)
        if ok_multi and decoded_info:
            for item in decoded_info:
                cleaned = str(item).strip()
                if cleaned and cleaned not in found:
                    found.append(cleaned)
    except cv2.error:
        pass

    if not found:
        try:
            single, _, _ = detector.detectAndDecode(bounded)
            cleaned_single = str(single).strip()
            if cleaned_single:
                found.append(cleaned_single)
        except cv2.error:
            pass
    return found


def decode_qr_codes(image_bytes: bytes) -> list[str]:
    """Decode single or multiple QR codes from raw image bytes using OpenCV."""
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if bgr is None:
        try:
            rgb = decode_image_to_rgb_array(image_bytes)
            bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
        except (InvalidMediaError, cv2.error):
            return []
    return _decode_qr_from_bgr(np.asarray(bgr, dtype=np.uint8))


def _extract_editing_software(img: Image.Image, raw_bytes: bytes) -> tuple[str | None, bool]:
    chunks: list[str] = []
    with contextlib.suppress(Exception):
        exif = img.getexif()
        if exif:
            raw_sw = exif.get(0x0131)
            if raw_sw:
                chunks.append(str(raw_sw)[:256])

    for key, max_len in (
        ("Software", 256),
        ("Creator", 256),
        ("XML:com.adobe.xmp", 4096),
    ):
        if key in img.info and img.info[key] is not None:
            chunks.append(str(img.info[key])[:max_len])

    chunks.append(raw_bytes[:16384].decode("latin-1", errors="ignore"))
    combined = " ".join(chunks).lower()
    for sig in _EDITING_SIGNATURES:
        if sig in combined:
            return _EDITING_LABELS[sig], True
    return None, False


def _compute_ela_and_tamper_score(rgb_img: Image.Image) -> tuple[int, str, list[str]]:
    working = _downscale_pil(rgb_img, MAX_ELA_DIMENSION)
    jpeg_buf = io.BytesIO()
    working.save(jpeg_buf, format="JPEG", quality=90)
    jpeg_buf.seek(0)
    with Image.open(jpeg_buf) as recompressed:
        diff_img = ImageChops.difference(working, recompressed.convert("RGB"))

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
                "Phát hiện vùng ảnh có mức nén bất thường so với phần còn lại, gợi ý dấu hiệu chỉnh sửa."
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
        transposed = ImageOps.exif_transpose(opened)
        rgb = transposed if transposed.mode == "RGB" else transposed.convert("RGB")
        width, height = rgb.size

    dhash = _compute_dhash_from_transposed(rgb)
    qr_img = _downscale_pil(rgb, MAX_QR_DIMENSION)
    ela_img = _downscale_pil(rgb, MAX_ELA_DIMENSION)
    del rgb

    qr_bgr = np.asarray(
        cv2.cvtColor(np.asarray(qr_img, dtype=np.uint8), cv2.COLOR_RGB2BGR),
        dtype=np.uint8,
    )
    del qr_img
    qr_list = _decode_qr_from_bgr(qr_bgr)
    del qr_bgr

    ela_score, ela_b64, reasons = _compute_ela_and_tamper_score(ela_img)
    del ela_img
    tamper_score = ela_score
    if editing_detected:
        tamper_score = max(tamper_score + 45, 55)
        reasons.insert(
            0,
            f"Phát hiện dấu vết phần mềm chỉnh sửa ảnh trong thông tin tệp ({software_tag}).",
        )

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
