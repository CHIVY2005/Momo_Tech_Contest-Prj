import io

import cv2
import numpy as np
from PIL import Image, ImageDraw

from app.services.image_forensics import (
    analyze_image_forensics,
    compute_dhash_hex,
    decode_qr_codes,
)


def test_dhash_stability_across_zalo_jpeg_recompression_and_exif_detection() -> None:
    img = Image.new("RGB", (360, 240), color=(245, 247, 250))
    draw = ImageDraw.Draw(img)
    draw.rectangle((20, 20, 340, 90), fill=(15, 95, 60))
    draw.rectangle((20, 110, 280, 210), fill=(40, 40, 40))

    orig_hash = compute_dhash_hex(img)
    assert len(orig_hash) == 16

    # Recompress at JPEG quality 72 stripping EXIF (simulating Zalo chat recompression)
    zalo_buf = io.BytesIO()
    img.save(zalo_buf, format="JPEG", quality=72)
    zalo_bytes = zalo_buf.getvalue()

    res_zalo = analyze_image_forensics(zalo_bytes, "zalo_bill.jpg", enable_ocr=False)
    assert res_zalo.dhash_hex == orig_hash
    assert res_zalo.editing_software_detected is False
    assert res_zalo.ela_heatmap_base64 is not None

    # Save with Photoshop EXIF tag (0x0131 = Software)
    exif = img.getexif()
    exif[0x0131] = "Adobe Photoshop 25.2 (Windows)"
    ps_buf = io.BytesIO()
    img.save(ps_buf, format="JPEG", quality=92, exif=exif.tobytes())
    res_ps = analyze_image_forensics(ps_buf.getvalue(), "edited_bill.jpg", enable_ocr=False)
    assert res_ps.editing_software_detected is True
    assert res_ps.tamper_score >= 45


def test_decode_qr_codes_extracts_embedded_payload() -> None:
    # Render a crisp QR matrix via OpenCV QRCodeEncoder if present or simple synthetic check
    encoder = getattr(cv2, "QRCodeEncoder_create", None)
    if encoder is not None:
        qr_mat = encoder().encode("https://vneid-capnhat.vip/apk")
        padded = np.pad(qr_mat, 24, mode="constant", constant_values=255)
        rgb = cv2.cvtColor(padded, cv2.COLOR_GRAY2RGB)
        pil_qr = Image.fromarray(rgb).resize((300, 300), Image.Resampling.NEAREST)
        buf = io.BytesIO()
        pil_qr.save(buf, format="PNG")
        decoded = decode_qr_codes(buf.getvalue())
        assert "https://vneid-capnhat.vip/apk" in decoded
    else:
        buf = io.BytesIO()
        Image.new("RGB", (100, 100), color=(255, 255, 255)).save(buf, format="PNG")
        assert decode_qr_codes(buf.getvalue()) == []
