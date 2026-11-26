"""Generate 25 deterministic, 100% synthetic Vietnamese OCR benchmark images (zero real PII)."""

from __future__ import annotations

import io
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

FONT_PATH = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "app"
    / "data"
    / "fonts"
    / "DejaVuSans.ttf"
)
DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "dataset"


@dataclass(frozen=True)
class BenchmarkSample:
    sample_id: str
    category: str
    filename: str
    ground_truth_text: str
    entities: dict[str, list[str]]
    expected_is_scam: bool
    expected_is_receipt: bool


def _font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_PATH), size=size)


def _draw_card(
    lines: list[tuple[str, int, tuple[int, int, int]]],
    *,
    bg: tuple[int, int, int] = (248, 250, 252),
    header_bg: tuple[int, int, int] | None = None,
    width: int = 780,
    padding: int = 28,
    line_gap: int = 16,
    qr_payload: str | None = None,
) -> Image.Image:
    y = padding
    line_heights: list[int] = []
    for _txt, fsize, _col in lines:
        line_heights.append(int(fsize * 1.45) + line_gap)
    extra_qr = 250 if qr_payload else 0
    total_h = max(320, padding * 2 + sum(line_heights) + extra_qr)

    img = Image.new("RGB", (width, total_h), color=bg)
    draw = ImageDraw.Draw(img)

    if header_bg is not None and lines:
        hdr_h = line_heights[0] + padding + 6
        draw.rectangle((0, 0, width, hdr_h), fill=header_bg)

    for idx, (txt, fsize, col) in enumerate(lines):
        draw.text((padding, y), txt, font=_font(fsize), fill=col)
        y += line_heights[idx]

    if qr_payload:
        encoder = getattr(cv2, "QRCodeEncoder_create", None)
        if encoder is not None:
            qr_mat = encoder().encode(qr_payload)
            padded = np.pad(qr_mat, 16, mode="constant", constant_values=255)
            rgb = cv2.cvtColor(padded, cv2.COLOR_GRAY2RGB)
            qr_pil = Image.fromarray(rgb).resize((210, 210), Image.Resampling.NEAREST)
            img.paste(qr_pil, ((width - 210) // 2, y + 8))
    return img


def _degrade_low_quality(
    img: Image.Image,
    *,
    seed: int,
    quality: int = 34,
    angle: float = 1.8,
) -> Image.Image:
    rng = random.Random(seed)  # noqa: S311
    w, h = img.size
    small = img.resize((int(w * 0.72), int(h * 0.72)), Image.Resampling.BILINEAR)
    restored = small.resize((w, h), Image.Resampling.BILINEAR)
    blurred = restored.filter(ImageFilter.GaussianBlur(radius=0.65))
    rotated = blurred.rotate(
        angle,
        resample=Image.Resampling.BICUBIC,
        expand=False,
        fillcolor=(235, 238, 242),
    )

    arr = np.asarray(rotated, dtype=np.int16)
    noise = np.asarray(
        [
            [[rng.randint(-8, 8) for _ in range(3)] for _ in range(arr.shape[1])]
            for _ in range(arr.shape[0])
        ],
        dtype=np.int16,
    )
    noisy = np.clip(arr + noise, 0, 255).astype(np.uint8)
    out_pil = Image.fromarray(noisy)
    buf = io.BytesIO()
    out_pil.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    return Image.open(buf).convert("RGB")


def build_synthetic_dataset(out_dir: Path = DEFAULT_OUT_DIR) -> list[BenchmarkSample]:
    """Create 25 synthetic Vietnamese benchmark images + manifest.json (100% synthetic, zero PII)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    samples: list[BenchmarkSample] = []

    def _save(
        sample_id: str,
        category: str,
        img: Image.Image,
        lines: list[str],
        entities: dict[str, list[str]],
        expected_is_scam: bool,
        expected_is_receipt: bool,
        ext: str = "png",
    ) -> None:
        fname = f"{sample_id}.{ext}"
        target = out_dir / fname
        if ext == "jpg":
            img.save(target, format="JPEG", quality=85)
        else:
            img.save(target, format="PNG")
        samples.append(
            BenchmarkSample(
                sample_id=sample_id,
                category=category,
                filename=fname,
                ground_truth_text="\n".join(lines),
                entities=entities,
                expected_is_scam=expected_is_scam,
                expected_is_receipt=expected_is_receipt,
            )
        )

    # 1. Category: chat_sms (5 samples)
    chat_specs: list[tuple[str, list[str], dict[str, list[str]], bool]] = [
        (
            "chat_01_napas_phish",
            [
                "TIN NHẮN SMS - NAPAS",
                "Điểm thưởng thẻ của Quý khách sắp hết hạn lúc 23:59 hôm nay.",
                "Truy cập https://napas-diemthuong-01.top/verify để đổi 1.250.000 đ.",
                "Liên hệ hỗ trợ: 0981000101",
            ],
            {
                "urls": ["https://napas-diemthuong-01.top/verify"],
                "phones": ["0981000101"],
                "bank_accounts": [],
                "amounts": ["1250000"],
                "ref_codes": [],
            },
            True,
        ),
        (
            "chat_02_police_extortion",
            [
                "Cán bộ điều tra yêu cầu giữ bí mật tuyệt đối cuộc gọi này.",
                "Chuyển ngay 15.000.000 VND vào STK tạm giữ: 190300011122",
                "Ngân hàng Techcombank để xác minh nguồn tiền trong sạch.",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190300011122"],
                "amounts": ["15000000"],
                "ref_codes": [],
            },
            True,
        ),
        (
            "chat_03_vneid_apk",
            [
                "THÔNG BÁO CẬP NHẬT ĐỊNH DANH MỨC 2",
                "Tải ứng dụng tại https://vneid-capnhat-02.vip/dichvucong.apk",
                "Gọi ngay cán bộ phụ trách 0912000202 để được hướng dẫn.",
            ],
            {
                "urls": ["https://vneid-capnhat-02.vip/dichvucong.apk"],
                "phones": ["0912000202"],
                "bank_accounts": [],
                "amounts": [],
                "ref_codes": [],
            },
            True,
        ),
        (
            "chat_04_job_task_scam",
            [
                "Tuyển cộng tác viên chốt đơn Shopee hoa hồng 20% mỗi ngày.",
                "Nạp 2.500.000 đ vào tài khoản nhận: 102900033344 để mở nhiệm vụ VIP.",
                "Đăng ký tại https://shopee-nhiemvu-03.xyz/login",
            ],
            {
                "urls": ["https://shopee-nhiemvu-03.xyz/login"],
                "phones": [],
                "bank_accounts": ["102900033344"],
                "amounts": ["2500000"],
                "ref_codes": [],
            },
            True,
        ),
        (
            "chat_05_safe_advisory",
            [
                "KHUYẾN CÁO AN TOÀN TỪ VIETCOMBANK",
                "Ngân hàng KHÔNG BAO GIỜ yêu cầu cung cấp mã OTP hay mật khẩu.",
                "Không bấm vào đường link lạ hoặc cài đặt tệp .apk ngoài kho ứng dụng.",
                "Xem hướng dẫn chính thức tại https://vietcombank.com.vn",
            ],
            {
                "urls": ["https://vietcombank.com.vn"],
                "phones": [],
                "bank_accounts": [],
                "amounts": [],
                "ref_codes": [],
            },
            False,
        ),
    ]
    for sid, lines, ents, is_scam in chat_specs:
        styled = [(lines[0], 22, (255, 255, 255))] + [(ln, 20, (15, 23, 42)) for ln in lines[1:]]
        img = _draw_card(styled, bg=(248, 250, 252), header_bg=(15, 23, 42))
        _save(sid, "chat_sms", img, lines, ents, is_scam, False)

    # 2. Category: bank_receipt (5 samples)
    receipt_specs: list[tuple[str, tuple[int, int, int], list[str], dict[str, list[str]], bool]] = [
        (
            "receipt_01_vcb_fake",
            (10, 102, 64),
            [
                "VIETCOMBANK DIGIBANK",
                "Giao dịch thành công",
                "Số tiền: 5,000.000 VND",
                "STK nhận: 190300099988",
                "Ngân hàng nhận: Techcombank",
                "Mã GD: FAKE12",
                "Thời gian: 31/12/2027 23:55:10",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190300099988"],
                "amounts": ["5000000"],
                "ref_codes": ["FAKE12"],
            },
            True,
        ),
        (
            "receipt_02_tcb_valid",
            (185, 28, 28),
            [
                "TECHCOMBANK MOBILE",
                "Chuyển khoản thành công",
                "Số tiền: 1.450.000 VND",
                "Tài khoản nhận: 190311112222",
                "Ngân hàng nhận: Vietcombank",
                "Mã giao dịch: FT263301122334",
                "Thời gian: 26/11/2026 14:20",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190311112222"],
                "amounts": ["1450000"],
                "ref_codes": ["FT263301122334"],
            },
            False,
        ),
        (
            "receipt_03_mb_valid",
            (29, 78, 216),
            [
                "MB BANK",
                "Chuyển tiền thành công",
                "Số tiền: 3.200.000 VND",
                "STK nhận: 0001122334455",
                "Mã GD: FT263309988776",
                "Thời gian: 26/11/2026 15:10",
                "Nội dung: Thanh toán đơn hàng 882",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["0001122334455"],
                "amounts": ["3200000"],
                "ref_codes": ["FT263309988776"],
            },
            False,
        ),
        (
            "receipt_04_bidv_english",
            (0, 102, 102),
            [
                "BIDV SmartBanking",
                "Transfer Successful",
                "Amount: 2,800,000 VND",
                "Beneficiary Account: 2151000445566",
                "Transaction ID: FT263305544332",
                "Time: 26/11/2026 16:05",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["2151000445566"],
                "amounts": ["2800000"],
                "ref_codes": ["FT263305544332"],
            },
            False,
        ),
        (
            "receipt_05_acb_fake_sep",
            (30, 64, 175),
            [
                "ACB ONE",
                "Giao dịch thành công",
                "Số tiền: 8.500,000 VND",
                "STK nhận: 888900077766",
                "Số tham chiếu: FAKE99",
                "Thời gian: 26/11/2026 17:45",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["888900077766"],
                "amounts": ["8500000"],
                "ref_codes": ["FAKE99"],
            },
            True,
        ),
    ]
    for sid, hdr_col, lines, ents, is_scam in receipt_specs:
        styled = [(lines[0], 24, (255, 255, 255))] + [(ln, 20, (17, 24, 39)) for ln in lines[1:]]
        img = _draw_card(styled, bg=(255, 255, 255), header_bg=hdr_col)
        _save(sid, "bank_receipt", img, lines, ents, is_scam, True)

    # 3. Category: vietqr (5 samples)
    qr_specs: list[tuple[str, list[str], str, dict[str, list[str]], bool]] = [
        (
            "qr_01_refund_trap",
            [
                "MÃ QR HOÀN TIỀN ĐƠN HÀNG #882",
                "Quét mã VietQR bên dưới để nhận hoàn tiền 1.850.000 VND",
                "Tài khoản thụ hưởng: 190300088877",
            ],
            "https://hoantien-shopee-01.top/qr",
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190300088877"],
                "amounts": ["1850000"],
                "ref_codes": [],
            },
            True,
        ),
        (
            "qr_02_merchant_counter",
            [
                "QUÉT MÃ VIETQR THANH TOÁN",
                "Cửa hàng Cà Phê Phố Cổ",
                "Ngân hàng Vietcombank - STK nhận: 190311112222",
            ],
            "00020101021138570010A0000007270127000697043601121903111122220208QRIBFTTA53037045802VN63041A2B",
            {"urls": [], "phones": [], "bank_accounts": ["190311112222"], "amounts": [], "ref_codes": []},
            False,
        ),
        (
            "qr_03_tax_qr_phish",
            [
                "CỤC THUẾ - HỖ TRỢ QUYẾT TOÁN",
                "Quét mã QR hoặc truy cập https://thue-hotro-03.top/etax",
                "Hotline hỗ trợ: 0973000303",
            ],
            "https://thue-hotro-03.top/etax",
            {
                "urls": ["https://thue-hotro-03.top/etax"],
                "phones": ["0973000303"],
                "bank_accounts": [],
                "amounts": [],
                "ref_codes": [],
            },
            True,
        ),
        (
            "qr_04_evn_bill_qr",
            [
                "THÔNG BÁO CẮT ĐIỆN KHẨN CẤP",
                "Nợ cước 1.680.000 VND sẽ bị cắt điện sau 2 giờ.",
                "Chuyển vào STK: 038900055566 hoặc quét mã QR bên dưới.",
            ],
            "https://evn-thanhtoan-04.vip/pay",
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["038900055566"],
                "amounts": ["1680000"],
                "ref_codes": [],
            },
            True,
        ),
        (
            "qr_05_safe_cafe",
            [
                "VIETQR - NAPAS 247",
                "Thanh toán hóa đơn 125.000 VND",
                "Tài khoản nhận: 190311112222",
            ],
            "https://vietcombank.com.vn",
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190311112222"],
                "amounts": ["125000"],
                "ref_codes": [],
            },
            False,
        ),
    ]
    for sid, lines, payload, ents, is_scam in qr_specs:
        styled = [(lines[0], 22, (255, 255, 255))] + [(ln, 19, (15, 23, 42)) for ln in lines[1:]]
        img = _draw_card(styled, bg=(248, 250, 252), header_bg=(14, 116, 144), qr_payload=payload)
        _save(sid, "vietqr", img, lines, ents, is_scam, False)

    # 4. Category: dark_mode (5 samples)
    dark_specs: list[tuple[str, list[str], dict[str, list[str]], bool, bool]] = [
        (
            "dark_01_zalo_borrow",
            [
                "Zalo - Bạn thân (Chế độ tối)",
                "Ê đang kẹt tiền gấp quá, chuyển giúp mình 4.500.000 VND nhé!",
                "Gửi vào STK: 109800044455 ngân hàng MB Bank, lát 5h mình trả.",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["109800044455"],
                "amounts": ["4500000"],
                "ref_codes": [],
            },
            True,
            False,
        ),
        (
            "dark_02_receipt_dark",
            [
                "TECHCOMBANK - GIAO DỊCH THÀNH CÔNG",
                "Số tiền: 6.200.000 VND",
                "STK nhận: 190300066677",
                "Mã GD: FT263307788990",
                "Thời gian: 26/11/2026 19:30",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190300066677"],
                "amounts": ["6200000"],
                "ref_codes": ["FT263307788990"],
            },
            False,
            True,
        ),
        (
            "dark_03_sms_bank_phish",
            [
                "Cảnh báo bảo mật tài khoản Vietcombank",
                "Tài khoản của bạn bị tạm khóa do đăng nhập bất thường.",
                "Xác thực ngay tại https://vcb-xacthuc-05.top/otp trong 15 phút.",
            ],
            {
                "urls": ["https://vcb-xacthuc-05.top/otp"],
                "phones": [],
                "bank_accounts": [],
                "amounts": [],
                "ref_codes": [],
            },
            True,
            False,
        ),
        (
            "dark_04_invest_group",
            [
                "NHÓM ĐẦU TƯ CHỨNG KHOÁN NỘI BỘ",
                "Cam kết lợi nhuận 35% mỗi tuần, rút vốn bất cứ lúc nào.",
                "Liên hệ trợ lý 0934000404 hoặc https://dautu-vip-06.xyz",
            ],
            {
                "urls": ["https://dautu-vip-06.xyz"],
                "phones": ["0934000404"],
                "bank_accounts": [],
                "amounts": [],
                "ref_codes": [],
            },
            True,
            False,
        ),
        (
            "dark_05_safe_chat",
            [
                "Nhóm gia đình",
                "Cuối tuần này cả nhà về quê ăn giỗ nhé mọi người.",
                "Chiều thứ Bảy 15h xuất phát, nhớ mang theo áo khoác ấm.",
            ],
            {"urls": [], "phones": [], "bank_accounts": [], "amounts": [], "ref_codes": []},
            False,
            False,
        ),
    ]
    for sid, lines, ents, is_scam, is_rcpt in dark_specs:
        styled = [(lines[0], 22, (251, 191, 36))] + [(ln, 20, (241, 245, 249)) for ln in lines[1:]]
        img = _draw_card(styled, bg=(15, 23, 42), header_bg=(30, 41, 59))
        _save(sid, "dark_mode", img, lines, ents, is_scam, is_rcpt)

    # 5. Category: low_quality (5 samples — Zalo recompression, blur, noise, slight tilt)
    lq_specs: list[tuple[str, list[str], dict[str, list[str]], bool, bool, int, float]] = [
        (
            "lq_01_zalo_bill_blur",
            [
                "VIETCOMBANK DIGIBANK",
                "Chuyển khoản thành công",
                "Số tiền: 7,500.000 VND",
                "STK nhận: 190300022211",
                "Mã giao dịch: FAKE77",
                "Thời gian: 26/11/2026 20:15",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190300022211"],
                "amounts": ["7500000"],
                "ref_codes": ["FAKE77"],
            },
            True,
            True,
            101,
            1.6,
        ),
        (
            "lq_02_compressed_sms",
            [
                "THÔNG BÁO GIAO HÀNG KHÔNG THÀNH CÔNG",
                "Vui lòng cập nhật địa chỉ tại https://vnpost-giaohang-07.top/track",
                "Tổng đài hỗ trợ: 0965000505",
            ],
            {
                "urls": ["https://vnpost-giaohang-07.top/track"],
                "phones": ["0965000505"],
                "bank_accounts": [],
                "amounts": [],
                "ref_codes": [],
            },
            True,
            False,
            102,
            -1.4,
        ),
        (
            "lq_03_police_warrant",
            [
                "GIẤY TRIỆU TẬP KHẨN CẤP",
                "Yêu cầu chuyển 20.000.000 VND vào STK tạm giữ: 190300033355",
                "Tuyệt đối giữ bí mật với gia đình và ngân hàng.",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["190300033355"],
                "amounts": ["20000000"],
                "ref_codes": [],
            },
            True,
            False,
            103,
            2.0,
        ),
        (
            "lq_04_receipt_mb_compressed",
            [
                "MB BANK",
                "Giao dịch thành công",
                "Số tiền: 950.000 VND",
                "STK nhận: 0001999888777",
                "Mã GD: FT263304455667",
                "Thời gian: 26/11/2026 11:05",
            ],
            {
                "urls": [],
                "phones": [],
                "bank_accounts": ["0001999888777"],
                "amounts": ["950000"],
                "ref_codes": ["FT263304455667"],
            },
            False,
            True,
            104,
            -1.8,
        ),
        (
            "lq_05_safe_notice_compressed",
            [
                "THÔNG BÁO LỊCH HỌP PHÒNG KỸ THUẬT",
                "Thứ Hai tuần sau họp lúc 9h00 tại phòng họp tầng 4.",
                "Mọi người chuẩn bị báo cáo tiến độ trước giờ họp nhé.",
            ],
            {"urls": [], "phones": [], "bank_accounts": [], "amounts": [], "ref_codes": []},
            False,
            False,
            105,
            1.2,
        ),
    ]
    for sid, lines, ents, is_scam, is_rcpt, seed, angle in lq_specs:
        styled = [(lines[0], 22, (255, 255, 255))] + [(ln, 20, (15, 23, 42)) for ln in lines[1:]]
        raw_img = _draw_card(styled, bg=(248, 250, 252), header_bg=(30, 58, 138))
        degraded = _degrade_low_quality(raw_img, seed=seed, quality=32, angle=angle)
        _save(sid, "low_quality", degraded, lines, ents, is_scam, is_rcpt, ext="jpg")

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps([asdict(s) for s in samples], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return samples


if __name__ == "__main__":
    generated = build_synthetic_dataset()
    print(f"Generated {len(generated)} synthetic Vietnamese OCR benchmark images in {DEFAULT_OUT_DIR}")
