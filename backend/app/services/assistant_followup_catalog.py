"""Static catalog, intent patterns, and concept rules for context-aware assistant follow-ups."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

MD_NOISE_RE: Final[re.Pattern[str]] = re.compile(r"[*_`#~>|]+")
PUNCT_RE: Final[re.Pattern[str]] = re.compile(r"[^\w\s]+")
WS_RE: Final[re.Pattern[str]] = re.compile(r"\s+")
PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?:xin\s+hoi|cho\s+(?:toi|minh|em|anh|chi)\s+hoi|ban\s+cho\s+hoi|"
    r"cho\s+hoi|hay\s+cho\s+biet|vui\s+long|lam\s+on|tu\s+van\s+giup|giup\s+(?:toi|minh)|"
    r"hay)\s+)+"
)
STOPWORDS: Final[frozenset[str]] = frozenset({
    "toi", "minh", "em", "anh", "chi", "ban", "ho", "nguoi", "nay", "do", "kia", "la", "va",
    "hoac", "hay", "thi", "da", "vua", "moi", "dang", "se", "roi", "chua", "khong", "co",
    "nen", "can", "phai", "duoc", "cho", "voi", "cua", "trong", "ngoai", "tren", "duoi",
    "de", "khi", "neu", "vi", "tai", "sao", "the", "nao", "gi", "nhu", "cach", "lam",
    "ngay", "luon", "bay", "gio", "them", "nua", "mot", "nhung", "cac", "nhieu", "it",
    "mat", "bi", "tu", "den", "ve", "vao", "ra", "o", "ma", "nha", "nhe", "a", "oi",
})

INTENT_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("merchant_handover", re.compile(
        r"\b(?:giao|dua)\s+hang\b|\bcho\s+khach\s+(?:lay|mang)\s+hang\b|"
        r"\b(?:bien\s+lai|bill|anh\s+chuyen\s+khoan).{0,25}\b(?:that|gia|giao\s+hang)\b"
    )),
    ("merchant_balance_verify", re.compile(
        r"\b(?:doi\s+chieu|kiem\s+tra|xac\s+minh).{0,30}\b(?:tien|so\s+du|soundbox|sao\s+ke)\b|"
        r"\b(?:so\s+du\s+thuc\s+te|loa\s+soundbox|tien\s+(?:da\s+)?(?:ve|vao)(?:\s+tai\s+khoan)?)\b"
    )),
    ("merchant_customer_pressure", re.compile(
        r"\b(?:hoi\s+thuc|giuc\s+giao|nghen\s+mang|bao\s+tri\s+ngan\s+hang|shipper\s+dang\s+doi)\b"
    )),
    ("merchant_qr_counter", re.compile(
        r"\b(?:bang\s+ma\s+qr|dan\s+de|trao\s+(?:ma\s+)?qr|qr\s+tai\s+quay|quay\s+thu\s+ngan)\b"
    )),
    ("explain_forensics", re.compile(
        r"\b(?:ela|exif|chinh\s+sua\s+anh|bat\s+thuong\s+(?:tren\s+)?bien\s+lai|anh\s+bi\s+sua)\b"
    )),
    ("explain_report_signals", re.compile(
        r"\b(?:giai\s+thich|tom\s+tat).{0,30}\b(?:ket\s+qua|ho\s+so|bao\s+cao|dau\s+hieu|rui\s+ro)\b|"
        r"\b(?:vi\s+sao|tai\s+sao).{0,30}\b(?:nguy\s+hiem|rui\s+ro|canh\s+bao|lua\s+dao)\b"
    )),
    ("incident_transferred_money", re.compile(
        r"\b(?:lo|da|vua|bi\s+lua)\s+(?:chuyen|nop)\s+(?:nham\s+)?(?:tien|khoan)\b|"
        r"\bchuyen\s+(?:tien|khoan)\s+(?:nham|roi|cho\s+ke\s+(?:gian|lua))\b|\b60\s+phut\b"
    )),
    ("incident_otp_password", re.compile(
        r"\b(?:lo|doc|cung\s+cap|chia\s+se|gui|nhap)\s+(?:ma\s+)?(?:xac\s+thuc\s+)?"
        r"(?:otp|smartotp|pin|cvv|cvc|mat\s+khau)\b|"
        r"\b(?:otp|smartotp|mat\s+khau|cvv).{0,25}\b(?:xu\s+ly|khoa\s+(?:tai\s+khoan|the))\b"
    )),
    ("incident_apk_malware", re.compile(
        r"\b(?:cai|tai|go)\s+(?:dat\s+)?(?:tep|file|app|ung\s+dung)?\s*\.?apk\b|"
        r"\b(?:chia\s+se\s+man\s+hinh|dieu\s+khien\s+tu\s+xa|quyen\s+tro\s+nang|ngat\s+mang)\b"
    )),
    ("incident_cccd_ekyc", re.compile(
        r"\b(?:cccd|cmnd|can\s+cuoc|video\s+khuon\s+mat|ekyc|tttb|1414)\b"
    )),
    ("incident_social_hijack", re.compile(
        r"\b(?:mat\s+nick|bi\s+hack|chiem\s+quyen)\s+(?:tai\s+khoan\s+)?(?:zalo|facebook|telegram)\b|"
        r"\b(?:tai\s+khoan\s+)?(?:zalo|facebook)\s+bi\s+(?:chiem|hack)\b"
    )),
    ("incident_preserve_evidence", re.compile(
        r"\b(?:luu|thu\s+thap|giu\s+lai|chuan\s+bi|sao\s+luu).{0,25}\b(?:bang\s+chung|chung\s+cu|giay\s+to)\b|"
        r"\b(?:bang\s+chung|chung\s+cu).{0,20}\b(?:trinh\s+bao|nop|cong\s+an)\b"
    )),
    ("incident_report_police", re.compile(
        r"\b(?:quy\s+trinh|cach|huong\s+dan).{0,25}\b(?:trinh\s+bao|to\s+giac|tra\s+soat)\b|"
        r"\b(?:trinh\s+bao\s+cong\s+an|cuc\s+a05|yeu\s+cau\s+ngan\s+hang\s+tra\s+soat|phong\s+toa\s+tai\s+khoan)\b"
    )),
    ("incident_recovery_scam", re.compile(
        r"\b(?:lay\s+lai\s+tien|thu\s+hoi\s+tien|lua\s+dao\s+lan\s+(?:2|hai)|dich\s+vu\s+hoan\s+tien)\b"
    )),
    ("verify_domain_url", re.compile(
        r"\b(?:ten\s+mien|duong\s+dan|duong\s+link|link\s+gia|website|trang\s+web|gov\s+vn|url)\b"
        r".{0,35}\b(?:that|gia|phan\s+biet|kiem\s+tra|nhan\s+biet|chinh\s+thuc|lua\s+dao)\b|"
        r"\b(?:phan\s+biet|kiem\s+tra|nhan\s+biet).{0,25}\b(?:ten\s+mien|duong\s+dan|duong\s+link|link|website|trang\s+web)\b"
    )),
    ("verify_vietqr_bin", re.compile(
        r"\b(?:vietqr|bin\s+napas|quet\s+(?:ma\s+)?qr|ma\s+qr.{0,20}(?:hoan\s+tien|kiem\s+tra|nguoi\s+nhan))\b"
    )),
    ("verify_safe_epistemic", re.compile(
        r"\b(?:rui\s+ro\s+thap|muc\s+an\s+toan).{0,25}\b(?:chac\s+chan|an\s+toan|khong)\b|"
        r"\bchac\s+chan\s+an\s+toan\b|\ban\s+toan\s+(?:tuyet\s+doi|100)\b"
    )),
    ("verify_official_channel", re.compile(
        r"\b(?:tu\s+kiem\s+chung|kiem\s+chung\s+them|xac\s+minh\s+them|kenh\s+chinh\s+thuc|"
        r"buoc\s+nao\s+truoc\s+khi\s+(?:chuyen|giao\s+dich))\b"
    )),
    ("scam_education", re.compile(
        r"\b(?:thu\s+doan|kich\s+ban\s+lua\s+dao|chieu\s+tro|hoat\s+dong\s+nhu\s+the\s+nao|"
        r"nhan\s+biet\s+som|doi\s+kich\s+ban)\b"
    )),
    ("active_call_handling", re.compile(
        r"\b(?:dang\s+(?:nghe|goi)\s+dien\s+thoai|bi\s+giuc\s+chuyen\s+tien|cup\s+may|co\s+lap)\b"
    )),
    ("family_protection", re.compile(
        r"\b(?:nguoi\s+than|gia\s+dinh|canh\s+bao\s+nguoi\s+nha|nguoi\s+lon\s+tuoi)\b"
    )),
)

CONCEPT_RULES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("c_receipt", re.compile(r"\b(?:bien\s+lai|bill|anh\s+chuyen\s+(?:khoan|tien))\b")),
    ("c_handover", re.compile(r"\b(?:giao\s+hang|dua\s+hang|lay\s+hang)\b")),
    ("c_balance", re.compile(r"\b(?:so\s+du|soundbox|sao\s+ke|tien\s+(?:da\s+)?(?:ve|vao))\b")),
    ("c_transfer", re.compile(r"\b(?:chuyen\s+tien|chuyen\s+khoan|nop\s+tien)\b")),
    ("c_incident", re.compile(r"\b(?:lo|nham|bi\s+lua|xu\s+ly|60\s+phut)\b")),
    ("c_otp", re.compile(r"\b(?:otp|smartotp|mat\s+khau|pin|cvv|cvc|xac\s+thuc)\b")),
    ("c_apk", re.compile(r"\b(?:apk|chia\s+se\s+man\s+hinh|dieu\s+khien\s+tu\s+xa|ma\s+doc)\b")),
    ("c_evidence", re.compile(r"\b(?:bang\s+chung|chung\s+cu|chup\s+man\s+hinh|giay\s+to)\b")),
    ("c_police", re.compile(r"\b(?:trinh\s+bao|to\s+giac|cong\s+an|a05|tra\s+soat|phong\s+toa)\b")),
    ("c_recovery", re.compile(r"\b(?:lay\s+lai\s+tien|thu\s+hoi\s+tien|lan\s+hai|lan\s+2)\b")),
    ("c_domain", re.compile(r"\b(?:ten\s+mien|duong\s+dan|duong\s+link|link|website|trang\s+web|url)\b")),
    ("c_vietqr", re.compile(r"\b(?:vietqr|ma\s+qr|bin\s+napas|nguoi\s+thu\s+huong)\b")),
    ("c_safety", re.compile(r"\b(?:rui\s+ro\s+thap|chac\s+chan\s+an\s+toan|an\s+toan\s+tuyet\s+doi)\b")),
    ("c_verify", re.compile(r"\b(?:kiem\s+chung|xac\s+minh|doi\s+chieu|kenh\s+chinh\s+thuc)\b")),
    ("c_explain", re.compile(r"\b(?:giai\s+thich|dau\s+hieu\s+rui\s+ro|ket\s+qua|ho\s+so|bao\s+cao)\b")),
    ("c_tactic", re.compile(r"\b(?:thu\s+doan|kich\s+ban|chieu\s+tro|nhan\s+biet)\b")),
    ("c_pressure", re.compile(r"\b(?:hoi\s+thuc|giuc|nghen\s+mang|bao\s+tri)\b")),
)


@dataclass(frozen=True, slots=True)
class FollowupItem:
    intent: str
    text: str
    profiles: frozenset[str]
    base_priority: int


CATALOG: Final[tuple[FollowupItem, ...]] = (
    FollowupItem(
        "merchant_handover",
        "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?",
        frozenset({"merchant"}), 100,
    ),
    FollowupItem(
        "merchant_balance_verify",
        "Cách đối chiếu biến động số dư thực tế và loa Soundbox?",
        frozenset({"merchant"}), 95,
    ),
    FollowupItem(
        "merchant_customer_pressure",
        "Khách hối thúc giao hàng vì lý do nghẽn mạng ngân hàng thì xử lý sao?",
        frozenset({"merchant"}), 88,
    ),
    FollowupItem(
        "merchant_qr_counter",
        "Làm sao kiểm tra bảng mã QR tại quầy có bị dán đè hay tráo không?",
        frozenset({"merchant"}), 82,
    ),
    FollowupItem(
        "explain_forensics",
        "Giải thích các dấu hiệu chỉnh sửa ảnh hoặc bất thường trên biên lai này?",
        frozenset({"merchant"}), 78,
    ),
    FollowupItem(
        "incident_preserve_evidence",
        "Cần thu thập và lưu những bằng chứng nào để trình báo Công an?",
        frozenset({"merchant", "high", "general"}), 74,
    ),
    FollowupItem(
        "scam_education",
        "Thủ đoạn lừa đảo liên quan hoạt động như thế nào và làm sao phòng tránh sớm?",
        frozenset({"merchant", "high", "low"}), 68,
    ),
    FollowupItem(
        "incident_transferred_money",
        "Tôi lỡ chuyển tiền rồi thì cần làm gì ngay trong 60 phút đầu?",
        frozenset({"high", "general"}), 98,
    ),
    FollowupItem(
        "incident_otp_password",
        "Tôi lỡ cung cấp mã OTP hoặc mật khẩu ngân hàng thì xử lý sao?",
        frozenset({"high", "general"}), 92,
    ),
    FollowupItem(
        "incident_apk_malware",
        "Tôi lỡ cài tệp .apk hoặc chia sẻ màn hình thì cần ngắt mạng và gỡ thế nào?",
        frozenset({"high", "general"}), 86,
    ),
    FollowupItem(
        "incident_report_police",
        "Quy trình trình báo Công an và yêu cầu ngân hàng tra soát như thế nào?",
        frozenset({"high", "general"}), 76,
    ),
    FollowupItem(
        "incident_recovery_scam",
        "Làm sao tránh bẫy dịch vụ lấy lại tiền bị lừa lần hai trên mạng?",
        frozenset({"high", "general"}), 70,
    ),
    FollowupItem(
        "active_call_handling",
        "Đang nghe điện thoại bị giục chuyển tiền gấp thì nên xử lý thế nào?",
        frozenset({"high"}), 64,
    ),
    FollowupItem(
        "family_protection",
        "Nên cảnh báo gì cho người thân để tránh mắc cùng kịch bản này?",
        frozenset({"high"}), 60,
    ),
    FollowupItem(
        "verify_safe_epistemic",
        "Kết quả rủi ro thấp có nghĩa là chắc chắn an toàn không?",
        frozenset({"low"}), 96,
    ),
    FollowupItem(
        "verify_official_channel",
        "Cần tự kiểm chứng thêm những bước nào qua kênh chính thức trước khi giao dịch?",
        frozenset({"low"}), 92,
    ),
    FollowupItem(
        "verify_domain_url",
        "Làm sao phân biệt tên miền ngân hàng thật và trang giả mạo?",
        frozenset({"low", "high", "general"}), 84,
    ),
    FollowupItem(
        "verify_vietqr_bin",
        "Cách kiểm tra mã VietQR và thông tin người thụ hưởng trước khi chuyển tiền?",
        frozenset({"low", "high", "general"}), 80,
    ),
    FollowupItem(
        "explain_report_signals",
        "Giải thích cụ thể các dấu hiệu rủi ro quan trọng nhất trong hồ sơ này?",
        frozenset({"high", "low"}), 72,
    ),
    FollowupItem(
        "incident_cccd_ekyc",
        "Lỡ gửi ảnh CCCD hoặc video khuôn mặt thì cần kiểm tra thuê bao (1414) thế nào?",
        frozenset(), 66,
    ),
    FollowupItem(
        "incident_social_hijack",
        "Tài khoản Zalo hoặc Facebook bị chiếm quyền thì cần cảnh báo và khôi phục ra sao?",
        frozenset(), 66,
    ),
)

NEXT_STEP_BOOSTS: Final[dict[str, tuple[str, ...]]] = {
    "incident_transferred_money": (
        "incident_preserve_evidence", "incident_report_police", "incident_recovery_scam",
    ),
    "incident_otp_password": (
        "incident_preserve_evidence", "incident_apk_malware", "incident_report_police",
    ),
    "incident_apk_malware": (
        "incident_otp_password", "incident_preserve_evidence", "verify_domain_url",
    ),
    "merchant_handover": (
        "merchant_balance_verify", "merchant_customer_pressure", "merchant_qr_counter",
    ),
    "merchant_balance_verify": (
        "merchant_customer_pressure", "explain_forensics", "incident_preserve_evidence",
    ),
    "explain_report_signals": (
        "incident_transferred_money", "verify_official_channel", "merchant_balance_verify",
    ),
    "verify_safe_epistemic": (
        "verify_official_channel", "verify_domain_url", "verify_vietqr_bin",
    ),
}
QUICK_INTENT_MAP: Final[dict[str, str]] = {
    "explain_report": "explain_report_signals",
    "scam_education": "scam_education",
}
