"""Compiled regex constants and lexical tables for VeriShield Assistant output guardrails."""

from __future__ import annotations

import re
from typing import Final, Literal

OutputTier = Literal[0, 1, 2]
MAX_TIER2_SENTENCE_CHARS: Final[int] = 160
MERCHANT_BALANCE_WARNING_VI: Final[str] = (
    "Ảnh chụp biên lai không phải bằng chứng tiền đã vào tài khoản. Bạn bắt buộc phải kiểm tra số dư "
    "thực tế trên ứng dụng ngân hàng hoặc loa thông báo biến động số dư (Soundbox) trước khi giao hàng."
)
MERCHANT_SAFE_FALLBACK_SUMMARY_VI: Final[str] = (
    "Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp — hãy kiểm tra trực tiếp biến động "
    "số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền trước khi giao hàng."
)
TIER0_ACTION_LINE_VI: Final[str] = (
    "- **Hành động bắt buộc:** Không giao hàng chỉ dựa trên ảnh chụp; hãy mở ứng dụng ngân "
    "hàng chính thức hoặc kiểm tra loa thông báo Soundbox để xác nhận biến động số dư thực tế."
)
DEGRADED_SAFE_BODY_VI: Final[str] = (
    "Hệ thống chưa phát hiện dấu hiệu rủi ro rõ ràng, nhưng không đảm bảo an toàn "
    "tuyệt đối — hãy tự xác minh qua kênh chính thức."
)
DEGRADED_GENERIC_TAIL_VI: Final[str] = (
    "Hệ thống không thể khẳng định an toàn tuyệt đối. Hãy tự xác minh qua ứng dụng ngân "
    "hàng chính thức, tổng đài in mặt sau thẻ hoặc Công an địa phương (113 khi khẩn cấp)."
)
FAIL_CLOSED_MSG_VI: Final[str] = "Phản hồi đã được kiểm duyệt và chuyển sang hướng dẫn an toàn."
RECEIPT_STATUSES: Final[frozenset[str]] = frozenset({
    "UNVERIFIED_SCREENSHOT",
    "SUSPECTED_FAKE_RECEIPT",
    "TAMPER_OR_LOGIC_ANOMALY",
    "REPLAYED_RECEIPT",
    "BENEFICIARY_MISMATCH",
})

_C = re.compile
_S: Final[str] = r"[\s.\-/\u2013\u2014]{0,3}"

THINK_OPEN_RE: Final[re.Pattern[str]] = _C(r"<think(?:\s[^>]*)?>")
THINK_CLOSE_RE: Final[re.Pattern[str]] = _C(r"</think\s*>")
PARTIAL_THINK_RE: Final[re.Pattern[str]] = _C(r"</?(?:t(?:h(?:i(?:n(?:k(?:\s[^<]{0,56})?)?)?)?)?)?$")

TIER0_RE: Final[re.Pattern[str]] = _C(
    r"(?:(?:tien (?:da )?(?:ve|vao)(?: tai khoan)?|(?:khach(?: hang)? )?(?:da )?chuyen "
    r"(?:tien|khoan)(?: that| thanh cong)?|da nhan(?: duoc| du)? tien) (?:chua|khong|chac chua)|"
    r"(?:co (?:nen|the) )?(?:giao|dua) hang\b.{0,45}\b(?:duoc chua|chua|khong)\b|cho khach (?:lay|mang)"
    r" hang\b.{0,25}\b(?:chua|khong)\b|(?:bien lai|bill|anh (?:chuyen khoan|bien lai|bill))(?: nay)? "
    r"(?:co )?(?:phai )?(?:that|gia|uy tin)(?: hay (?:gia|that))? *(?:khong|chua|\?|$)|(?:chac chan|"
    r"dam bao|hoan toan) an toan *(?:chua|khong|\?|$)|xac nhan (?:tien (?:da )?(?:ve|vao)|giao hang))"
)
TIER1_RE: Final[re.Pattern[str]] = _C(
    r"(?:(?:co (?:nen|the) )?(?:chuyen|nop) (?:tien|khoan|\d[^\n?]{0,25})(?: (?:cho|vao))?"
    r".{0,30}\b(?:duoc )?(?:khong|chua)\b|\ban toan\b.{0,30}\b(?:khong|chua)\b|(?:co )?(?:tin duoc|"
    r"uy tin|dam bao|that) khong|(?:lo|da|bi lua) (?:chuyen (?:tien|khoan)|doc|gui|cung cap|lo|nhap)|"
    r"(?:lo|doc|gui|cung cap|chia se) (?:ma )?(?:otp|smartotp|pin|cvv|cvc|cccd|mat khau)|"
    r"(?:cai(?: dat)?|tai)\b.{0,20}\bapk\b|\.apk\b|chia se man hinh|giao hang)"
)
BOUNDARY_RE: Final[re.Pattern[str]] = _C(
    r"(?:(?<!\d)\.[ \t]*\n|[!?][ \t]*\n|(?<!\d)\.[ \t]+|[!?][ \t]+|\n)"
)
TIER2_ESC_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:bien lai|so du|giao hang|chuyen khoan|tien ve|tien vao)\b"
)
CLAUSE_RE: Final[re.Pattern[str]] = _C(r"(?:(?<!\d)\.(?=\s|$)|(?<=\d)\.(?=\s+[A-ZÀ-Ỹ])|[!?;\n:])+")
_CS: Final[str] = r"\b(?:nen|nhung|ma|vi vay|do do|tuy nhien|tuy vay)\b"
PIVOT_RE: Final[re.Pattern[str]] = _C(rf"(?:,|{_CS}|\bthi\b)")
CAUSAL_RE: Final[re.Pattern[str]] = _C(_CS)
NEG_TOK_RE: Final[re.Pattern[str]] = _C(r"\b(?:khong|chua|dung|ngung|tranh|cam)\b")
NEG_DECL_TOKS: Final[frozenset[str]] = frozenset({"khong", "chua"})
NEG_BRIDGE: Final[frozenset[str]] = frozenset({
    "the", "nen", "duoc", "phai", "bao", "gio", "chac", "voi", "tu", "dong",
    "la", "rang", "co", "nghia", "bang", "chung", "khang", "dinh", "xac", "nhan", "minh",
    "dam", "cam", "ket", "luan", "chuyen", "anh", "chup", "bien", "lai", "he", "thong",
    "tin", "tuong", "phep", "viec", "bat", "ky", "ai", "bi", "de", "hoan", "toan", "tuyet",
})
NEG_VERIFY_WORDS: Final[frozenset[str]] = frozenset({"xac", "minh", "nhan"})

GUIDE_TOPIC_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:cach|huong dan)\b.{0,30}\b(?:xac minh|kiem tra|doi chieu)$"
)
IMP_ASK_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:hay|can|nen|vui long|phai|tu|ban)\b.{0,25}\b(?:kiem tra|doi chieu|xac minh|xem)\b"
)
CLAIM_SUBJ_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:da|vua|moi|he thong|toi|chung toi|verishield|tro ly)\b"
)
CLOSE_CHUA_RE: Final[re.Pattern[str]] = _C(r"^(?:\S+ ){0,4}chua\b")
FRAUD_LOSS_RE: Final[re.Pattern[str]] = _C(r"\b(?:trung gian|ke gian|trinh bao)\b")
NEG_BAL_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:khong|khoi|mien|dung|tranh|cam) (?:(?:can |phai |nen )?(?:kiem tra|doi chieu|xem lai)|"
    r"(?:can|phai|nen) (?:xac nhan|xac minh))\b|\b(?:khoi|mien|dung|tranh|cam) (?:xac nhan|xac minh)\b"
)

SETTLE_PRE_VERBS: Final[tuple[str, ...]] = ("chuyen", "nop", "gui", "nhan", "doi", "cho", "rut")
SETTLE_PAST_ACTION_RE: Final[re.Pattern[str]] = _C(r"\b(?:da|vua|moi)\b")
SETTLE_CUSTOMER_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:khach(?:\s+hang)?|nguoi\s+mua|nguoi\s+chuyen|ben\s+mua)\b"
)
SETTLE_DONE_SUFFIX_RE: Final[re.Pattern[str]] = _C(r"\b(?:roi|thanh cong|xong|hoan tat)\b")
SETTLE_VICTIM_LO_RE: Final[re.Pattern[str]] = _C(r"\b(?:da|vua)\s+lo\b")

SETTLE_RE: Final[re.Pattern[str]] = _C(
    r"(?:tien (?:da (?:vao|ve|chuyen (?:vao|thanh cong))|(?:vao|ve) (?:tai khoan|roi|thanh "
    r"cong))|khach(?: hang)? da chuyen (?:tien|khoan) thanh cong|da (?:nhan (?:duoc |du )?tien|ghi co|"
    r"thanh toan (?:xong|thanh cong)|hoan tat thanh toan)|so du da (?:duoc )?(?:ghi co|cap nhat|tang|"
    r"cong)|(?:bien lai(?: chuyen khoan)?|bill|anh chup(?: bien lai| man hinh)?|giao dich)(?: nay)? (?:la"
    r" )?(?:hoan toan |chac chan |100% )?(?:that(?: 100%)?|chinh xac|hop le|da hoan tat an toan)|"
    r"(?:xac nhan|chung minh|dam bao) (?:rang )?tien (?:da )?(?:vao|ve))"
)
HANDOVER_RE: Final[re.Pattern[str]] = _C(
    r"(?:(?:cu|co the)? ?yen tam (?:giao|dua) hang|(?:co the|nen|cu|hay) (?:giao|dua) hang"
    r"|(?:giao|dua) hang(?: cho khach)? (?:ngay|luon|di))"
)
ABS_SAFE_RE: Final[re.Pattern[str]] = _C(
    r"(?:(?:chac chan|dam bao|cam ket|khang dinh|hoan toan|tuyet doi) (?:la )?an toan|"
    r"an toan (?:tuyet doi|hoan toan|100%|chac chan)|(?:100%|mot tram phan tram) (?:an toan|that|"
    r"uy tin|tin cay)|khong co bat ky rui ro nao|hoan toan khong phai lua dao)"
)
_OV: Final[str] = r"(?:cung cap|chia se|doc|gui|nhap) (?:ma |so )?(?:otp|smartotp|pin|cvv|cvc|mat khau)"
_AV: Final[str] = r"(?:tai|cai(?: dat)?) (?:file|tep|ung dung)? ?\.?apk"
UNSAFE_ACT_RE: Final[re.Pattern[str]] = _C(
    rf"(?:(?:\b(?:co the|nen|cu)|^hay|(?<=ban )hay|(?<=lo lang )hay) (?:{_OV}|{_AV}|"
    rf"(?:yen tam )?chuyen (?:tien|khoan)(?: (?:ngay|luon|di|cho|vao))?)|(?:^|\bban )(?:{_OV}|{_AV})\b|"
    rf"\b{_OV} (?:cho|vao|ngay|di|nhe|luon)\b|\b{_AV} (?:ve|ngay|di|nhe|luon|tu)\b)"
)
ADVICE_MOD_RE: Final[re.Pattern[str]] = _C(r"^(?:co the|nen|hay|cu|yen tam|vui long)\b")
PRE_ADVICE_RE: Final[re.Pattern[str]] = _C(r"\b(?:can|nen|hay|cu|co the|vui long|yen tam)$")
DESC_FRAME_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:neu|khi|truong hop|(?:da|vua) lo|bi lua|ke gian|doi tuong|nan nhan|yeu cau|du(?: do)?)\b"
)
BAL_COND_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:sau khi|khi da|neu da|khi)\b.{0,45}\b(?:kiem tra|doi chieu|xac nhan|thay|"
    r"bao nhan)\b.{0,45}\b(?:so du|ung dung ngan hang|soundbox|loa thong bao|bien dong)\b"
)
PRE_BAL_RE: Final[re.Pattern[str]] = _C(
    r"\b(?:sau khi|khi|neu)\b.{0,45}\b(?:ung dung ngan hang|soundbox|loa thong bao|so du)\b"
)

MD_EMPH_RE: Final[re.Pattern[str]] = _C(
    r"(?<!\*)(?:(?<!\d)\*{1,3}|\*{1,3}(?!\d))(?!\*)|(?<!_)_{1,3}(?!_)"
)
HOTLINE_RE: Final[re.Pattern[str]] = _C(
    rf"(?<![\d*])(?:"
    rf"(?:\(\s*)?(?:1800|1900)(?:\s*\))?(?:{_S}\d){{4,6}}|"
    rf"(?:\(\s*)?\+?84(?:\s*\))?(?:{_S}\(?0\)?)?{_S}(?:[35789](?:{_S}\d){{8}}|2\d(?:{_S}\d){{8,9}})|"
    rf"(?:\(\s*)?02\d{{1,2}}(?:\s*\))?(?:{_S}\d){{7,8}}|"
    rf"0[3-9](?:{_S}\d){{8}}"
    rf")(?![\d*]|\.\d)"
)
DATE_RE: Final[re.Pattern[str]] = _C(r"^\d{2}[./-]\d{2}[./-](?:19|20)\d{2}\b")
CURR_RE: Final[re.Pattern[str]] = _C(
    r"^\s*(?:đ|d|vnd|vnđ|dong|đồng|triệu|trieu|nghìn|nghin|ngàn|ngan)(?!\w)", re.I
)
CHECK_VERBS: Final[tuple[str, ...]] = (
    "kiem tra", "doi chieu", "xac nhan", "chi giao hang", "verify", "check"
)
BAL_TARGETS: Final[tuple[str, ...]] = (
    "so du", "ung dung ngan hang", "soundbox", "loa thong bao", "bien dong so du", "balance"
)
EPISTEMIC_CUES: Final[tuple[str, ...]] = (
    "chua phat hien", "chua ghi nhan", "khong dam bao", "khong the khang dinh",
    "khong the xac nhan", "chua the xac nhan", "chua the ket luan", "khong phai bang chung",
    "khong bao gio la bang chung", "tu xac minh", "xac minh lai", "xac minh truc tiep", "kiem tra xem",
    "kiem tra truc tiep", "kiem tra so du", "doi chieu", "kenh chinh thuc", "than trong", "canh giac",
)
