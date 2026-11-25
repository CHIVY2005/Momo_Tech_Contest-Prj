"""SSRF-safe URL redirect tracer, IDN Punycode/homoglyph detector, and brand-spoof analyzer."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Final
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.security import validate_url_target
from app.schemas import UrlFinding

MAX_REDIRECT_HOPS: Final[int] = 5

_RISKY_TLDS: Final[frozenset[str]] = frozenset(
    {"top", "vip", "xyz", "click", "buzz", "icu", "shop", "club", "cfd", "live", "online", "site"}
)

_CONFUSABLE_MAP: Final[dict[str, str]] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "а": "a",  # Cyrillic small letters
    "е": "e",
    "і": "i",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
}

_PHISHING_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\.apk(?:$|\?)|/(?:login|verify|xacthuc|capnhat|otp|kyc|diemthuong|hoantien))",
    re.IGNORECASE,
)


@lru_cache(maxsize=1)
def _load_brand_rules() -> list[dict[str, Any]]:
    kb_path = Path(__file__).resolve().parent.parent / "data" / "vn_scam_kb.json"
    with kb_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    brands: list[dict[str, Any]] = data.get("official_brands", [])
    return brands


def _is_official_domain(ascii_host: str, official_domains: list[str]) -> bool:
    for official in official_domains:
        off = official.lower()
        if ascii_host == off or ascii_host.endswith("." + off):
            return True
    return False


def _skeletonize(label: str) -> str:
    replaced = "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in label.lower())
    return re.sub(r"[^a-z0-9]", "", replaced)


def _levenshtein_le_two(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 2:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        if min(curr) > 2:
            return False
        prev = curr
    return prev[-1] <= 2


def _detect_brand_spoof(
    ascii_host: str,
    unicode_host: str,
    url_path: str,
) -> tuple[str | None, bool, list[str]]:
    reasons: list[str] = []
    is_punycode = "xn--" in ascii_host
    has_non_ascii = not unicode_host.isascii()
    is_homoglyph = is_punycode or has_non_ascii

    brand_rules = _load_brand_rules()
    for entry in brand_rules:
        if _is_official_domain(ascii_host, entry["official_domains"]):
            return None, False, []

    host_labels = [lbl for lbl in unicode_host.split(".") if lbl]
    core_skeleton = _skeletonize(".".join(host_labels[:-1]) if len(host_labels) > 1 else unicode_host)
    full_target = f"{core_skeleton} {url_path.lower()}"

    for entry in brand_rules:
        brand_name: str = entry["brand"]
        for kw in entry["keywords"]:
            kw_clean = re.sub(r"[^a-z0-9]", "", kw.lower())
            if kw_clean in full_target or (
                len(kw_clean) >= 6 and _levenshtein_le_two(core_skeleton, kw_clean)
            ):
                if unicode_host != ascii_host or any(ch in unicode_host for ch in _CONFUSABLE_MAP):
                    is_homoglyph = True
                reasons.append(
                    f"Tên miền '{unicode_host}' mạo danh thương hiệu '{brand_name}' "
                    f"(không thuộc tên miền chính thức {', '.join(entry['official_domains'])})."
                )
                return brand_name, is_homoglyph, reasons

    if is_homoglyph:
        reasons.append(
            f"Tên miền chứa mã hóa IDN Punycode / ký tự đồng hình đáng ngờ ({ascii_host})."
        )
    return None, is_homoglyph, reasons


async def inspect_url(
    url: str,
    enable_network: bool = True,
    client: httpx.AsyncClient | None = None,
) -> UrlFinding:
    """Inspect a URL statically and optionally follow up to 5 SSRF-checked redirect hops."""
    cleaned = url.strip()
    parsed = urlsplit(cleaned)
    raw_host = (parsed.hostname or "").strip().rstrip(".").lower()

    try:
        ascii_host = raw_host.encode("idna").decode("ascii") if raw_host else ""
        unicode_host = ascii_host.encode("ascii").decode("idna") if ascii_host else raw_host
    except UnicodeError:
        ascii_host = raw_host
        unicode_host = raw_host

    ok_target, block_reason, _ = validate_url_target(cleaned, resolve_dns=enable_network)
    if not ok_target:
        # Distinguish DNS lookup failure on offline dead phishing domains from actual SSRF blocks
        is_ssrf = block_reason is not None and not block_reason.startswith("DNS resolution failed")
        if is_ssrf:
            return UrlFinding(
                url=cleaned,
                domain=raw_host,
                normalized_ascii_domain=ascii_host,
                is_blocked_ssrf=True,
                risk_points=90,
                reasons=[f"Chặn truy cập mục tiêu không an toàn (SSRF Guard): {block_reason}"],
            )

    spoofed_brand, is_homoglyph, reasons = _detect_brand_spoof(
        ascii_host=ascii_host,
        unicode_host=unicode_host,
        url_path=f"{parsed.path}?{parsed.query}",
    )

    risk = 0
    if spoofed_brand:
        risk += 70
    if is_homoglyph:
        risk = max(risk + 15, 75)

    tld = ascii_host.rsplit(".", 1)[-1] if "." in ascii_host else ""
    if tld in _RISKY_TLDS:
        risk += 15
        reasons.append(f"Sử dụng đuôi tên miền rủi ro cao '.{tld}' phổ biến trong chiến dịch phishing.")

    path_and_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    if re.search(r"\.apk(?:$|\?)", path_and_query, re.IGNORECASE):
        risk = max(risk + 25, 85)
        reasons.append("Đường dẫn trỏ trực tiếp tới tệp cài đặt Android (.apk) ngoài chợ ứng dụng.")
    elif _PHISHING_PATH_RE.search(path_and_query) and (spoofed_brand or tld in _RISKY_TLDS):
        risk += 10
        reasons.append("Đường dẫn chứa từ khóa thu thập thông tin xác thực / OTP.")

    final_url: str | None = None
    hops = 0

    if enable_network and ok_target:
        current_url = cleaned
        owns_client = client is None
        http_client = client or httpx.AsyncClient(timeout=3.5, follow_redirects=False)
        try:
            for _ in range(MAX_REDIRECT_HOPS):
                resp = await http_client.get(
                    current_url,
                    follow_redirects=False,
                    headers={"User-Agent": "VeriShield-SecurityInspector/2.0"},
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location")
                    if not loc:
                        break
                    next_url = urljoin(current_url, loc)
                    hop_ok, hop_reason, _ = validate_url_target(next_url, resolve_dns=True)
                    if not hop_ok:
                        return UrlFinding(
                            url=cleaned,
                            domain=raw_host,
                            normalized_ascii_domain=ascii_host,
                            final_url=next_url,
                            redirect_hops=hops + 1,
                            is_blocked_ssrf=True,
                            is_idn_homoglyph=is_homoglyph,
                            spoofed_brand=spoofed_brand,
                            risk_points=90,
                            reasons=[
                                *reasons,
                                f"Chặn chuyển hướng HTTP tới đích nội bộ (SSRF Redirect): {hop_reason}",
                            ],
                        )
                    current_url = next_url
                    hops += 1
                    final_url = current_url
                else:
                    final_url = current_url
                    break
        except httpx.HTTPError:
            reasons.append("Máy chủ đích không phản hồi hoặc đã ngắt kết nối sớm.")
        finally:
            if owns_client:
                await http_client.aclose()

    return UrlFinding(
        url=cleaned,
        domain=raw_host,
        normalized_ascii_domain=ascii_host,
        final_url=final_url,
        redirect_hops=hops,
        is_blocked_ssrf=False,
        is_idn_homoglyph=is_homoglyph,
        spoofed_brand=spoofed_brand,
        risk_points=min(100, risk),
        reasons=reasons,
    )
