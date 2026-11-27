"""SSRF-pinned streaming URL redirect tracer, Punycode/homoglyph detector, and hop scorer."""

from __future__ import annotations

import asyncio
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Final
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.security import (
    SsrfBlockedError,
    async_validate_url_target,
    build_ssrf_pinned_http_client,
)
from app.core.url_authority import (
    extract_strict_ascii_host,
    has_disallowed_url_backslash,
    strip_single_trailing_dot,
)
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
    "а": "a",
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


_BACKSLASH_SPOOF_REASON: Final[str] = (
    "Đường dẫn chứa ký tự dấu gạch chéo ngược ('\\') bất thường trong phần tên miền, "
    "có dấu hiệu giả mạo thương hiệu hoặc đánh lừa trình duyệt."
)


def _score_single_url(target_url: str) -> tuple[str, str, str | None, bool, int, list[str]]:
    """Compute static brand-spoof, homoglyph, TLD, and APK risk for a single URL."""
    raw = target_url.strip()
    if has_disallowed_url_backslash(raw):
        return "", "", None, False, 90, [_BACKSLASH_SPOOF_REASON]

    try:
        parsed = urlsplit(raw)
        raw_host = strip_single_trailing_dot((parsed.hostname or "").strip().lower())
    except ValueError:
        return "", "", None, False, 90, ["Đường dẫn không đúng định dạng địa chỉ trang web."]

    strict_ascii_host = extract_strict_ascii_host(raw)
    try:
        ascii_host = (
            strict_ascii_host
            if strict_ascii_host is not None
            else (raw_host.encode("idna").decode("ascii").lower() if raw_host else "")
        )
        unicode_host = ascii_host.encode("ascii").decode("idna") if ascii_host else raw_host
    except UnicodeError:
        ascii_host = raw_host
        unicode_host = raw_host

    reasons: list[str] = []
    is_homoglyph = ("xn--" in ascii_host) or (not unicode_host.isascii())
    spoofed_brand: str | None = None

    brand_rules = _load_brand_rules()
    if strict_ascii_host is not None:
        for entry in brand_rules:
            if _is_official_domain(strict_ascii_host, entry["official_domains"]):
                return raw_host, strict_ascii_host, None, False, 0, []

    host_labels = [lbl for lbl in unicode_host.split(".") if lbl]
    core_skeleton = _skeletonize(".".join(host_labels[:-1]) if len(host_labels) > 1 else unicode_host)
    path_and_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    full_target = f"{core_skeleton} {path_and_query.lower()}"

    for entry in brand_rules:
        brand_name: str = entry["brand"]
        for kw in entry["keywords"]:
            kw_clean = re.sub(r"[^a-z0-9]", "", kw.lower())
            if kw_clean in full_target or (
                len(kw_clean) >= 6 and _levenshtein_le_two(core_skeleton, kw_clean)
            ):
                if unicode_host != ascii_host or any(ch in unicode_host for ch in _CONFUSABLE_MAP):
                    is_homoglyph = True
                spoofed_brand = brand_name
                reasons.append(
                    f"Tên miền '{unicode_host}' có dấu hiệu giả mạo thương hiệu '{brand_name}' "
                    f"(khác với tên miền chính thức {', '.join(entry['official_domains'])})."
                )
                break
        if spoofed_brand:
            break

    if is_homoglyph and not spoofed_brand:
        reasons.append(
            "Tên miền sử dụng ký tự đặc biệt gần giống chữ thông thường để gây nhầm lẫn."
        )

    risk = 0
    if spoofed_brand:
        risk += 70
    if is_homoglyph:
        risk = max(risk + 15, 75)

    tld = ascii_host.rsplit(".", 1)[-1] if "." in ascii_host else ""
    if tld in _RISKY_TLDS:
        risk += 15
        reasons.append(
            f"Tên miền sử dụng đuôi '.{tld}' thường xuất hiện trong các trang web giả mạo."
        )

    if re.search(r"\.apk(?:$|\?)", path_and_query, re.IGNORECASE):
        risk = max(risk + 25, 85)
        reasons.append("Đường dẫn trỏ trực tiếp tới tệp cài đặt Android (.apk) ngoài kho ứng dụng.")
    elif _PHISHING_PATH_RE.search(path_and_query) and (spoofed_brand or tld in _RISKY_TLDS):
        risk += 10
        reasons.append("Đường dẫn có dấu hiệu yêu cầu đăng nhập hoặc xác thực mã OTP đáng ngờ.")

    return raw_host, ascii_host, spoofed_brand, is_homoglyph, min(100, risk), reasons


async def inspect_url(
    url: str,
    enable_network: bool = True,
    client: httpx.AsyncClient | None = None,
) -> UrlFinding:
    """Inspect URL statically and trace up to 5 SSRF-pinned streaming redirect hops."""
    cleaned = url.strip()
    raw_host, ascii_host, spoofed_brand, is_homoglyph, max_risk, all_reasons = _score_single_url(
        cleaned
    )

    ok_target, block_reason, _ = await async_validate_url_target(
        cleaned,
        resolve_dns=enable_network,
    )
    if not ok_target:
        is_ssrf = block_reason is not None and not block_reason.startswith("DNS resolution failed")
        if is_ssrf:
            if has_disallowed_url_backslash(cleaned) and all_reasons:
                blocked_reasons = list(all_reasons)
            else:
                generic_msg = (
                    "Đã chặn truy cập vì đường dẫn trỏ tới địa chỉ mạng nội bộ không an toàn."
                )
                blocked_reasons = [*all_reasons, generic_msg] if all_reasons else [generic_msg]
            return UrlFinding(
                url=cleaned,
                domain=raw_host,
                normalized_ascii_domain=ascii_host,
                is_blocked_ssrf=True,
                is_idn_homoglyph=is_homoglyph,
                spoofed_brand=spoofed_brand,
                risk_points=max(90, max_risk),
                reasons=blocked_reasons,
            )

    final_url: str | None = None
    hops = 0
    redirect_domains: list[str] = []

    def _record_redirect_domain(target: str) -> None:
        if len(redirect_domains) >= 8 or has_disallowed_url_backslash(target):
            return
        hop_host = extract_strict_ascii_host(target)
        if not hop_host:
            try:
                raw_h = strip_single_trailing_dot((urlsplit(target).hostname or "").strip().lower())
                hop_host = raw_h.encode("idna").decode("ascii").lower() if raw_h else ""
            except (ValueError, UnicodeError):
                hop_host = ""
        if hop_host and hop_host not in redirect_domains:
            redirect_domains.append(hop_host)

    if enable_network and ok_target:
        current_url = cleaned
        owns_client = client is None
        http_client = client or build_ssrf_pinned_http_client(timeout_sec=3.5)
        try:
            async with asyncio.timeout(5.5):
                for _ in range(MAX_REDIRECT_HOPS):
                    async with http_client.stream(
                        "GET",
                        current_url,
                        follow_redirects=False,
                        headers={"User-Agent": "VeriShield-SecurityInspector/2.0"},
                    ) as resp:
                        status_code = resp.status_code
                        loc = resp.headers.get("location")

                    if status_code in (301, 302, 303, 307, 308) and loc:
                        try:
                            next_url = urljoin(current_url, loc)
                        except ValueError:
                            return UrlFinding(
                                url=cleaned,
                                domain=raw_host,
                                normalized_ascii_domain=ascii_host,
                                final_url=loc[:160],
                                redirect_hops=hops + 1,
                                redirect_domains=redirect_domains,
                                is_blocked_ssrf=True,
                                is_idn_homoglyph=is_homoglyph,
                                spoofed_brand=spoofed_brand,
                                risk_points=90,
                                reasons=[
                                    *all_reasons,
                                    "Đã chặn chuyển hướng vì địa chỉ đích không hợp lệ.",
                                ],
                            )
                        hop_ok, hop_reason, _ = await async_validate_url_target(
                            next_url,
                            resolve_dns=True,
                        )
                        if not hop_ok:
                            is_hop_ssrf = hop_reason is not None and not hop_reason.startswith(
                                "DNS resolution failed"
                            )
                            if is_hop_ssrf:
                                hop_block_msg = (
                                    _BACKSLASH_SPOOF_REASON
                                    if has_disallowed_url_backslash(next_url)
                                    else "Đã chặn chuyển hướng tới địa chỉ mạng nội bộ không an toàn."
                                )
                                return UrlFinding(
                                    url=cleaned,
                                    domain=raw_host,
                                    normalized_ascii_domain=ascii_host,
                                    final_url=next_url,
                                    redirect_hops=hops + 1,
                                    redirect_domains=redirect_domains,
                                    is_blocked_ssrf=True,
                                    is_idn_homoglyph=is_homoglyph,
                                    spoofed_brand=spoofed_brand,
                                    risk_points=90,
                                    reasons=[*all_reasons, hop_block_msg],
                                )
                            _record_redirect_domain(next_url)
                            all_reasons.append("Không tìm thấy địa chỉ máy chủ của đường dẫn chuyển hướng.")
                            final_url = next_url
                            hops += 1
                            break

                        _record_redirect_domain(next_url)
                        _, _, hop_brand, hop_homo, hop_risk, hop_reasons = _score_single_url(
                            next_url
                        )
                        if hop_brand and not spoofed_brand:
                            spoofed_brand = hop_brand
                        is_homoglyph = is_homoglyph or hop_homo
                        max_risk = max(max_risk, hop_risk)
                        for r in hop_reasons:
                            if r not in all_reasons:
                                all_reasons.append(r)

                        current_url = next_url
                        hops += 1
                        final_url = current_url
                    else:
                        final_url = current_url
                        break
        except SsrfBlockedError:
            return UrlFinding(
                url=cleaned,
                domain=raw_host,
                normalized_ascii_domain=ascii_host,
                final_url=current_url,
                redirect_hops=hops,
                redirect_domains=redirect_domains,
                is_blocked_ssrf=True,
                is_idn_homoglyph=is_homoglyph,
                spoofed_brand=spoofed_brand,
                risk_points=90,
                reasons=[
                    *all_reasons,
                    "Đã chặn kết nối vì tên miền trỏ tới địa chỉ mạng nội bộ không an toàn.",
                ],
            )
        except httpx.RemoteProtocolError as exc:
            if "location header" in str(exc).lower() or "invalid url" in str(exc).lower():
                return UrlFinding(
                    url=cleaned,
                    domain=raw_host,
                    normalized_ascii_domain=ascii_host,
                    final_url=current_url,
                    redirect_hops=hops + 1,
                    redirect_domains=redirect_domains,
                    is_blocked_ssrf=True,
                    is_idn_homoglyph=is_homoglyph,
                    spoofed_brand=spoofed_brand,
                    risk_points=90,
                    reasons=[
                        *all_reasons,
                        "Đã chặn chuyển hướng vì địa chỉ đích trả về không hợp lệ.",
                    ],
                )
            all_reasons.append("Trang web trả về phản hồi không hợp lệ.")
        except (TimeoutError, httpx.HTTPError):
            all_reasons.append("Trang web không phản hồi hoặc quá thời gian kiểm tra.")
        finally:
            if owns_client:
                await http_client.aclose()

    return UrlFinding(
        url=cleaned,
        domain=raw_host,
        normalized_ascii_domain=ascii_host,
        final_url=final_url,
        redirect_hops=hops,
        redirect_domains=redirect_domains,
        is_blocked_ssrf=False,
        is_idn_homoglyph=is_homoglyph,
        spoofed_brand=spoofed_brand,
        risk_points=min(100, max_risk),
        reasons=all_reasons,
    )
