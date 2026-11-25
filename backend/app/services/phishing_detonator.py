"""Sandboxed Playwright headless Chromium detonator proxied strictly through IP-pinned HTTP."""

from __future__ import annotations

import base64
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
from app.schemas import SandboxInspection

MAX_SANDBOX_BODY_BYTES: Final[int] = 1_500_000
MAX_SANDBOX_REDIRECTS: Final[int] = 4

_PASSWORD_INPUT_RE: Final[re.Pattern[str]] = re.compile(
    r"<input[^>]+type=['\"]?password['\"]?",
    re.IGNORECASE,
)
_OTP_SIGNAL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:nhập\s+mã\s+otp|mã\s+xác\s+thực\s+otp|name=['\"]?otp|maxlength=['\"]?6['\"]?|"
    r"số\s+thẻ\s+tín\s+dụng|cvv)",
    re.IGNORECASE,
)
_APK_SIGNAL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:href=['\"][^'\"]+\.apk(?:['\"?])|application/vnd\.android\.package-archive)",
    re.IGNORECASE,
)


@lru_cache(maxsize=1)
def _load_official_brands() -> list[dict[str, Any]]:
    kb_path = Path(__file__).resolve().parent.parent / "data" / "vn_scam_kb.json"
    with kb_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    brands: list[dict[str, Any]] = data.get("official_brands", [])
    return brands


def _host_matches_official(host: str, official_domains: list[str]) -> bool:
    h = host.lower().rstrip(".")
    return any(h == dom.lower() or h.endswith("." + dom.lower()) for dom in official_domains)


def inspect_rendered_dom(
    visited_url: str,
    final_url: str | None,
    page_title: str | None,
    html: str,
    download_urls: list[str],
    screenshot_base64: str | None = None,
) -> SandboxInspection:
    """Pure analyzer inspecting rendered DOM HTML & title for credential/APK phishing traps."""
    effective_url = final_url or visited_url
    try:
        host = (urlsplit(effective_url).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""

    has_password = bool(_PASSWORD_INPUT_RE.search(html))
    has_otp = bool(_OTP_SIGNAL_RE.search(html))
    has_apk = bool(_APK_SIGNAL_RE.search(html)) or any(
        u.lower().split("?", 1)[0].endswith(".apk") for u in download_urls
    )

    impersonated_brand: str | None = None
    corpus = f"{page_title or ''} {html[:6000]}".lower()
    official_entries = _load_official_brands()

    is_any_official = any(
        _host_matches_official(host, entry["official_domains"]) for entry in official_entries
    )
    if not is_any_official:
        for entry in official_entries:
            brand_name: str = entry["brand"]
            if brand_name.lower() in corpus or any(kw.lower() in corpus for kw in entry["keywords"]):
                impersonated_brand = brand_name
                break

    risk = 0
    reasons: list[str] = []
    if impersonated_brand:
        risk += 55
        reasons.append(
            f"Giao diện trang web hiển thị thương hiệu '{impersonated_brand}' trên tên miền lạ '{host}'."
        )
    if has_password:
        risk += 20
        reasons.append("Trang chứa biểu mẫu thu thập mật khẩu (<input type='password'>).")
    if has_otp:
        risk += 25
        reasons.append("Trang yêu cầu nhập mã xác thực OTP / thông tin thẻ.")
    if has_apk:
        risk = max(risk + 35, 85)
        reasons.append("Trang phát tán tệp cài đặt Android (.apk) có nguy cơ chiếm quyền thiết bị.")

    if is_any_official:
        risk = 0
        reasons = []

    return SandboxInspection(
        available=True,
        visited_url=visited_url,
        final_url=effective_url,
        page_title=page_title,
        blocked_ssrf=False,
        has_password_field=has_password,
        has_otp_field=has_otp,
        has_apk_download=has_apk,
        impersonated_brand=impersonated_brand,
        screenshot_base64=screenshot_base64,
        risk_points=min(100, risk),
        reasons=reasons,
    )


async def _fetch_via_pinned_client(
    safe_client: httpx.AsyncClient,
    method: str,
    target_url: str,
    download_urls: list[str],
) -> tuple[int, dict[str, str], bytes, str]:
    """Fetch a browser subrequest hop-by-hop using SSRF-pinned sockets with bounded body size."""
    curr = target_url
    for _ in range(MAX_SANDBOX_REDIRECTS + 1):
        if curr.lower().split("?", 1)[0].endswith(".apk"):
            download_urls.append(curr)
            return 204, {}, b"", curr

        async with safe_client.stream(
            method if method in ("GET", "HEAD") else "GET",
            curr,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 VeriShieldSandbox/2.0"},
        ) as resp:
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                curr = urljoin(curr, resp.headers["location"])
                ok_hop, hop_reason, _ = await async_validate_url_target(curr, resolve_dns=True)
                if not ok_hop:
                    raise SsrfBlockedError(hop_reason or "Redirect target blocked")
                continue

            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_SANDBOX_BODY_BYTES:
                    break
                chunks.append(chunk)
            clean_headers = {
                k: v
                for k, v in resp.headers.items()
                if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
            }
            return resp.status_code, clean_headers, b"".join(chunks), curr

    return 400, {}, b"", curr


async def detonate_url_in_sandbox(
    url: str,
    enabled: bool = True,
    timeout_ms: int = 3000,
) -> SandboxInspection:
    """Render suspicious URL in headless Chromium with Service Workers blocked & IP-pinned routing."""
    cleaned = url.strip()

    ok_static, static_reason, _ = await async_validate_url_target(cleaned, resolve_dns=False)
    if not ok_static:
        return SandboxInspection(
            available=False,
            visited_url=cleaned,
            blocked_ssrf=True,
            risk_points=90,
            reasons=[f"Buồng cô lập chặn địa chỉ nội bộ (SSRF Guard): {static_reason}"],
        )

    if not enabled:
        return SandboxInspection(available=False, visited_url=cleaned)

    ok_dns, dns_reason, _ = await async_validate_url_target(cleaned, resolve_dns=True)
    if not ok_dns:
        is_ssrf = dns_reason is not None and not dns_reason.startswith("DNS resolution failed")
        return SandboxInspection(
            available=False,
            visited_url=cleaned,
            blocked_ssrf=is_ssrf,
            risk_points=90 if is_ssrf else 0,
            reasons=[f"Chặn kết nối không an toàn: {dns_reason}"] if is_ssrf else [],
        )

    try:
        from playwright.async_api import Route, async_playwright
    except ImportError:
        return SandboxInspection(available=False, visited_url=cleaned)

    blocked_subrequest_reason: str | None = None
    last_resolved_url = cleaned
    download_urls: list[str] = []

    safe_client = build_ssrf_pinned_http_client(timeout_sec=max(1.5, timeout_ms / 1000.0))
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-sandbox", "--disable-background-networking"],
            )
            try:
                context = await browser.new_context(
                    viewport={"width": 800, "height": 500},
                    accept_downloads=False,
                    java_script_enabled=True,
                    service_workers="block",
                )

                async def _pinned_proxy_route(route: Route) -> None:
                    nonlocal blocked_subrequest_reason, last_resolved_url
                    req_url = route.request.url
                    if req_url.startswith(("data:", "blob:", "about:")):
                        await route.continue_()
                        return
                    try:
                        status, headers, body, resolved = await _fetch_via_pinned_client(
                            safe_client,
                            route.request.method,
                            req_url,
                            download_urls,
                        )
                        if route.request.is_navigation_request():
                            last_resolved_url = resolved
                        await route.fulfill(status=status, headers=headers, body=body)
                    except SsrfBlockedError as exc:
                        blocked_subrequest_reason = str(exc)
                        await route.abort("accessdenied")
                    except Exception:
                        await route.abort("failed")

                await context.route("**/*", _pinned_proxy_route)
                page = await context.new_page()
                await page.goto(cleaned, wait_until="domcontentloaded", timeout=timeout_ms)

                if blocked_subrequest_reason is not None:
                    return SandboxInspection(
                        available=True,
                        visited_url=cleaned,
                        final_url=last_resolved_url,
                        blocked_ssrf=True,
                        risk_points=90,
                        reasons=[
                            f"Chặn sub-request/redirect tới mạng nội bộ: {blocked_subrequest_reason}"
                        ],
                    )

                title = await page.title()
                html = await page.content()
                shot_bytes = await page.screenshot(type="jpeg", quality=55)
                shot_b64 = base64.b64encode(shot_bytes).decode("ascii")

                return inspect_rendered_dom(
                    visited_url=cleaned,
                    final_url=last_resolved_url,
                    page_title=title,
                    html=html,
                    download_urls=download_urls,
                    screenshot_base64=shot_b64,
                )
            finally:
                await browser.close()
    except Exception:
        return SandboxInspection(available=False, visited_url=cleaned)
    finally:
        await safe_client.aclose()
