"""Sandboxed Playwright headless Chromium detonator proxied strictly through IP-pinned HTTP."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Final
from urllib.parse import urljoin, urlsplit
from weakref import WeakKeyDictionary

import httpx

from app.core.security import (
    SsrfBlockedError,
    async_validate_url_target,
    build_ssrf_pinned_http_client,
)
from app.schemas import SandboxInspection

MAX_SANDBOX_BODY_BYTES: Final[int] = 1_500_000
MAX_SANDBOX_REDIRECT_HOPS: Final[int] = 5

_LOOP_SEMAPHORES: WeakKeyDictionary[asyncio.AbstractEventLoop, tuple[int, asyncio.Semaphore]] = (
    WeakKeyDictionary()
)


def _get_playwright_concurrency_limit() -> int:
    raw = os.getenv("PLAYWRIGHT_MAX_CONCURRENCY", "2").strip()
    try:
        return max(1, min(8, int(raw)))
    except ValueError:
        return 2


def _use_chromium_sandbox() -> bool:
    raw = os.getenv("PLAYWRIGHT_CHROMIUM_SANDBOX", "true").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _get_playwright_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    limit = _get_playwright_concurrency_limit()
    cached = _LOOP_SEMAPHORES.get(loop)
    if cached is not None and cached[0] == limit:
        return cached[1]
    sem = asyncio.Semaphore(limit)
    _LOOP_SEMAPHORES[loop] = (limit, sem)
    return sem

_DISABLE_DIRECT_BROWSER_EGRESS_JS: Final[str] = """
(() => {
  const deny = () => { throw new Error('Blocked by VeriShield Sandbox Policy'); };
  Object.defineProperty(window, 'WebSocket', { value: deny, configurable: false, writable: false });
  Object.defineProperty(window, 'EventSource', { value: deny, configurable: false, writable: false });
  Object.defineProperty(window, 'RTCPeerConnection', { value: deny, configurable: false, writable: false });
  if (navigator && 'sendBeacon' in navigator) {
    Object.defineProperty(navigator, 'sendBeacon', { value: () => false, configurable: false });
  }
})();
"""

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
    max_hops: int = MAX_SANDBOX_REDIRECT_HOPS,
) -> tuple[int, dict[str, str], bytes, str]:
    """Follow redirects strictly inside IP-pinned client; NEVER delegate 3xx to Chromium."""
    current = target_url
    for _hop in range(max_hops + 1):
        ok_hop, hop_reason, _ = await async_validate_url_target(current, resolve_dns=True)
        if not ok_hop:
            is_ssrf = hop_reason is not None and not hop_reason.startswith("DNS resolution failed")
            if is_ssrf:
                raise SsrfBlockedError(hop_reason or "Blocked non-public subrequest target")
            raise httpx.ConnectError(hop_reason or "DNS resolution failed")

        if current.lower().split("?", 1)[0].endswith(".apk"):
            download_urls.append(current)
            return 204, {}, b"", current

        try:
            async with safe_client.stream(
                method if method in ("GET", "HEAD") else "GET",
                current,
                follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 VeriShieldSandbox/2.0"},
            ) as resp:
                if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                    if _hop >= max_hops:
                        raise httpx.TooManyRedirects("Sandbox redirect limit exceeded")
                    try:
                        next_url = urljoin(current, resp.headers["location"])
                    except ValueError as exc:
                        raise SsrfBlockedError(f"Malformed redirect Location: {exc}") from exc
                    ok_redir, redir_reason, _ = await async_validate_url_target(
                        next_url,
                        resolve_dns=True,
                    )
                    if not ok_redir:
                        is_redir_ssrf = redir_reason is not None and not redir_reason.startswith(
                            "DNS resolution failed"
                        )
                        if is_redir_ssrf:
                            raise SsrfBlockedError(redir_reason or "Redirect target blocked")
                        raise httpx.ConnectError(redir_reason or "Redirect DNS failed")
                    current = next_url
                    method = "GET"
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
                    if k.lower()
                    not in ("content-encoding", "transfer-encoding", "content-length", "location")
                }
                status_out = 204 if 300 <= resp.status_code < 400 else resp.status_code
                return status_out, clean_headers, b"".join(chunks), current
        except httpx.RemoteProtocolError as exc:
            if "location header" in str(exc).lower() or "invalid url" in str(exc).lower():
                raise SsrfBlockedError(f"Malformed redirect Location header: {exc}") from exc
            raise
    raise httpx.TooManyRedirects("Sandbox redirect limit exceeded")


async def detonate_url_in_sandbox(
    url: str,
    enabled: bool = True,
    timeout_ms: int = 3000,
) -> SandboxInspection:
    """Render suspicious URL in headless Chromium with WebSockets/DNS disabled & IP-pinned routing."""
    t_entry = time.monotonic()
    deadline_sec = max(0.25, timeout_ms / 1000.0)
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

    try:
        from playwright.async_api import Route, async_playwright
    except ImportError:
        return SandboxInspection(available=False, visited_url=cleaned)

    blocked_subrequest_reason: str | None = None
    main_frame_url = cleaned
    download_urls: list[str] = []

    safe_client = build_ssrf_pinned_http_client(timeout_sec=deadline_sec)
    try:
        async with asyncio.timeout(deadline_sec), _get_playwright_semaphore():
            ok_dns, dns_reason, _ = await async_validate_url_target(
                cleaned,
                resolve_dns=True,
                timeout_sec=deadline_sec,
            )
            if not ok_dns:
                is_ssrf = dns_reason is not None and not dns_reason.startswith(
                    "DNS resolution failed"
                )
                return SandboxInspection(
                    available=False,
                    visited_url=cleaned,
                    blocked_ssrf=is_ssrf,
                    risk_points=90 if is_ssrf else 0,
                    reasons=[f"Chặn kết nối không an toàn: {dns_reason}"] if is_ssrf else [],
                )

            # Pre-resolve initial navigation hops via IP-pinned client to establish true final origin
            init_status, init_headers, init_body, resolved_entry_url = await _fetch_via_pinned_client(
                safe_client,
                "GET",
                cleaned,
                download_urls,
            )
            main_frame_url = resolved_entry_url
            staged_docs: dict[str, tuple[int, dict[str, str], bytes]] = {
                resolved_entry_url: (init_status, init_headers, init_body)
            }
            deferred_main_nav_url: str | None = None

            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    chromium_sandbox=_use_chromium_sandbox(),
                    args=[
                        "--disable-dev-shm-usage",
                        "--disable-background-networking",
                        "--host-resolver-rules=MAP * ~NOTFOUND",
                    ],
                )
                try:
                    context = await browser.new_context(
                        viewport={"width": 800, "height": 500},
                        accept_downloads=False,
                        java_script_enabled=True,
                        service_workers="block",
                    )
                    await context.add_init_script(_DISABLE_DIRECT_BROWSER_EGRESS_JS)
                    route_ws = getattr(context, "route_web_socket", None)
                    if callable(route_ws):
                        await route_ws("**/*", lambda ws: ws.close())

                    page = await context.new_page()

                    async def _pinned_proxy_route(route: Route) -> None:
                        nonlocal blocked_subrequest_reason, main_frame_url, deferred_main_nav_url
                        req = route.request
                        req_url = req.url
                        if req_url.startswith(("data:", "blob:", "about:")):
                            await route.continue_()
                            return
                        try:
                            if req_url in staged_docs:
                                st_s, hd_s, bd_s = staged_docs.pop(req_url)
                                await route.fulfill(status=st_s, headers=hd_s, body=bd_s)
                                return

                            status, headers, body, final_hop = await _fetch_via_pinned_client(
                                safe_client,
                                req.method,
                                req_url,
                                download_urls,
                            )
                            if req.is_navigation_request() and final_hop != req_url:
                                # Never render a redirected document under the old origin
                                if req.frame == page.main_frame:
                                    staged_docs[final_hop] = (status, headers, body)
                                    deferred_main_nav_url = final_hop
                                    main_frame_url = final_hop
                                await route.abort("aborted")
                                return

                            if req.is_navigation_request() and req.frame == page.main_frame:
                                main_frame_url = final_hop
                            await route.fulfill(status=status, headers=headers, body=body)
                        except SsrfBlockedError as exc:
                            blocked_subrequest_reason = str(exc)
                            await route.abort("accessdenied")
                        except Exception:
                            await route.abort("failed")

                    await context.route("**/*", _pinned_proxy_route)
                    current_nav_target: str | None = resolved_entry_url
                    nav_steps = 0
                    while current_nav_target is not None and nav_steps < MAX_SANDBOX_REDIRECT_HOPS:
                        nav_steps += 1
                        target_now = current_nav_target
                        deferred_main_nav_url = None
                        rem_ms = max(100, int((deadline_sec - (time.monotonic() - t_entry)) * 1000))
                        try:
                            await page.goto(
                                target_now,
                                wait_until="domcontentloaded",
                                timeout=rem_ms,
                            )
                        except Exception:
                            if blocked_subrequest_reason is not None:
                                return SandboxInspection(
                                    available=True,
                                    visited_url=cleaned,
                                    final_url=main_frame_url,
                                    blocked_ssrf=True,
                                    risk_points=90,
                                    reasons=[
                                        "Chặn điều hướng/sub-request tới mạng nội bộ: "
                                        f"{blocked_subrequest_reason}"
                                    ],
                                )
                            if deferred_main_nav_url is not None:
                                current_nav_target = deferred_main_nav_url
                                continue
                            raise
                        current_nav_target = deferred_main_nav_url

                    title = await page.title()
                    html = await page.content()
                    shot_bytes = await page.screenshot(type="jpeg", quality=55)
                    shot_b64 = base64.b64encode(shot_bytes).decode("ascii")

                    if blocked_subrequest_reason is not None:
                        return SandboxInspection(
                            available=True,
                            visited_url=cleaned,
                            final_url=main_frame_url,
                            blocked_ssrf=True,
                            risk_points=90,
                            reasons=[
                                f"Chặn sub-request/redirect tới mạng nội bộ: {blocked_subrequest_reason}"
                            ],
                        )

                    return inspect_rendered_dom(
                        visited_url=cleaned,
                        final_url=main_frame_url,
                        page_title=title,
                        html=html,
                        download_urls=download_urls,
                        screenshot_base64=shot_b64,
                    )
                finally:
                    await browser.close()
    except SsrfBlockedError as exc:
        return SandboxInspection(
            available=True,
            visited_url=cleaned,
            final_url=main_frame_url,
            blocked_ssrf=True,
            risk_points=90,
            reasons=[f"Chặn chuyển hướng HTTP tới mạng nội bộ (SSRF Guard): {exc}"],
        )
    except Exception as exc:
        if blocked_subrequest_reason is not None:
            return SandboxInspection(
                available=True,
                visited_url=cleaned,
                final_url=main_frame_url,
                blocked_ssrf=True,
                risk_points=90,
                reasons=[f"Chặn kết nối nội bộ trong buồng cô lập: {blocked_subrequest_reason}"],
            )
        return SandboxInspection(
            available=False,
            visited_url=cleaned,
            reasons=[f"Buồng cô lập không thể hoàn tất hiển thị ({type(exc).__name__})."],
        )
    finally:
        await safe_client.aclose()
