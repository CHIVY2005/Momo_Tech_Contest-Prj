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
from urllib.parse import urljoin
from weakref import WeakKeyDictionary

import httpx

from app.core.http_decompression import SharedByteBudget, read_bounded_http_body
from app.core.security import (
    SsrfBlockedError,
    async_validate_url_target,
    build_ssrf_pinned_http_client,
)
from app.core.url_authority import (
    extract_strict_ascii_host,
    has_disallowed_url_backslash,
)
from app.schemas import SandboxInspection

MAX_SANDBOX_BODY_BYTES: Final[int] = 1_500_000
MAX_SANDBOX_REDIRECT_HOPS: Final[int] = 5
MAX_SANDBOX_SUBREQUESTS: Final[int] = 24
MAX_SANDBOX_TOTAL_BYTES: Final[int] = 4_000_000

_POSIX_SANDBOX_TMP: Final[str] = "/tmp"  # noqa: S108
_WINDOWS_ENV_ALLOWLIST: Final[tuple[str, ...]] = (
    "SYSTEMROOT",
    "COMSPEC",
    "TEMP",
    "TMP",
    "LOCALAPPDATA",
    "USERPROFILE",
    "PATH",
    "PLAYWRIGHT_BROWSERS_PATH",
)
_POSIX_ENV_ALLOWLIST: Final[tuple[str, ...]] = (
    "PATH",
    "PLAYWRIGHT_BROWSERS_PATH",
    "LANG",
    "LC_ALL",
    "TZ",
)
_CHROMIUM_LAUNCH_ARGS: Final[tuple[str, ...]] = (
    "--disable-dev-shm-usage",
    "--disable-background-networking",
    "--host-resolver-rules=MAP * ~NOTFOUND",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-features=WebTransport",
    "--disable-blink-features=WebTransport",
    "--proxy-server=http://127.0.0.1:9",
    "--proxy-bypass-list=<-loopback>",
)
_STRIPPED_RESPONSE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "content-encoding",
        "transfer-encoding",
        "content-length",
        "location",
        "content-security-policy",
        "content-security-policy-report-only",
        "report-to",
        "reporting-endpoints",
        "nel",
        "x-content-type-options",
    }
)
_SANDBOX_HTML_CSP: Final[str] = "worker-src 'none'; child-src 'none'; object-src 'none'"
_ALLOWED_DATA_IMAGE_PREFIXES: Final[tuple[str, ...]] = (
    "data:image/png;",
    "data:image/jpeg;",
    "data:image/jpg;",
    "data:image/webp;",
    "data:image/gif;",
)
_BLOCKED_RESOURCE_TYPES: Final[frozenset[str]] = frozenset(
    {"worker", "shared_worker", "websocket", "eventsource"}
)

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

def _sanitized_chromium_env() -> dict[str, str]:
    """Return a minimal allowlisted env for Chromium so backend secrets never leak."""
    if os.name == "nt":
        return {k: v for k in _WINDOWS_ENV_ALLOWLIST if (v := os.environ.get(k))}
    env: dict[str, str] = {
        "HOME": _POSIX_SANDBOX_TMP,
        "TMPDIR": _POSIX_SANDBOX_TMP,
        "XDG_CACHE_HOME": _POSIX_SANDBOX_TMP,
        "XDG_CONFIG_HOME": _POSIX_SANDBOX_TMP,
    }
    for key in _POSIX_ENV_ALLOWLIST:
        val = os.environ.get(key)
        if val:
            env[key] = val
    return env


_DISABLE_DIRECT_BROWSER_EGRESS_JS: Final[str] = """
(() => {
  function deny() { throw new Error('Blocked by VeriShield Sandbox Policy'); }
  for (const key of [
    'WebSocket',
    'EventSource',
    'RTCPeerConnection',
    'webkitRTCPeerConnection',
    'mozRTCPeerConnection',
    'WebTransport',
    'Worker',
    'SharedWorker',
  ]) {
    try {
      Object.defineProperty(window, key, {
        value: deny,
        configurable: false,
        writable: false,
      });
    } catch (_) {}
  }
  try {
    if (navigator && 'sendBeacon' in navigator) {
      Object.defineProperty(navigator, 'sendBeacon', {
        value: () => false,
        configurable: false,
        writable: false,
      });
    }
  } catch (_) {}
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
    if not h:
        return False
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
    visited_strict_host = (
        None
        if has_disallowed_url_backslash(visited_url)
        else extract_strict_ascii_host(visited_url)
    )
    effective_strict_host = (
        None
        if has_disallowed_url_backslash(effective_url)
        else extract_strict_ascii_host(effective_url)
    )
    authority_valid = visited_strict_host is not None and effective_strict_host is not None
    host = effective_strict_host or ""

    has_password = bool(_PASSWORD_INPUT_RE.search(html))
    has_otp = bool(_OTP_SIGNAL_RE.search(html))
    has_apk = bool(_APK_SIGNAL_RE.search(html)) or any(
        u.lower().split("?", 1)[0].endswith(".apk") for u in download_urls
    )

    impersonated_brand: str | None = None
    corpus = f"{page_title or ''} {html[:6000]}".lower()
    official_entries = _load_official_brands()

    is_any_official = authority_valid and any(
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
        host_label = host or "không hợp lệ"
        reasons.append(
            f"Giao diện trang web hiển thị thương hiệu '{impersonated_brand}' "
            f"trên tên miền lạ '{host_label}'."
        )
    if has_password:
        risk += 20
        reasons.append("Trang web có biểu mẫu yêu cầu nhập mật khẩu.")
    if has_otp:
        risk += 25
        reasons.append("Trang web yêu cầu nhập mã OTP hoặc thông tin thẻ ngân hàng.")
    if has_apk:
        risk = max(risk + 35, 85)
        reasons.append(
            "Trang web chứa liên kết tải tệp cài đặt Android (.apk) có nguy cơ chiếm quyền thiết bị."
        )

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
    *,
    max_body_bytes: int = MAX_SANDBOX_BODY_BYTES,
    session_budget: SharedByteBudget | None = None,
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
                headers={
                    "User-Agent": "Mozilla/5.0 VeriShieldSandbox/2.0",
                    "Accept-Encoding": "identity",
                },
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

                body = await read_bounded_http_body(
                    resp,
                    max_body_bytes=max_body_bytes,
                    max_wire_bytes=max_body_bytes,
                    session_budget=session_budget,
                )
                clean_headers = {
                    k: v
                    for k, v in resp.headers.items()
                    if k.lower() not in _STRIPPED_RESPONSE_HEADERS
                }
                clean_headers["X-Content-Type-Options"] = "nosniff"
                clean_headers["Content-Security-Policy"] = _SANDBOX_HTML_CSP
                status_out = 204 if 300 <= resp.status_code < 400 else resp.status_code
                return status_out, clean_headers, body, current
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

    ok_static, _static_reason, _ = await async_validate_url_target(cleaned, resolve_dns=False)
    if not ok_static:
        return SandboxInspection(
            available=False,
            visited_url=cleaned,
            blocked_ssrf=True,
            risk_points=90,
            reasons=["Đã chặn truy cập trong môi trường cách ly vì đường dẫn trỏ tới địa chỉ nội bộ."],
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
                    reasons=["Đã chặn kết nối tới địa chỉ mạng nội bộ không an toàn."]
                    if is_ssrf
                    else [],
                )

            # Pre-resolve initial navigation hops via IP-pinned client to establish true final origin
            session_budget = SharedByteBudget(MAX_SANDBOX_TOTAL_BYTES)
            init_status, init_headers, init_body, resolved_entry_url = await _fetch_via_pinned_client(
                safe_client,
                "GET",
                cleaned,
                download_urls,
                session_budget=session_budget,
            )
            main_frame_url = resolved_entry_url
            staged_docs: dict[str, tuple[int, dict[str, str], bytes]] = {
                resolved_entry_url: (init_status, init_headers, init_body)
            }
            deferred_main_nav_url: str | None = None
            subrequest_count = 0

            async with async_playwright() as pw:
                launch_env: dict[str, str | float | bool] = {
                    k: v for k, v in _sanitized_chromium_env().items()
                }
                browser = await pw.chromium.launch(
                    headless=True,
                    chromium_sandbox=_use_chromium_sandbox(),
                    env=launch_env,
                    args=list(_CHROMIUM_LAUNCH_ARGS),
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
                        nonlocal subrequest_count
                        req = route.request
                        req_url = req.url
                        req_url_lower = req_url.lower()
                        if req.resource_type in _BLOCKED_RESOURCE_TYPES:
                            await route.abort("blockedbyclient")
                            return
                        if req_url_lower == "about:blank" or (
                            req.resource_type == "image"
                            and req_url_lower.startswith(_ALLOWED_DATA_IMAGE_PREFIXES)
                        ):
                            await route.continue_()
                            return
                        if req_url_lower.startswith(("blob:", "data:", "about:")):
                            await route.abort("blockedbyclient")
                            return
                        try:
                            if req_url in staged_docs:
                                st_s, hd_s, bd_s = staged_docs.pop(req_url)
                                await route.fulfill(status=st_s, headers=hd_s, body=bd_s)
                                return

                            if (
                                subrequest_count >= MAX_SANDBOX_SUBREQUESTS
                                or session_budget.remaining <= 0
                            ):
                                await route.abort("failed")
                                return
                            subrequest_count += 1
                            remaining_budget = min(
                                MAX_SANDBOX_BODY_BYTES,
                                session_budget.remaining,
                            )

                            status, headers, body, final_hop = await _fetch_via_pinned_client(
                                safe_client,
                                req.method,
                                req_url,
                                download_urls,
                                max_body_bytes=remaining_budget,
                                session_budget=session_budget,
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
                                        "Đã chặn chuyển hướng tới địa chỉ mạng nội bộ không an toàn."
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
                                "Đã chặn yêu cầu kết nối tới địa chỉ mạng nội bộ không an toàn."
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
    except SsrfBlockedError:
        return SandboxInspection(
            available=True,
            visited_url=cleaned,
            final_url=main_frame_url,
            blocked_ssrf=True,
            risk_points=90,
            reasons=["Đã chặn chuyển hướng tới địa chỉ mạng nội bộ không an toàn."],
        )
    except Exception:
        if blocked_subrequest_reason is not None:
            return SandboxInspection(
                available=True,
                visited_url=cleaned,
                final_url=main_frame_url,
                blocked_ssrf=True,
                risk_points=90,
                reasons=["Đã chặn kết nối tới địa chỉ mạng nội bộ trong môi trường cách ly."],
            )
        return SandboxInspection(
            available=False,
            visited_url=cleaned,
            reasons=["Không thể mở xem trước trang web này trong môi trường cách ly."],
        )
    finally:
        await safe_client.aclose()
