"""Unit tests for WP-2 phishing detonator and bounded HTTP decompression hardening."""

from __future__ import annotations

import asyncio
import gzip
import os
import sys
import types
import zlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from app.core.http_decompression import (
    DecompressionLimitError,
    SharedByteBudget,
    read_bounded_http_body,
)
from app.services import phishing_detonator as pd


class _ChunkedByteStream(httpx.AsyncByteStream):
    """True async byte stream so httpx exercises resp.aiter_raw() without pre-buffering."""

    def __init__(self, payload: bytes, chunk_size: int = 4096) -> None:
        self._payload = payload
        self._chunk_size = chunk_size
        self.chunks_yielded = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for idx in range(0, len(self._payload), self._chunk_size):
            self.chunks_yielded += 1
            yield self._payload[idx : idx + self._chunk_size]


async def _allow_all_public_validate(
    target: str,
    resolve_dns: bool = True,
    timeout_sec: float = 2.5,
) -> tuple[bool, str | None, list[str]]:
    _ = (target, resolve_dns, timeout_sec)
    return True, None, ["93.184.216.34"]


@pytest.mark.asyncio
async def test_read_bounded_http_body_blocks_gzip_bomb_incrementally() -> None:
    bomb = gzip.compress(b"\x00" * 12_000_000, compresslevel=9)
    assert len(bomb) < 30_000  # tiny on the wire, 12 MB uncompressed

    def _handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/bomb":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                stream=_ChunkedByteStream(bomb, chunk_size=1024),
            )
        if path == "/xgzip-ok":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "x-gzip"},
                stream=_ChunkedByteStream(gzip.compress(b"hello-xgzip"), chunk_size=8),
            )
        if path == "/multi-member-bomb":
            combined = gzip.compress(b"ok") + bomb
            return httpx.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                stream=_ChunkedByteStream(combined, chunk_size=1024),
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        async with client.stream("GET", "https://example.com/bomb") as resp:
            assert resp.is_stream_consumed is False
            with pytest.raises(DecompressionLimitError):
                await read_bounded_http_body(resp, max_body_bytes=64_000)

        async with client.stream("GET", "https://example.com/xgzip-ok") as resp:
            assert await read_bounded_http_body(resp, max_body_bytes=1024) == b"hello-xgzip"

        async with client.stream("GET", "https://example.com/multi-member-bomb") as resp:
            with pytest.raises(DecompressionLimitError):
                await read_bounded_http_body(resp, max_body_bytes=64_000)


@pytest.mark.asyncio
async def test_read_bounded_http_body_handles_zlib_and_raw_rfc1951_deflate_and_caps() -> None:
    plain = b"VeriShield bounded deflate payload " * 100
    zlib_wrapped = zlib.compress(plain)

    raw_comp = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    raw_deflate = raw_comp.compress(plain) + raw_comp.flush()

    bomb_comp = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    raw_deflate_bomb = bomb_comp.compress(b"A" * 5_000_000) + bomb_comp.flush()

    def _handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/zlib":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "deflate"},
                stream=_ChunkedByteStream(zlib_wrapped, chunk_size=64),
            )
        if req.url.path == "/raw":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "deflate"},
                stream=_ChunkedByteStream(raw_deflate, chunk_size=64),
            )
        if req.url.path == "/raw-bomb":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "deflate"},
                stream=_ChunkedByteStream(raw_deflate_bomb, chunk_size=512),
            )
        if req.url.path == "/corrupt":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "deflate"},
                stream=_ChunkedByteStream(b"\xff\xfe\xfd\xfc\xfb", chunk_size=8),
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        async with client.stream("GET", "https://example.com/zlib") as resp:
            assert await read_bounded_http_body(resp, max_body_bytes=10_000) == plain

        async with client.stream("GET", "https://example.com/raw") as resp:
            assert await read_bounded_http_body(resp, max_body_bytes=10_000) == plain

        async with client.stream("GET", "https://example.com/raw-bomb") as resp:
            with pytest.raises(DecompressionLimitError):
                await read_bounded_http_body(resp, max_body_bytes=32_000)

        async with client.stream("GET", "https://example.com/corrupt") as resp:
            with pytest.raises(DecompressionLimitError):
                await read_bounded_http_body(resp, max_body_bytes=1024)


@pytest.mark.asyncio
async def test_read_bounded_http_body_rejects_stacked_and_unsupported_encodings() -> None:
    payload = gzip.compress(gzip.compress(b"nested"))

    def _handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/stacked":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "gzip, gzip"},
                stream=_ChunkedByteStream(payload),
            )
        if req.url.path == "/dup-header":
            return httpx.Response(
                200,
                headers=[("Content-Encoding", "gzip"), ("Content-Encoding", "gzip")],
                stream=_ChunkedByteStream(payload),
            )
        if req.url.path == "/br":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "br"},
                stream=_ChunkedByteStream(b"fake-brotli"),
            )
        if req.url.path == "/zstd":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "zstd"},
                stream=_ChunkedByteStream(b"fake-zstd"),
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        for path in ("/stacked", "/dup-header", "/br", "/zstd"):
            async with client.stream("GET", f"https://example.com{path}") as resp:
                with pytest.raises(DecompressionLimitError):
                    await read_bounded_http_body(resp, max_body_bytes=10_000)


@pytest.mark.asyncio
async def test_read_bounded_http_body_enforces_wire_body_and_prebuffered_caps() -> None:
    def _handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/wire-over":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "identity"},
                stream=_ChunkedByteStream(b"x" * 2048, chunk_size=256),
            )
        if req.url.path == "/prebuffered-ok":
            return httpx.Response(200, text="<html>prebuffered</html>")
        if req.url.path == "/prebuffered-big":
            return httpx.Response(200, text="A" * 500)
        if req.url.path == "/empty-gzip":
            return httpx.Response(
                204,
                headers={"Content-Encoding": "gzip"},
                stream=_ChunkedByteStream(b""),
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        async with client.stream("GET", "https://example.com/wire-over") as resp:
            with pytest.raises(DecompressionLimitError):
                await read_bounded_http_body(resp, max_body_bytes=4096, max_wire_bytes=1024)

        async with client.stream("GET", "https://example.com/prebuffered-ok") as resp:
            assert resp.is_stream_consumed is True
            assert await read_bounded_http_body(resp, max_body_bytes=1024) == b"<html>prebuffered</html>"

        async with client.stream("GET", "https://example.com/prebuffered-big") as resp:
            with pytest.raises(DecompressionLimitError):
                await read_bounded_http_body(resp, max_body_bytes=128)

        async with client.stream("GET", "https://example.com/empty-gzip") as resp:
            assert await read_bounded_http_body(resp, max_body_bytes=1024) == b""


@pytest.mark.asyncio
async def test_fetch_via_pinned_client_hardens_headers_csp_and_blocks_gzip_bomb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pd, "async_validate_url_target", _allow_all_public_validate)
    seen_accept_encodings: list[str] = []
    bomb = gzip.compress(b"\x00" * 5_000_000, compresslevel=9)

    def _handler(req: httpx.Request) -> httpx.Response:
        seen_accept_encodings.append(req.headers.get("accept-encoding", ""))
        if req.url.path == "/page":
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": "report-uri http://169.254.169.254/csp",
                    "Content-Security-Policy-Report-Only": "default-src 'none'; report-to leak",
                    "Report-To": '{"group":"leak","endpoints":[{"url":"http://127.0.0.1/r"}]}',
                    "Reporting-Endpoints": 'leak="http://127.0.0.1/r"',
                    "NEL": '{"report_to":"leak","max_age":60}',
                    "X-Safe-Keep": "ok",
                },
                stream=_ChunkedByteStream(b"<html><body>hi</body></html>"),
            )
        if req.url.path == "/xhtml":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/xhtml+xml"},
                stream=_ChunkedByteStream(b"<html/>"),
            )
        if req.url.path == "/style.css":
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/css",
                    "Content-Security-Policy": "report-uri http://127.0.0.1/css",
                    "X-Content-Type-Options": "allow-sniff",
                    "NEL": '{"report_to":"leak"}',
                },
                stream=_ChunkedByteStream(b"body { color: red; }"),
            )
        if req.url.path == "/sniff-no-mime":
            return httpx.Response(
                200,
                headers={"X-Content-Type-Options": "invalid"},
                stream=_ChunkedByteStream(b"<html><script>new Worker('x')</script></html>"),
            )
        if req.url.path == "/icon.svg":
            return httpx.Response(
                200,
                headers={"Content-Type": "image/svg+xml"},
                stream=_ChunkedByteStream(b"<svg xmlns='http://www.w3.org/2000/svg'/>"),
            )
        if req.url.path == "/bomb":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Content-Encoding": "gzip"},
                stream=_ChunkedByteStream(bomb, chunk_size=1024),
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        st, hdrs, body, final_u = await pd._fetch_via_pinned_client(
            client, "GET", "https://example.com/page", []
        )
        assert st == 200
        assert final_u == "https://example.com/page"
        assert body == b"<html><body>hi</body></html>"
        lower_hdrs = {k.lower(): v for k, v in hdrs.items()}
        assert lower_hdrs["content-security-policy"] == (
            "worker-src 'none'; child-src 'none'; object-src 'none'"
        )
        assert lower_hdrs["x-content-type-options"] == "nosniff"
        for stripped in (
            "content-security-policy-report-only",
            "report-to",
            "reporting-endpoints",
            "nel",
        ):
            assert stripped not in lower_hdrs
        assert lower_hdrs["x-safe-keep"] == "ok"

        _, xhtml_hdrs, _, _ = await pd._fetch_via_pinned_client(
            client, "GET", "https://example.com/xhtml", []
        )
        assert xhtml_hdrs["Content-Security-Policy"] == (
            "worker-src 'none'; child-src 'none'; object-src 'none'"
        )
        assert xhtml_hdrs["X-Content-Type-Options"] == "nosniff"

        _, css_hdrs, _, _ = await pd._fetch_via_pinned_client(
            client, "GET", "https://example.com/style.css", []
        )
        css_lower = {k.lower(): v for k, v in css_hdrs.items()}
        assert css_lower["content-security-policy"] == pd._SANDBOX_HTML_CSP
        assert "report-uri" not in css_lower["content-security-policy"]
        assert css_lower["x-content-type-options"] == "nosniff"
        assert "nel" not in css_lower

        for path in ("/sniff-no-mime", "/icon.svg"):
            _, extra_hdrs, _, _ = await pd._fetch_via_pinned_client(
                client, "GET", f"https://example.com{path}", []
            )
            extra_lower = {k.lower(): v for k, v in extra_hdrs.items()}
            assert extra_lower["content-security-policy"] == pd._SANDBOX_HTML_CSP
            assert extra_lower["x-content-type-options"] == "nosniff"

        with pytest.raises(DecompressionLimitError):
            await pd._fetch_via_pinned_client(client, "GET", "https://example.com/bomb", [])

    assert seen_accept_encodings
    assert all(enc == "identity" for enc in seen_accept_encodings)


def test_sanitized_chromium_env_scrubs_secrets_on_posix_and_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = (
        "GEMINI_API_KEY",
        "GEMINI_BACKUP_API_KEY",
        "ANALYST_PIN",
        "IOC_HMAC_SECRET",
        "CASE_TOKEN_SECRET",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_WEBHOOK_SECRET",
        "UNRELATED_SECRET_TOKEN",
    )
    for idx, key in enumerate(secrets):
        monkeypatch.setenv(key, f"secret_val_{idx}")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/ms-playwright")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("COMSPEC", r"C:\Windows\System32\cmd.exe")
    monkeypatch.setenv("TEMP", r"C:\Temp")
    monkeypatch.setenv("TMP", r"C:\Temp")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\app\AppData\Local")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\app")

    monkeypatch.setattr(os, "name", "posix")
    posix_env = pd._sanitized_chromium_env()
    for secret in secrets:
        assert secret not in posix_env
    assert posix_env["HOME"] == "/tmp"  # noqa: S108
    assert posix_env["TMPDIR"] == "/tmp"  # noqa: S108
    assert posix_env["XDG_CACHE_HOME"] == "/tmp"  # noqa: S108
    assert posix_env["XDG_CONFIG_HOME"] == "/tmp"  # noqa: S108
    assert posix_env["PLAYWRIGHT_BROWSERS_PATH"] == "/ms-playwright"
    assert set(posix_env).issubset(
        {
            "PATH",
            "HOME",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "PLAYWRIGHT_BROWSERS_PATH",
            "LANG",
            "LC_ALL",
            "TZ",
        }
    )

    monkeypatch.setattr(os, "name", "nt")
    win_env = pd._sanitized_chromium_env()
    for secret in secrets:
        assert secret not in win_env
    assert win_env["PLAYWRIGHT_BROWSERS_PATH"] == "/ms-playwright"
    assert set(win_env).issubset(
        {
            "SYSTEMROOT",
            "COMSPEC",
            "TEMP",
            "TMP",
            "LOCALAPPDATA",
            "USERPROFILE",
            "PATH",
            "PLAYWRIGHT_BROWSERS_PATH",
        }
    )


def test_disable_direct_browser_egress_js_hardens_all_egress_apis() -> None:
    script = pd._DISABLE_DIRECT_BROWSER_EGRESS_JS
    assert "function deny()" in script
    assert "Blocked by VeriShield Sandbox Policy" in script
    assert "try {" in script and "catch (_)" in script
    for api_name in (
        "WebSocket",
        "EventSource",
        "RTCPeerConnection",
        "webkitRTCPeerConnection",
        "mozRTCPeerConnection",
        "WebTransport",
        "Worker",
        "SharedWorker",
        "sendBeacon",
    ):
        assert api_name in script


@dataclass
class _FakeRequest:
    url: str
    method: str = "GET"
    resource_type: str = "fetch"
    navigation: bool = False
    frame: object = field(default_factory=object)

    def is_navigation_request(self) -> bool:
        return self.navigation


@dataclass
class _FakeRoute:
    request: _FakeRequest
    action: str | None = None
    abort_code: str | None = None
    fulfilled_status: int | None = None
    fulfilled_body: bytes | None = None

    async def continue_(self) -> None:
        self.action = "continue"

    async def abort(self, error_code: str = "failed") -> None:
        self.action = "abort"
        self.abort_code = error_code

    async def fulfill(
        self,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        _ = headers
        self.action = "fulfill"
        self.fulfilled_status = status
        self.fulfilled_body = body


def _install_fake_playwright(
    monkeypatch: pytest.MonkeyPatch,
    *,
    on_goto: Callable[[Any, object], Any],
) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    main_frame = object()

    class _FakePage:
        def __init__(self) -> None:
            self.main_frame = main_frame

        async def goto(self, url: str, **kwargs: Any) -> None:
            _ = (url, kwargs)
            handler = captured["route_handler"]
            await on_goto(handler, main_frame)

        async def title(self) -> str:
            return "Fake Title"

        async def content(self) -> str:
            return "<html><body>ok</body></html>"

        async def screenshot(self, **kwargs: Any) -> bytes:
            _ = kwargs
            return b"\xff\xd8\xff\xd9"

    class _FakeContext:
        async def add_init_script(self, script: str) -> None:
            captured["init_script"] = script

        async def route_web_socket(self, pattern: str, handler: Any) -> None:
            captured["ws_route"] = (pattern, handler)

        async def new_page(self) -> _FakePage:
            return _FakePage()

        async def route(self, pattern: str, handler: Any) -> None:
            captured["route_pattern"] = pattern
            captured["route_handler"] = handler

    class _FakeBrowser:
        async def new_context(self, **kwargs: Any) -> _FakeContext:
            captured["context_kwargs"] = kwargs
            return _FakeContext()

        async def close(self) -> None:
            captured["closed"] = True

    class _FakeChromium:
        async def launch(self, **kwargs: Any) -> _FakeBrowser:
            captured["launch_kwargs"] = kwargs
            return _FakeBrowser()

    class _FakePlaywrightCM:
        async def __aenter__(self) -> Any:
            return types.SimpleNamespace(chromium=_FakeChromium())

        async def __aexit__(self, *args: Any) -> None:
            _ = args

    fake_api = types.ModuleType("playwright.async_api")
    fake_api.async_playwright = lambda: _FakePlaywrightCM()  # type: ignore[attr-defined]
    fake_api.Route = Any  # type: ignore[attr-defined]
    fake_pkg = types.ModuleType("playwright")
    fake_pkg.async_api = fake_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", fake_pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_api)
    return captured


@pytest.mark.asyncio
async def test_sandbox_launch_args_env_and_pinned_proxy_route_blocks_bypasses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "top-secret-gemini")
    monkeypatch.setenv("ANALYST_PIN", "999999")
    monkeypatch.setattr(pd, "async_validate_url_target", _allow_all_public_validate)

    def _transport_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            stream=_ChunkedByteStream(b"<html><body>landing</body></html>"),
        )

    monkeypatch.setattr(
        pd,
        "build_ssrf_pinned_http_client",
        lambda timeout_sec=3.0: httpx.AsyncClient(
            transport=httpx.MockTransport(_transport_handler)
        ),
    )

    route_results: dict[str, _FakeRoute] = {}

    async def _drive_routes(handler: Any, main_frame: object) -> None:
        cases = [
            ("about_blank", _FakeRequest("about:blank", resource_type="document", frame=main_frame)),
            ("data_png", _FakeRequest("data:image/png;base64,iVBORw0KGgo=", resource_type="image")),
            ("data_jpg_upper", _FakeRequest("DATA:IMAGE/JPEG;base64,/9j/4AAQ", resource_type="image")),
            ("data_webp", _FakeRequest("data:image/webp;base64,UklGRg==", resource_type="image")),
            ("data_gif", _FakeRequest("data:image/gif;base64,R0lGODlh", resource_type="image")),
            ("blob_url", _FakeRequest("blob:https://evil.example/1234", resource_type="script")),
            ("data_svg", _FakeRequest("data:image/svg+xml;base64,PHN2Zy8+", resource_type="image")),
            ("data_js", _FakeRequest("data:text/javascript,alert(1)", resource_type="script")),
            ("data_html", _FakeRequest("data:text/html,<h1>x</h1>", resource_type="document")),
            ("about_srcdoc", _FakeRequest("about:srcdoc", resource_type="document")),
            ("worker_type", _FakeRequest("https://example.com/w.js", resource_type="worker")),
            ("shared_worker", _FakeRequest("https://example.com/sw.js", resource_type="shared_worker")),
            ("websocket_type", _FakeRequest("https://example.com/ws", resource_type="websocket")),
            ("eventsource_type", _FakeRequest("https://example.com/sse", resource_type="eventsource")),
            (
                "worker_on_data_png",
                _FakeRequest("data:image/png;base64,iVBORw0KGgo=", resource_type="worker"),
            ),
            (
                "script_on_data_png",
                _FakeRequest("data:image/png;base64,iVBORw0KGgo=", resource_type="script"),
            ),
            (
                "doc_on_data_png",
                _FakeRequest("data:image/png;base64,iVBORw0KGgo=", resource_type="document"),
            ),
        ]
        for label, req in cases:
            rt = _FakeRoute(req)
            await handler(rt)
            route_results[label] = rt

    captured = _install_fake_playwright(monkeypatch, on_goto=_drive_routes)
    res = await pd.detonate_url_in_sandbox("https://example.com/", enabled=True, timeout_ms=3000)
    assert res.available is True

    launch_kwargs = captured["launch_kwargs"]
    assert "GEMINI_API_KEY" not in launch_kwargs["env"]
    assert "ANALYST_PIN" not in launch_kwargs["env"]
    for flag in (
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-features=WebTransport",
        "--disable-blink-features=WebTransport",
        "--proxy-server=http://127.0.0.1:9",
        "--proxy-bypass-list=<-loopback>",
    ):
        assert flag in launch_kwargs["args"]
    assert captured["init_script"] == pd._DISABLE_DIRECT_BROWSER_EGRESS_JS

    for allowed_label in ("about_blank", "data_png", "data_jpg_upper", "data_webp", "data_gif"):
        assert route_results[allowed_label].action == "continue", allowed_label

    for blocked_label in (
        "blob_url",
        "data_svg",
        "data_js",
        "data_html",
        "about_srcdoc",
        "worker_type",
        "shared_worker",
        "websocket_type",
        "eventsource_type",
        "worker_on_data_png",
        "script_on_data_png",
        "doc_on_data_png",
    ):
        assert route_results[blocked_label].action == "abort", blocked_label
        assert route_results[blocked_label].abort_code == "blockedbyclient", blocked_label


@pytest.mark.asyncio
async def test_pinned_proxy_route_enforces_subrequest_count_and_total_bytes_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pd, "async_validate_url_target", _allow_all_public_validate)

    # 1. Subrequest count limit (MAX_SANDBOX_SUBREQUESTS = 24)
    subreq_fetch_calls = 0

    def _count_handler(req: httpx.Request) -> httpx.Response:
        nonlocal subreq_fetch_calls
        if req.url.path.startswith("/sub/"):
            subreq_fetch_calls += 1
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            stream=_ChunkedByteStream(b"ok"),
        )

    monkeypatch.setattr(
        pd,
        "build_ssrf_pinned_http_client",
        lambda timeout_sec=3.0: httpx.AsyncClient(
            transport=httpx.MockTransport(_count_handler)
        ),
    )

    count_routes: list[_FakeRoute] = []

    async def _drive_subreq_cap(handler: Any, _main_frame: object) -> None:
        for idx in range(pd.MAX_SANDBOX_SUBREQUESTS + 3):
            rt = _FakeRoute(_FakeRequest(f"https://example.com/sub/{idx}"))
            await handler(rt)
            count_routes.append(rt)

    _install_fake_playwright(monkeypatch, on_goto=_drive_subreq_cap)
    await pd.detonate_url_in_sandbox("https://example.com/start", enabled=True, timeout_ms=3000)

    assert subreq_fetch_calls == pd.MAX_SANDBOX_SUBREQUESTS
    assert all(r.action == "fulfill" for r in count_routes[: pd.MAX_SANDBOX_SUBREQUESTS])
    assert all(
        r.action == "abort" and r.abort_code == "failed"
        for r in count_routes[pd.MAX_SANDBOX_SUBREQUESTS :]
    )

    # 2. Total session bytes limit (MAX_SANDBOX_TOTAL_BYTES = 4_000_000)
    def _bytes_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/init":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                stream=_ChunkedByteStream(b"I" * 1_000_000, chunk_size=65_536),
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/octet-stream"},
            stream=_ChunkedByteStream(b"B" * 1_200_000, chunk_size=65_536),
        )

    monkeypatch.setattr(
        pd,
        "build_ssrf_pinned_http_client",
        lambda timeout_sec=3.0: httpx.AsyncClient(
            transport=httpx.MockTransport(_bytes_handler)
        ),
    )

    byte_routes: list[_FakeRoute] = []

    async def _drive_bytes_cap(handler: Any, _main_frame: object) -> None:
        # 1.0 MB init + 1.2 MB (2.2 MB) + 1.2 MB (3.4 MB) succeed; 3rd (+1.2 MB -> 4.6 MB > 4.0 MB) aborts
        for idx in range(4):
            rt = _FakeRoute(_FakeRequest(f"https://example.com/blob/{idx}"))
            await handler(rt)
            byte_routes.append(rt)

    _install_fake_playwright(monkeypatch, on_goto=_drive_bytes_cap)
    await pd.detonate_url_in_sandbox("https://example.com/init", enabled=True, timeout_ms=3000)

    assert byte_routes[0].action == "fulfill"
    assert byte_routes[1].action == "fulfill"
    assert byte_routes[2].action == "abort"
    assert byte_routes[2].abort_code == "failed"
    assert byte_routes[3].action == "abort"
    assert byte_routes[3].abort_code == "failed"


class _YieldingChunkStream(httpx.AsyncByteStream):
    """Async stream yielding to the event loop per chunk to force true concurrent interleaving."""

    def __init__(self, payload: bytes, chunk_size: int = 16_384) -> None:
        self._payload = payload
        self._chunk_size = chunk_size
        self._offset = 0
        self.bytes_yielded = 0

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        if self._offset >= len(self._payload):
            raise StopAsyncIteration
        chunk = self._payload[self._offset : self._offset + self._chunk_size]
        self._offset += len(chunk)
        self.bytes_yielded += len(chunk)
        await asyncio.sleep(0)
        return chunk


@pytest.mark.asyncio
async def test_concurrent_subrequests_share_byte_budget_and_abort_mid_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pd, "async_validate_url_target", _allow_all_public_validate)

    # 1. Direct SharedByteBudget enforcement under concurrent read_bounded_http_body streams
    shared_budget = SharedByteBudget(pd.MAX_SANDBOX_TOTAL_BYTES)
    streams: list[_YieldingChunkStream] = []

    def _direct_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/gz/"):
            gz_payload = gzip.compress(b"Z" * 1_200_000, compresslevel=6)
            st = _YieldingChunkStream(gz_payload, chunk_size=4096)
            streams.append(st)
            return httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=st)
        st = _YieldingChunkStream(b"X" * 1_200_000, chunk_size=16_384)
        streams.append(st)
        return httpx.Response(200, headers={"Content-Type": "application/octet-stream"}, stream=st)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_direct_handler)) as client:
        async def _pull(path: str) -> int:
            async with client.stream("GET", f"https://example.com{path}") as resp:
                data = await read_bounded_http_body(
                    resp,
                    max_body_bytes=pd.MAX_SANDBOX_BODY_BYTES,
                    session_budget=shared_budget,
                )
                return len(data)

        # 6 concurrent 1.2 MB streams = 7.2 MB attempted against 4.0 MB shared budget
        results = await asyncio.gather(
            *[_pull(f"/raw/{i}") for i in range(4)],
            *[_pull(f"/gz/{i}") for i in range(2)],
            return_exceptions=True,
        )

    errors = [r for r in results if isinstance(r, DecompressionLimitError)]
    succeeded_bytes = sum(r for r in results if isinstance(r, int))
    assert errors, "Expected concurrent streams exceeding MAX_SANDBOX_TOTAL_BYTES to abort"
    assert shared_budget.used <= pd.MAX_SANDBOX_TOTAL_BYTES
    assert succeeded_bytes <= pd.MAX_SANDBOX_TOTAL_BYTES

    # 2. End-to-end concurrent _pinned_proxy_route subrequests inside detonate_url_in_sandbox
    route_streams: list[_YieldingChunkStream] = []

    def _sandbox_concurrent_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/init":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                stream=_YieldingChunkStream(b"I" * 500_000, chunk_size=16_384),
            )
        st = _YieldingChunkStream(b"C" * 1_200_000, chunk_size=16_384)
        route_streams.append(st)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/octet-stream"},
            stream=st,
        )

    monkeypatch.setattr(
        pd,
        "build_ssrf_pinned_http_client",
        lambda timeout_sec=3.0: httpx.AsyncClient(
            transport=httpx.MockTransport(_sandbox_concurrent_handler)
        ),
    )

    concurrent_routes: list[_FakeRoute] = []

    async def _drive_concurrent_subreqs(handler: Any, _main_frame: object) -> None:
        routes = [_FakeRoute(_FakeRequest(f"https://example.com/asset/{i}")) for i in range(6)]
        await asyncio.gather(*(handler(rt) for rt in routes))
        concurrent_routes.extend(routes)

    _install_fake_playwright(monkeypatch, on_goto=_drive_concurrent_subreqs)
    await pd.detonate_url_in_sandbox("https://example.com/init", enabled=True, timeout_ms=3000)

    fulfilled_bytes = sum(
        len(rt.fulfilled_body or b"") for rt in concurrent_routes if rt.action == "fulfill"
    )
    aborted = [rt for rt in concurrent_routes if rt.action == "abort" and rt.abort_code == "failed"]
    assert aborted, "Concurrent Playwright subrequests must abort when shared budget is exhausted"
    assert 500_000 + fulfilled_bytes <= pd.MAX_SANDBOX_TOTAL_BYTES
    # Verify streams aborted mid-flight rather than buffering all 6 * 1.2 MB = 7.2 MB
    total_yielded = sum(s.bytes_yielded for s in route_streams)
    assert total_yielded < 6 * 1_200_000


def test_inspect_rendered_dom_never_whitelists_backslash_or_invalid_authority_urls() -> None:
    phish_html = """
    <html>
      <head><title>Vietcombank Digibank Xác Thực</title></head>
      <body>
        <form>
          <input type="password" name="pwd" />
          <input type="text" name="otp" placeholder="Nhập mã OTP" maxlength="6" />
        </form>
      </body>
    </html>
    """
    malicious_pairs = [
        ("https://evil.top\\@vietcombank.com.vn/login", "https://vietcombank.com.vn/login"),
        ("https://short.example/go", "https://evil.top\\@vietcombank.com.vn/login"),
        ("https://vietcombank.com.vn\\@evil.top/login", None),
        ("https://sub_bad.vietcombank.com.vn/login", "https://sub_bad.vietcombank.com.vn/login"),
        ("https://vietcombank.com.vn.../login", "https://vietcombank.com.vn.../login"),
        ("https://user:pass@vietcombank.com.vn/login", "https://user:pass@vietcombank.com.vn/login"),
    ]
    for visited, final in malicious_pairs:
        res = pd.inspect_rendered_dom(
            visited_url=visited,
            final_url=final,
            page_title="Vietcombank Digibank Xác Thực",
            html=phish_html,
            download_urls=[],
        )
        assert res.risk_points >= 90, f"Risk wrongly suppressed for ({visited!r}, {final!r})"
        assert res.impersonated_brand == "Vietcombank"
        assert res.reasons

    # Control: clean official domain remains recognized as official
    official = pd.inspect_rendered_dom(
        visited_url="https://vietcombank.com.vn/login",
        final_url="https://vietcombank.com.vn/login",
        page_title="Vietcombank Digibank",
        html=phish_html,
        download_urls=[],
    )
    assert official.risk_points == 0
    assert official.reasons == []
