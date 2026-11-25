import socket

import httpx
import pytest
import respx

from app.services.url_inspector import inspect_url


@pytest.mark.asyncio
async def test_blocks_initial_malformed_and_redirect_hop_ssrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    direct = await inspect_url("http://127.0.0.1:8000/health", enable_network=True)
    assert direct.is_blocked_ssrf is True
    assert direct.risk_points >= 85

    malformed = await inspect_url("http://example.com:99999/login", enable_network=False)
    assert malformed.is_blocked_ssrf is True

    loop = pytest.MonkeyPatch()
    _ = loop
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host: str, port: int, *args: object, **kwargs: object) -> list[tuple]:
        if host in ("short.example", "napas-diemthuong-247.top"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return real_getaddrinfo(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with respx.mock:
        respx.get("https://short.example/go").mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            )
        )
        async with httpx.AsyncClient() as client:
            finding = await inspect_url(
                "https://short.example/go",
                enable_network=True,
                client=client,
            )
    assert finding.is_blocked_ssrf is True
    assert finding.risk_points >= 85


@pytest.mark.asyncio
async def test_scores_phishing_redirect_destination_from_neutral_shortlink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host: str, port: int, *args: object, **kwargs: object) -> list[tuple]:
        if host in ("short.example", "napas-diemthuong-247.top"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return real_getaddrinfo(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with respx.mock:
        respx.get("https://short.example/promo").mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "https://napas-diemthuong-247.top/VNeID.apk"},
            )
        )
        respx.get("https://napas-diemthuong-247.top/VNeID.apk").mock(
            return_value=httpx.Response(200, content=b"apk-binary")
        )
        async with httpx.AsyncClient() as client:
            hop_finding = await inspect_url(
                "https://short.example/promo",
                enable_network=True,
                client=client,
            )
    assert hop_finding.redirect_hops == 1
    assert hop_finding.spoofed_brand in ("NAPAS", "VNeID")
    assert hop_finding.risk_points >= 85


@pytest.mark.asyncio
async def test_detects_napas_bank_typosquatting_and_idn_punycode() -> None:
    puny = await inspect_url("https://xn--vietcmbank-21a.com/login", enable_network=False)
    assert puny.is_idn_homoglyph is True
    assert puny.risk_points >= 75

    official_vcb = await inspect_url("https://portal.vietcombank.com.vn/vi-VN", enable_network=False)
    assert official_vcb.spoofed_brand is None
    assert official_vcb.risk_points == 0
