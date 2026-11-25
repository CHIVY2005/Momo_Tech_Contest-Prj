import httpx
import pytest
import respx

from app.services.url_inspector import inspect_url


@pytest.mark.asyncio
async def test_blocks_initial_and_redirect_hop_to_internal_metadata_ssrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    direct = await inspect_url("http://127.0.0.1:8000/health", enable_network=True)
    assert direct.is_blocked_ssrf is True
    assert direct.risk_points >= 85

    # Simulate public DNS for initial domain, then 302 redirect to AWS/Cloud IMDS
    import socket

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host: str, port: int, *args: object, **kwargs: object) -> list[tuple]:
        if host == "short.example":
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
async def test_detects_napas_bank_typosquatting_and_idn_punycode() -> None:
    napas_spoof = await inspect_url("https://napas-diemthuong-247.top/verify", enable_network=False)
    assert napas_spoof.spoofed_brand == "NAPAS"
    assert napas_spoof.risk_points >= 70

    puny = await inspect_url("https://xn--vietcmbank-21a.com/login", enable_network=False)
    assert puny.is_idn_homoglyph is True
    assert puny.risk_points >= 75

    apk_link = await inspect_url("https://dichvucong-capnhat.xyz/VNeID_v2.apk", enable_network=False)
    assert apk_link.spoofed_brand == "VNeID"
    assert apk_link.risk_points >= 80

    official_vcb = await inspect_url("https://portal.vietcombank.com.vn/vi-VN", enable_network=False)
    assert official_vcb.spoofed_brand is None
    assert official_vcb.risk_points == 0

    official_napas = await inspect_url("https://napas.com.vn/tin-tuc", enable_network=False)
    assert official_napas.spoofed_brand is None
    assert official_napas.risk_points == 0
