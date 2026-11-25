import pytest

from app.services.phishing_detonator import (
    detonate_url_in_sandbox,
    inspect_rendered_dom,
)


def test_inspect_rendered_dom_catches_otp_password_and_apk_traps() -> None:
    html = """
    <html>
      <head><title>Cổng xác thực VNeID Bộ Công an</title></head>
      <body>
        <form action="/steal">
          <input type="password" name="passcode" />
          <input type="text" name="otp_code" placeholder="Nhập mã OTP 6 số" maxlength="6" />
          <a href="/files/VNeID_CapNhat_2026.apk">Tải ứng dụng xác thực</a>
        </form>
      </body>
    </html>
    """
    summary = inspect_rendered_dom(
        visited_url="https://vneid-xacthuc.top/login",
        final_url="https://vneid-xacthuc.top/login",
        page_title="Cổng xác thực VNeID Bộ Công an",
        html=html,
        download_urls=[],
    )
    assert summary.has_password_field is True
    assert summary.has_otp_field is True
    assert summary.has_apk_download is True
    assert summary.impersonated_brand == "VNeID"
    assert summary.risk_points >= 85


@pytest.mark.asyncio
async def test_sandbox_blocks_ssrf_and_handles_disabled_flag() -> None:
    ssrf = await detonate_url_in_sandbox(
        "http://169.254.169.254/latest/meta-data/",
        enabled=True,
    )
    assert ssrf.blocked_ssrf is True
    assert ssrf.risk_points >= 85

    disabled = await detonate_url_in_sandbox(
        "https://example.com",
        enabled=False,
    )
    assert disabled.available is False
    assert disabled.blocked_ssrf is False
