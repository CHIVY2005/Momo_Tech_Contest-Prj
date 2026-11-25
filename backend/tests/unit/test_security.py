import io

import pytest
from PIL import Image

from app.core.security import (
    InvalidMediaError,
    UploadTooLargeError,
    is_public_ip,
    validate_upload_bytes,
    validate_url_target,
    verify_secret,
)


def test_blocks_loopback_private_metadata_cgnat_and_ipv4_mapped_ipv6() -> None:
    blocked_ips = [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.10.2",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "fe80::1",
        "fc00::1",
    ]
    for ip in blocked_ips:
        assert is_public_ip(ip) is False, f"Expected {ip} to be blocked"

    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("2606:4700:4700::1111") is True


def test_validate_url_target_rejects_bad_schemes_credentials_and_mapped_ips() -> None:
    ok_mapped, reason_mapped, _ = validate_url_target(
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        resolve_dns=False,
    )
    assert ok_mapped is False and reason_mapped is not None

    ok_scheme, _, _ = validate_url_target("file:///etc/passwd", resolve_dns=False)
    assert ok_scheme is False

    ok_localhost, _, _ = validate_url_target("http://localhost:8000/api", resolve_dns=False)
    assert ok_localhost is False

    ok_public, reason_public, _ = validate_url_target(
        "https://vietcombank.com.vn/khach-hang",
        resolve_dns=False,
    )
    assert ok_public is True and reason_public is None


def test_upload_validation_enforces_size_and_magic_bytes() -> None:
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), color=(255, 0, 0)).save(buf, format="PNG")
    valid_png = buf.getvalue()

    validate_upload_bytes(valid_png, max_bytes=1024 * 1024, kind="image")

    # Valid MP3 ID3 header & WAV RIFF header
    validate_upload_bytes(b"ID3\x04\x00\x00\x00\x00\x00\x00frame", max_bytes=1024, kind="audio")
    validate_upload_bytes(b"RIFF\x24\x00\x00\x00WAVEfmt ", max_bytes=1024, kind="audio")

    with pytest.raises(UploadTooLargeError):
        validate_upload_bytes(b"x" * 1025, max_bytes=1024, kind="image")
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(b"", max_bytes=1024, kind="image")
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(b"not-an-image-at-all", max_bytes=1024, kind="image")
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(b"not-valid-audio-bytes", max_bytes=1024, kind="audio")


def test_verify_secret_constant_time_and_empty_handling() -> None:
    assert verify_secret("2026", "2026") is True
    assert verify_secret("0000", "2026") is False
    assert verify_secret(None, "2026") is False
    assert verify_secret("2026", "") is False
