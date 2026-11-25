import io
import math
import struct
import wave

import pytest
from PIL import Image

from app.core.security import (
    InvalidMediaError,
    UploadTooLargeError,
    async_validate_url_target,
    is_public_ip,
    validate_upload_bytes,
    validate_url_target,
    verify_secret,
)


def _make_valid_wav_bytes(duration_ms: int = 80, sample_rate: int = 8000) -> bytes:
    buf = io.BytesIO()
    n_samples = int(sample_rate * duration_ms / 1000)
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        frames = bytearray()
        for i in range(n_samples):
            sample = int(12000 * math.sin(2 * math.pi * 440 * i / sample_rate))
            frames.extend(struct.pack("<h", sample))
        wf.writeframes(bytes(frames))
    return buf.getvalue()


def test_blocks_loopback_private_metadata_cgnat_and_all_ipv4_mapped_ipv6() -> None:
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
        "::ffff:8.8.8.8",  # Mapped IPv6 form itself is blocked even for public IPv4
        "fe80::1",
        "fc00::1",
    ]
    for ip in blocked_ips:
        assert is_public_ip(ip) is False, f"Expected {ip} to be blocked"

    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("2606:4700:4700::1111") is True


@pytest.mark.asyncio
async def test_validate_url_target_handles_malformed_authorities_and_async_dns() -> None:
    malformed_urls = [
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:8.8.8.8]/test",
        "http://example.com:99999/path",
        "http://example.com:notaport/path",
        "http://[::1/broken",
        "file:///etc/passwd",
        "http://localhost:8000/api",
    ]
    for bad in malformed_urls:
        ok, reason, _ = validate_url_target(bad, resolve_dns=False)
        assert ok is False and reason is not None
        a_ok, a_reason, _ = await async_validate_url_target(bad, resolve_dns=False)
        assert a_ok is False and a_reason is not None

    ok_public, reason_public, _ = await async_validate_url_target(
        "https://vietcombank.com.vn/khach-hang",
        resolve_dns=False,
    )
    assert ok_public is True and reason_public is None


def test_upload_validation_enforces_size_magic_and_decodable_audio() -> None:
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), color=(255, 0, 0)).save(buf, format="PNG")
    validate_upload_bytes(buf.getvalue(), max_bytes=1024 * 1024, kind="image")

    valid_wav = _make_valid_wav_bytes()
    validate_upload_bytes(valid_wav, max_bytes=1024 * 1024, kind="audio")

    with pytest.raises(UploadTooLargeError):
        validate_upload_bytes(b"x" * 1025, max_bytes=1024, kind="image")
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(b"", max_bytes=1024, kind="image")
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(b"not-an-image-at-all", max_bytes=1024, kind="image")
    # Truncated WAV header with magic prefix but zero decodable audio frames must fail (HTTP 400)
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(b"RIFF\x24\x00\x00\x00WAVEfmt ", max_bytes=1024, kind="audio")
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(b"ID3\x04\x00\x00\x00\x00\x00\x00junk", max_bytes=1024, kind="audio")


def test_verify_secret_constant_time_and_empty_handling() -> None:
    assert verify_secret("2026", "2026") is True
    assert verify_secret("0000", "2026") is False
    assert verify_secret(None, "2026") is False
    assert verify_secret("2026", "") is False
