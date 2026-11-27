"""Media upload validation, magic-header allowlists, bounded audio decoding, and image canonicalization."""

from __future__ import annotations

import io
import warnings
from typing import Any, Final, Literal

import av
import numpy as np
from numpy.typing import NDArray
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_DECOMPRESSED_PIXELS: Final[int] = 25_000_000
MAX_IMAGE_DIMENSION: Final[int] = 10_000
MAX_DECODED_AUDIO_SAMPLES: Final[int] = 48_000 * 600  # Max 10 minutes at 48kHz
MAX_AUDIO_CHANNELS: Final[int] = 8
MIN_AUDIO_SAMPLE_RATE: Final[int] = 8_000
MAX_AUDIO_SAMPLE_RATE: Final[int] = 192_000
MAX_AUDIO_DURATION_SEC: Final[float] = 600.0
MAX_RESAMPLED_PCM16K_SAMPLES: Final[int] = 16_000 * 600  # 9_600_000 (10 min at 16kHz)

_ALLOWED_IMAGE_MIMES: Final[frozenset[str]] = frozenset(
    {"image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif", "application/octet-stream"}
)
_ALLOWED_AUDIO_MIMES: Final[frozenset[str]] = frozenset(
    {
        "audio/wav", "audio/x-wav", "audio/wave", "audio/mpeg", "audio/mp3", "audio/mp4",
        "audio/x-m4a", "audio/m4a", "audio/ogg", "audio/webm", "audio/flac", "audio/x-flac",
        "application/octet-stream",
    }
)
_IMAGE_DECODE_ERRORS: Final[tuple[type[BaseException], ...]] = (
    UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning,
    OSError, ValueError, SyntaxError,
)


class UploadTooLargeError(ValueError):
    """Raised when uploaded media exceeds configured max_upload_bytes (HTTP 413)."""


class InvalidMediaError(ValueError):
    """Raised when uploaded media is empty, corrupt, or fails container decoding (HTTP 400)."""


def _is_valid_mp3_frame_sync(data: bytes) -> bool:
    """Return True if data begins with a valid 4-byte MPEG audio frame sync header."""
    if len(data) < 4 or data[0] != 0xFF or (data[1] & 0xE0) != 0xE0:
        return False
    version, layer = (data[1] >> 3) & 0x03, (data[1] >> 1) & 0x03
    bitrate_idx, sample_rate_idx = (data[2] >> 4) & 0x0F, (data[2] >> 2) & 0x03
    return version != 0x01 and layer != 0x00 and bitrate_idx not in (0x00, 0x0F) and sample_rate_idx != 0x03


def detect_audio_format(data: bytes) -> tuple[str, str] | None:
    """Detect allowlisted audio container via magic bytes -> (pyav_format, canonical_mime)."""
    if len(data) < 12:
        return None
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "wav", "audio/wav"
    if data.startswith(b"OggS"):
        return "ogg", "audio/ogg"
    if data.startswith(b"fLaC"):
        return "flac", "audio/flac"
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return "matroska", "audio/webm"
    if data[4:8] == b"ftyp":
        box_size = int.from_bytes(data[:4], "big")
        if 12 <= box_size <= 4096 and all(32 <= b <= 126 for b in data[8:12]):
            return "mp4", "audio/mp4"
        return None
    if (
        data.startswith(b"ID3")
        and data[3] < 0xFF
        and data[4] < 0xFF
        and all(b < 0x80 for b in data[6:10])
    ) or _is_valid_mp3_frame_sync(data):
        return "mp3", "audio/mpeg"
    return None


def _decode_audio_core(data: bytes, *, collect_pcm16k: bool) -> NDArray[np.float32] | None:
    if len(data) < 12:
        raise InvalidMediaError("Audio payload too short.")
    detected = detect_audio_format(data)
    if detected is None:
        raise InvalidMediaError("Unsupported or unrecognized audio container header.")
    av_fmt, _canonical_mime = detected

    try:
        with av.open(
            io.BytesIO(data), mode="r", format=av_fmt, options={"protocol_whitelist": "crypto,data"}
        ) as container:
            attached_pic = av.stream.Disposition.attached_pic
            if any(not (s.disposition & attached_pic) for s in container.streams.video):
                raise InvalidMediaError("Video streams are not allowed in audio uploads.")
            if not container.streams.audio:
                raise InvalidMediaError("Container has no audio streams.")
            stream = container.streams.audio[0]
            channels = int(getattr(stream, "channels", 1) or 1)
            if channels <= 0 or channels > MAX_AUDIO_CHANNELS:
                raise InvalidMediaError(f"Audio channel count {channels} exceeds limit.")
            stream_rate = int(getattr(stream, "rate", 0) or 0)
            if stream_rate != 0 and not (
                MIN_AUDIO_SAMPLE_RATE <= stream_rate <= MAX_AUDIO_SAMPLE_RATE
            ):
                raise InvalidMediaError(
                    f"Audio sample rate {stream_rate} Hz is outside allowed range "
                    f"({MIN_AUDIO_SAMPLE_RATE}-{MAX_AUDIO_SAMPLE_RATE} Hz)."
                )

            resampler = (
                av.AudioResampler(format="s16", layout="mono", rate=16000) if collect_pcm16k else None
            )
            pcm_chunks: list[NDArray[np.int16]] = []
            total_samples, total_ch_samples, max_ch_samples = 0, 0, MAX_DECODED_AUDIO_SAMPLES * 2
            total_duration_sec = 0.0
            total_pcm16k_samples = 0

            for frame in container.decode(audio=0):
                frame_samples = int(frame.samples)
                frame_ch = int(getattr(getattr(frame, "layout", None), "nb_channels", channels) or channels)
                if frame_ch <= 0 or frame_ch > MAX_AUDIO_CHANNELS:
                    raise InvalidMediaError(f"Audio frame channel count {frame_ch} exceeds limit.")
                frame_rate = int(getattr(frame, "sample_rate", 0) or stream_rate or 0)
                if not (MIN_AUDIO_SAMPLE_RATE <= frame_rate <= MAX_AUDIO_SAMPLE_RATE):
                    raise InvalidMediaError(
                        f"Audio frame sample rate {frame_rate} Hz is outside allowed range "
                        f"({MIN_AUDIO_SAMPLE_RATE}-{MAX_AUDIO_SAMPLE_RATE} Hz)."
                    )
                total_samples += frame_samples
                total_ch_samples += frame_samples * frame_ch
                total_duration_sec += frame_samples / frame_rate
                if (
                    total_samples > MAX_DECODED_AUDIO_SAMPLES
                    or total_ch_samples > max_ch_samples
                    or total_duration_sec > MAX_AUDIO_DURATION_SEC
                ):
                    raise InvalidMediaError("Audio duration exceeds maximum safe decoding budget.")
                if resampler is not None:
                    for rf in resampler.resample(frame):
                        out_arr = np.asarray(rf.to_ndarray(), dtype=np.int16).reshape(-1)
                        total_pcm16k_samples += out_arr.size
                        if total_pcm16k_samples > MAX_RESAMPLED_PCM16K_SAMPLES:
                            raise InvalidMediaError("Resampled audio exceeds maximum safe PCM budget.")
                        pcm_chunks.append(out_arr)

            if total_samples <= 0:
                raise InvalidMediaError("Audio stream contains zero decodable frames.")
            if resampler is None:
                return None

            for rf in resampler.resample(None):
                out_arr = np.asarray(rf.to_ndarray(), dtype=np.int16).reshape(-1)
                total_pcm16k_samples += out_arr.size
                if total_pcm16k_samples > MAX_RESAMPLED_PCM16K_SAMPLES:
                    raise InvalidMediaError("Resampled audio exceeds maximum safe PCM budget.")
                pcm_chunks.append(out_arr)
            if not pcm_chunks:
                raise InvalidMediaError("Audio stream produced zero resampled PCM samples.")
            pcm_i16 = np.concatenate(pcm_chunks)
            return pcm_i16.astype(np.float32) / np.float32(32768.0)
    except InvalidMediaError:
        raise
    except Exception as exc:
        raise InvalidMediaError(f"Corrupt or undecodable audio payload: {exc}") from exc


def _verify_decodable_audio(data: bytes) -> None:
    _decode_audio_core(data, collect_pcm16k=False)


def decode_audio_to_pcm16k(data: bytes) -> NDArray[np.float32]:
    """Safely decode allowlisted audio bytes in-memory to 1D 16kHz mono float32 PCM."""
    pcm = _decode_audio_core(data, collect_pcm16k=True)
    if pcm is None or pcm.size == 0:
        raise InvalidMediaError("Audio decoding produced empty PCM buffer.")
    return pcm


def detect_canonical_image_mime(data: bytes) -> str:
    """Return canonical image MIME type strictly from binary magic header."""
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data.startswith(b"RIFF"):
        if len(data) >= 12 and data[8:12] == b"WEBP":
            return "image/webp"
        raise InvalidMediaError("RIFF container is not a valid WEBP image.")
    raise InvalidMediaError("Unsupported image header; expected JPEG, PNG, WEBP, or GIF.")


def _check_image_bounds_and_frames(img: Any) -> None:
    w, h = int(img.size[0]), int(img.size[1])
    if w <= 0 or h <= 0 or max(w, h) > MAX_IMAGE_DIMENSION or (w * h) > MAX_DECOMPRESSED_PIXELS:
        raise InvalidMediaError("Image dimensions invalid or exceed pixel-bomb threshold.")
    if bool(getattr(img, "is_animated", False)) or int(getattr(img, "n_frames", 1) or 1) > 1:
        raise InvalidMediaError("Animated or multi-frame images are not supported.")


def _decode_validated_rgb_image(data: bytes) -> tuple[Image.Image, str]:
    if not data:
        raise InvalidMediaError("Empty image payload.")
    canonical_mime = detect_canonical_image_mime(data)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as img:
                _check_image_bounds_and_frames(img)
                img.load()
                return ImageOps.exif_transpose(img).convert("RGB"), canonical_mime
    except _IMAGE_DECODE_ERRORS as exc:
        if isinstance(exc, InvalidMediaError):
            raise
        raise InvalidMediaError(f"Corrupt or unsafe image file: {exc}") from exc


def decode_image_to_rgb_array(data: bytes) -> NDArray[np.uint8]:
    """Decode validated single-frame image via Pillow with EXIF transpose into an RGB uint8 array."""
    rgb_img, _mime = _decode_validated_rgb_image(data)
    return np.asarray(rgb_img, dtype=np.uint8)


def normalize_image_for_downstream(data: bytes) -> tuple[bytes, str]:
    """Validate single-frame image and re-encode clean RGB bytes without EXIF or polyglot tails."""
    rgb_img, canonical_mime = _decode_validated_rgb_image(data)
    out = io.BytesIO()
    if canonical_mime == "image/jpeg":
        rgb_img.save(out, format="JPEG", quality=92)
        return out.getvalue(), "image/jpeg"
    rgb_img.save(out, format="PNG")
    return out.getvalue(), "image/png"


def validate_upload_bytes(
    data: bytes, max_bytes: int, kind: Literal["image", "audio"], declared_mime: str | None = None
) -> None:
    """Enforce upload byte ceiling, MIME/magic checks, full pixel/frame decoding, and bomb caps."""
    if not data:
        raise InvalidMediaError(f"Empty {kind} payload.")
    if len(data) > max_bytes:
        raise UploadTooLargeError(f"Upload size {len(data)} bytes exceeds limit of {max_bytes} bytes.")

    if declared_mime is not None:
        clean_mime = declared_mime.split(";", 1)[0].strip().lower()
        allowed_mimes = _ALLOWED_IMAGE_MIMES if kind == "image" else _ALLOWED_AUDIO_MIMES
        if not clean_mime or clean_mime not in allowed_mimes:
            raise InvalidMediaError(f"Unsupported declared MIME type for {kind}: {declared_mime!r}.")

    if kind == "audio":
        _verify_decodable_audio(data)
        return

    detect_canonical_image_mime(data)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as img:
                _check_image_bounds_and_frames(img)
                img.verify()
            with Image.open(io.BytesIO(data)) as decoded_img:
                _check_image_bounds_and_frames(decoded_img)
                decoded_img.load()
    except _IMAGE_DECODE_ERRORS as exc:
        if isinstance(exc, InvalidMediaError):
            raise
        raise InvalidMediaError(f"Corrupt or unsafe image file: {exc}") from exc
