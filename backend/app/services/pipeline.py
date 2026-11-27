"""3-Tier async analysis pipeline with modular OCR, URL provenance isolation, and SSE streaming."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from app.config import Settings
from app.core.case_tokens import CaseOwnerChannel, generate_case_id, resolve_case_token_secret
from app.core.media_executors import (
    MediaExecutorBusyError,
    run_forensics_bounded,
    run_stt_bounded,
)
from app.core.media_security import detect_audio_format, detect_canonical_image_mime
from app.core.security import InvalidMediaError, UploadTooLargeError, validate_upload_bytes
from app.core.url_authority import has_disallowed_url_backslash
from app.db.repository import CaseRepository, redact_report_pii, strip_visual_blobs_copy
from app.schemas import (
    AnalysisReport,
    AnalyzeMode,
    BlockRule,
    DemoScenario,
    EvidenceItem,
    ExtractedIOCs,
    ImageForensicsResult,
    IocType,
    ReceiptLogicResult,
    SandboxInspection,
    ScamClassifierOutput,
    TraceStep,
    UrlFinding,
    VietQRInfo,
)
from app.services.action_copilot import build_action_bundle
from app.services.ai_orchestrator import run_gemini_reasoning
from app.services.guardrails import GuardrailResult, evaluate_guardrails
from app.services.image_forensics import analyze_image_forensics
from app.services.ioc_extractor import (
    MAX_EXTRACTED_URLS,
    extract_candidate_urls,
    extract_iocs,
    mask_ioc,
    normalize_ioc_value,
)
from app.services.knowledge_base import KnowledgeBaseRetriever
from app.services.local_stt import LocalSttResult, run_local_stt
from app.services.ocr import OcrBox, OcrOrchestrator, OcrResult
from app.services.phishing_detonator import detonate_url_in_sandbox
from app.services.receipt_validator import build_trusted_merchant_summary, validate_receipt_logic
from app.services.risk_calibrator import calibrate_risk
from app.services.scam_classifier import ScamClassifier
from app.services.url_inspector import inspect_url
from app.services.vietqr_parser import parse_qr_payload

MediaItem = tuple[bytes, str, str]  # (raw_bytes, filename, mime_type)
PersistenceMode = Literal["ephemeral_private", "persist_private_case", "persist_and_radar"]


@dataclass(frozen=True, slots=True)
class EphemeralAnalysisBundle:
    """Ephemeral supplementary analysis bundle with pre-hashed IOCs and zero raw PII/media."""

    live_report: AnalysisReport
    staged_redacted_report: AnalysisReport
    prehashed_iocs: list[dict[str, str]]
    replay_fingerprints: list[dict[str, str]]


class UnknownDemoError(KeyError):
    """Raised when a requested demo_id does not exist."""


_guard_merchant_summary = build_trusted_merchant_summary

_VERDICT_SHORT_VI: dict[str, str] = {
    "SAFE": "mức rủi ro thấp",
    "SUSPICIOUS": "cần thận trọng",
    "HIGH_RISK": "rủi ro cao",
    "CRITICAL_SCAM": "rủi ro rất cao",
}


def _dedupe_evidence(items: list[EvidenceItem]) -> list[EvidenceItem]:
    seen: set[tuple[str, str, str]] = set()
    out: list[EvidenceItem] = []
    for ev in items:
        key = (ev.source, ev.title, ev.detail)
        if key not in seen:
            seen.add(key)
            out.append(ev)
    return out


def _extract_safe_redirect_host(raw_url: str | None) -> str:
    """Extract canonical domain host from a redirect/final URL, skipping backslash-spoofed URLs."""
    if not raw_url or not raw_url.strip():
        return ""
    cleaned = raw_url.strip()
    if has_disallowed_url_backslash(cleaned):
        return ""
    return normalize_ioc_value("domain", cleaned)


def _prepend_unique_accounts(
    priority_accounts: list[str],
    existing: list[str],
) -> list[str]:
    """Prepend high-trust (VietQR/receipt) accounts ahead of free-text accounts, deduped."""
    merged: list[str] = []
    seen: set[str] = set()
    for acct in (*priority_accounts, *existing):
        cleaned = acct.strip()
        if not cleaned:
            continue
        norm = normalize_ioc_value("bank_account", cleaned) or cleaned
        if norm not in seen:
            seen.add(norm)
            merged.append(cleaned)
    return merged


def _compute_tier1_score(
    *,
    url_findings: list[UrlFinding],
    sandbox_res: SandboxInspection | None,
    img_forensics_list: list[ImageForensicsResult],
    receipt_logic: ReceiptLogicResult | None,
    vietqr_list: list[VietQRInfo],
    matched_pbs: list[dict[str, Any]],
    guardrails: GuardrailResult,
    clf_out: ScamClassifierOutput,
) -> int:
    """Compute deterministic Tier-1 score using max() across signals (no double-counting)."""
    tier1_score = 0
    if url_findings:
        tier1_score = max(tier1_score, max(u.risk_points for u in url_findings))
    if sandbox_res and (sandbox_res.available or sandbox_res.blocked_ssrf):
        tier1_score = max(tier1_score, sandbox_res.risk_points)
    if img_forensics_list:
        tier1_score = max(tier1_score, max(fr.tamper_score for fr in img_forensics_list))
    if receipt_logic:
        tier1_score = max(tier1_score, receipt_logic.logic_risk_points)
    if any(v.receive_scam_detected or v.beneficiary_mismatch for v in vietqr_list):
        tier1_score = max(tier1_score, 88)
    if (
        matched_pbs
        and not guardrails.safety_advisory_detected
        and (not clf_out.available or clf_out.scam_probability >= 0.45)
    ):
        tier1_score = max(tier1_score, min(85, 58 + 12 * len(matched_pbs)))
    return tier1_score


class AnalysisPipeline:
    """Coordinates Tier 1 (Security/Forensics/OCR/ONNX), Tier 2 (Gemini), and Tier 3 (Copilot/DB)."""

    def __init__(
        self,
        settings: Settings,
        repo: CaseRepository,
        *,
        case_token_secret: str | None = None,
    ) -> None:
        self.settings = settings
        self.repo = repo
        self.case_token_secret: str = (
            case_token_secret.strip()
            if case_token_secret and case_token_secret.strip()
            else resolve_case_token_secret(settings)
        )
        data_dir = Path(__file__).resolve().parent.parent / "data"
        self._data_dir = data_dir

        model_dir = Path(settings.model_dir)
        if not model_dir.is_absolute():
            model_dir = Path(__file__).resolve().parents[2] / settings.model_dir
        self.classifier = ScamClassifier(
            str(model_dir),
            intra_threads=settings.onnx_intra_threads,
        )
        self.ocr_orchestrator = OcrOrchestrator(settings=settings)

        emb_path = model_dir / "playbook_embeddings.npy"
        self.kb = KnowledgeBaseRetriever(
            str(data_dir / "vn_scam_kb.json"),
            embeddings_path=str(emb_path) if emb_path.exists() else None,
        )
        self._demos = self._load_demos()

    def _load_demos(self) -> dict[str, DemoScenario]:
        demo_file = self._data_dir / "demo_scenarios.json"
        if not demo_file.exists():
            return {}
        raw = json.loads(demo_file.read_text(encoding="utf-8"))
        return {item["demo_id"]: DemoScenario.model_validate(item) for item in raw}

    def list_demos(self) -> list[DemoScenario]:
        return list(self._demos.values())

    def _resolve_media_lists(
        self,
        *,
        image_bytes: bytes | None,
        image_filename: str,
        image_mime: str,
        audio_bytes: bytes | None,
        audio_filename: str,
        audio_mime: str,
        image_items: list[MediaItem] | None,
        audio_items: list[MediaItem] | None,
        prevalidated: bool = False,
    ) -> tuple[list[MediaItem], list[MediaItem]]:
        imgs: list[MediaItem] = list(image_items) if image_items else []
        if image_bytes is not None and not imgs:
            imgs.append((image_bytes, image_filename, image_mime))
        auds: list[MediaItem] = list(audio_items) if audio_items else []
        if audio_bytes is not None and not auds:
            auds.append((audio_bytes, audio_filename, audio_mime))

        if len(imgs) > self.settings.max_images_per_request:
            raise InvalidMediaError(
                f"Tối đa {self.settings.max_images_per_request} hình ảnh cho mỗi lần kiểm tra."
            )
        if len(auds) > self.settings.max_audios_per_request:
            raise InvalidMediaError(
                f"Tối đa {self.settings.max_audios_per_request} tệp ghi âm cho mỗi lần kiểm tra."
            )

        normalized_imgs: list[MediaItem] = []
        normalized_auds: list[MediaItem] = []
        total_bytes = 0
        for raw_b, fn, mime in imgs:
            if prevalidated:
                if not raw_b:
                    raise InvalidMediaError("Empty image payload.")
                if len(raw_b) > self.settings.max_upload_bytes:
                    raise UploadTooLargeError(
                        f"Upload size {len(raw_b)} bytes exceeds limit of "
                        f"{self.settings.max_upload_bytes} bytes."
                    )
            else:
                validate_upload_bytes(
                    raw_b, self.settings.max_upload_bytes, kind="image", declared_mime=mime
                )
            normalized_imgs.append((raw_b, fn, detect_canonical_image_mime(raw_b)))
            total_bytes += len(raw_b)
        for raw_b, fn, mime in auds:
            if prevalidated:
                if not raw_b:
                    raise InvalidMediaError("Empty audio payload.")
                if len(raw_b) > self.settings.max_upload_bytes:
                    raise UploadTooLargeError(
                        f"Upload size {len(raw_b)} bytes exceeds limit of "
                        f"{self.settings.max_upload_bytes} bytes."
                    )
                detected_aud = detect_audio_format(raw_b)
                if detected_aud is None:
                    raise InvalidMediaError("Unsupported or unrecognized audio container header.")
                normalized_auds.append((raw_b, fn, detected_aud[1]))
            else:
                validate_upload_bytes(
                    raw_b, self.settings.max_upload_bytes, kind="audio", declared_mime=mime
                )
                normalized_auds.append((raw_b, fn, mime))
            total_bytes += len(raw_b)
        if total_bytes > 2 * self.settings.max_upload_bytes:
            raise UploadTooLargeError("Tổng dung lượng các tệp đính kèm vượt quá giới hạn cho phép.")
        return normalized_imgs, normalized_auds

    async def stream(
        self,
        mode: AnalyzeMode = "personal",
        text: str = "",
        url: str | None = None,
        image_bytes: bytes | None = None,
        image_filename: str = "upload.jpg",
        image_mime: str = "image/jpeg",
        audio_bytes: bytes | None = None,
        audio_filename: str = "call.wav",
        audio_mime: str = "audio/wav",
        image_items: list[MediaItem] | None = None,
        audio_items: list[MediaItem] | None = None,
        demo_id: str | None = None,
        in_active_call: bool = False,
        is_simulation: bool = False,
        transfer_amount: int | None = None,
        expected_merchant_account: str | None = None,
        reference_now: datetime | None = None,
        case_id_override: str | None = None,
        owner_channel: CaseOwnerChannel = "web_token",
        owner_chat_hash: str | None = None,
        persistence_mode: PersistenceMode = "persist_and_radar",
        allow_external_media_ai: bool = True,
        is_demo_override: bool = False,
        media_prevalidated: bool = False,
        _ephemeral_out: list[EphemeralAnalysisBundle] | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Execute full 3-tier pipeline yielding live SSE trace steps and final AnalysisReport."""
        is_demo_fixture = bool(demo_id and demo_id.strip())
        is_demo = is_demo_fixture or is_demo_override
        effective_prevalidated = media_prevalidated and not is_demo_fixture
        if is_demo_fixture and demo_id is not None:
            key = demo_id.strip()
            if key not in self._demos:
                raise UnknownDemoError(f"Unknown demo_id: {key}")
            demo = self._demos[key]
            image_bytes = None
            audio_bytes = None
            image_items = None
            audio_items = None
            mode = demo.mode
            text = demo.text
            url = demo.url
            in_active_call = demo.in_active_call
            transfer_amount = demo.transfer_amount
            expected_merchant_account = demo.expected_merchant_account
            media_dir = self._data_dir / "demo_media"
            if demo.image_filename:
                img_path = media_dir / demo.image_filename
                image_bytes = img_path.read_bytes()
                image_filename = demo.image_filename
                image_mime = "image/png" if image_filename.endswith(".png") else "image/jpeg"
            if demo.audio_filename:
                aud_path = media_dir / demo.audio_filename
                audio_bytes = aud_path.read_bytes()
                audio_filename = demo.audio_filename
                audio_mime = "audio/wav"

        imgs, auds = await asyncio.to_thread(
            self._resolve_media_lists,
            image_bytes=image_bytes,
            image_filename=image_filename,
            image_mime=image_mime,
            audio_bytes=audio_bytes,
            audio_filename=audio_filename,
            audio_mime=audio_mime,
            image_items=image_items,
            audio_items=audio_items,
            prevalidated=effective_prevalidated,
        )

        if not text.strip() and not (url and url.strip()) and not imgs and not auds:
            raise InvalidMediaError("At least one non-empty evidence input is required.")

        trace: list[TraceStep] = []
        evidence: list[EvidenceItem] = []
        _ = transfer_amount

        # Step 1: Media Forensics, Modular OCR, Local STT & VietQR Decoding
        t_media = time.perf_counter()
        img_forensics_list: list[ImageForensicsResult] = []
        ocr_results: list[OcrResult] = []
        ocr_boxes_list: list[list[OcrBox]] = []
        vietqr_list: list[VietQRInfo] = []
        qr_urls: list[str] = []
        qr_text_parts: list[str] = []
        local_transcript: str | None = None

        forensics_failed = False
        if imgs:
            # Physical forensics + QR decoding in bounded chunks of <= 2 so multi-image uploads
            # never self-starve FORENSICS_EXECUTOR (max_workers=2).
            async def _run_single_forensics(
                raw_b: bytes, fn: str
            ) -> tuple[ImageForensicsResult, bool]:
                try:
                    res = await run_forensics_bounded(analyze_image_forensics, raw_b, fn, False)
                    return res, False
                except (MediaExecutorBusyError, TimeoutError):
                    return (
                        ImageForensicsResult(
                            filename=fn,
                            format="UNKNOWN",
                            width=1,
                            height=1,
                            dhash_hex="",
                        ),
                        True,
                    )

            forensics_raw: list[ImageForensicsResult] = []
            for start in range(0, len(imgs), 2):
                img_chunk = imgs[start : start + 2]
                chunk_out = await asyncio.gather(
                    *(_run_single_forensics(raw_b, fn) for raw_b, fn, _mime in img_chunk)
                )
                for fr_res, failed in chunk_out:
                    forensics_raw.append(fr_res)
                    if failed:
                        forensics_failed = True
            has_any_qr = any(bool(fr.qr_payloads) for fr in forensics_raw)
            is_image_only_no_qr = (
                not text.strip() and not (url and url.strip()) and not auds and not has_any_qr
            )
            ocr_results = await self.ocr_orchestrator.extract_batch(
                [(raw_b, mime) for raw_b, _fn, mime in imgs],
                allow_gemini_fallback=allow_external_media_ai,
                allow_empty_fallback=is_image_only_no_qr and allow_external_media_ai,
            )

            for fr, ocr_res in zip(forensics_raw, ocr_results, strict=True):
                merged_fr = fr.model_copy(
                    update={
                        "ocr_text": ocr_res.full_text,
                        "ocr_height_cv": ocr_res.height_cv,
                        "ocr_provider": ocr_res.provider,
                        "ocr_confidence": ocr_res.mean_confidence,
                        "ocr_status": ocr_res.status,
                    }
                )
                img_forensics_list.append(merged_fr)
                ocr_boxes_list.append(ocr_res.boxes)
                for reason in merged_fr.reasons:
                    evidence.append(
                        EvidenceItem(
                            source="image_forensics",
                            severity="HIGH" if merged_fr.tamper_score >= 45 else "MEDIUM",
                            title="Phát hiện dấu hiệu bất thường trên hình ảnh",
                            detail=reason,
                        )
                    )
                for raw_qr in merged_fr.qr_payloads:
                    vqr, vqr_ev = parse_qr_payload(
                        raw_qr,
                        accompanying_text=text,
                        expected_merchant_account=expected_merchant_account,
                    )
                    vietqr_list.append(vqr)
                    evidence.extend(vqr_ev)
                    if vqr.kind == "URL_QR":
                        qr_urls.append(vqr.raw)
                    elif vqr.kind == "TEXT_QR" and not vqr.raw.startswith("[VIETQR_INVALID_FRAME:"):
                        qr_urls.extend(extract_candidate_urls(vqr.raw))
                        if vqr.raw.strip():
                            qr_text_parts.append(vqr.raw.strip())

        stt_results: list[LocalSttResult] = []
        stt_timed_out = False
        if auds:
            stt_segments: list[str] = []
            for idx, (aud_b, aud_fn, _aud_mime) in enumerate(auds, start=1):
                try:
                    stt_res = await run_stt_bounded(
                        run_local_stt,
                        aud_b,
                        aud_fn,
                        self.settings.enable_local_stt,
                        timeout_sec=15.0,
                    )
                    stt_results.append(stt_res)
                    if stt_res.available and stt_res.transcript.strip():
                        seg = stt_res.transcript.strip()
                        stt_segments.append(f"[Ghi âm {idx}] {seg}" if len(auds) > 1 else seg)
                except (TimeoutError, MediaExecutorBusyError):
                    stt_timed_out = True
                    continue
            if stt_segments:
                local_transcript = "\n".join(stt_segments)

        img_forensics: ImageForensicsResult | None = (
            max(img_forensics_list, key=lambda item: (item.tamper_score, len(item.ocr_text)))
            if img_forensics_list
            else None
        )

        ocr_engine_failed = bool(
            self.settings.enable_local_ocr
            and any(r.status in ("timeout", "error", "unavailable") for r in ocr_results)
        )
        ocr_failed = ocr_engine_failed or forensics_failed
        ocr_unreadable_image_only = bool(
            imgs
            and self.settings.enable_local_ocr
            and not text.strip()
            and not (url and url.strip())
            and not qr_urls
            and not qr_text_parts
            and not local_transcript
            and all(r.status in ("empty", "timeout", "error", "unavailable") for r in ocr_results)
        )
        stt_failed = bool(
            auds
            and self.settings.enable_local_stt
            and (
                stt_timed_out
                or any(r.status in ("error", "unavailable") for r in stt_results)
            )
        )
        stt_unreadable_audio_only = bool(
            auds
            and self.settings.enable_local_stt
            and not text.strip()
            and not (url and url.strip())
            and not imgs
            and not local_transcript
            and (
                stt_timed_out
                or (
                    bool(stt_results)
                    and all(r.status in ("empty", "error", "unavailable") for r in stt_results)
                )
            )
        )
        if forensics_failed:
            evidence.append(
                EvidenceItem(
                    source="image_forensics",
                    severity="MEDIUM",
                    title="Không thể hoàn tất kiểm tra kỹ thuật hình ảnh",
                    detail=(
                        "Bộ phân tích kỹ thuật hình ảnh tạm thời bận hoặc quá thời gian trên ít "
                        "nhất một ảnh đính kèm, không được xem đây là kết luận an toàn."
                    ),
                )
            )
        if ocr_engine_failed:
            evidence.append(
                EvidenceItem(
                    source="ocr_engine",
                    severity="MEDIUM",
                    title="Không thể trích xuất đầy đủ văn bản từ hình ảnh",
                    detail=(
                        "Bộ trích xuất văn bản OCR gặp lỗi hoặc quá thời gian trên ít nhất một "
                        "hình ảnh đính kèm, không được xem đây là kết luận an toàn."
                    ),
                )
            )
        elif ocr_unreadable_image_only:
            evidence.append(
                EvidenceItem(
                    source="ocr_engine",
                    severity="MEDIUM",
                    title="Không đọc được nội dung văn bản từ hình ảnh",
                    detail=(
                        "Ảnh tải lên không trích xuất được văn bản rõ ràng và không kèm ngữ cảnh "
                        "bổ sung; hệ thống giữ mức thận trọng để tránh kết luận an toàn nhầm."
                    ),
                )
            )
        if stt_failed:
            evidence.append(
                EvidenceItem(
                    source="local_stt",
                    severity="MEDIUM",
                    title="Không thể chuyển đổi đầy đủ nội dung tệp ghi âm",
                    detail=(
                        "Bộ chuyển đổi giọng nói cục bộ gặp lỗi, chưa sẵn sàng hoặc quá thời gian "
                        "trên ít nhất một tệp ghi âm đính kèm, không được xem đây là kết luận an toàn."
                    ),
                )
            )
        elif stt_unreadable_audio_only:
            evidence.append(
                EvidenceItem(
                    source="local_stt",
                    severity="MEDIUM",
                    title="Không nhận diện được lời thoại rõ ràng từ tệp ghi âm",
                    detail=(
                        "Tệp ghi âm tải lên không trích xuất được lời thoại rõ ràng và không kèm ngữ "
                        "cảnh bổ sung; hệ thống giữ mức thận trọng để tránh kết luận an toàn nhầm."
                    ),
                )
            )

        media_step = TraceStep(
            step_id="media_forensics",
            title="Phân tích tính xác thực của hình ảnh, mã QR và ghi âm",
            status=(
                "warning"
                if (ocr_failed or stt_failed)
                else ("done" if (imgs or auds) else "skipped")
            ),
            detail=(
                f"Đã kiểm tra {len(imgs)} hình ảnh, {len(auds)} tệp ghi âm và {len(vietqr_list)} mã QR."
                if (imgs or auds)
                else "Không có hình ảnh hoặc tệp ghi âm đính kèm."
            ),
            duration_ms=int((time.perf_counter() - t_media) * 1000),
        )
        trace.append(media_step)
        yield {"event": "trace", "data": media_step.model_dump()}

        # Step 2: IOC Extraction (URL Provenance Split), Active Block Rules, URL Inspection & Sandbox
        t_sec = time.perf_counter()
        ocr_text_chunks = [fr.ocr_text.strip() for fr in img_forensics_list if fr.ocr_text.strip()]
        all_ocr_text = "\n".join(ocr_text_chunks)
        non_ocr_text = "\n".join(
            part for part in (text, "\n".join(qr_text_parts), local_transcript or "") if part.strip()
        )
        combined_text = "\n".join(part for part in (non_ocr_text, all_ocr_text) if part.strip())
        # Prepend explicit URL & QR URLs BEFORE non_ocr_text so long text cannot truncate them
        llm_body_parts: list[str] = []
        if url and url.strip():
            llm_body_parts.append(f"[URL_EXPLICIT]\n{url.strip()}")
        if qr_urls:
            llm_body_parts.append("[QR_URLS]\n" + "\n".join(qr_urls[:MAX_EXTRACTED_URLS]))
        if non_ocr_text:
            llm_body_parts.append(non_ocr_text)
        if all_ocr_text:
            llm_body_parts.append(f"[OCR_EXTRACTED_UNTRUSTED_TEXT]\n{all_ocr_text}")
        llm_input_text = "\n\n".join(llm_body_parts)

        user_direct_extra_urls = [url] if url and url.strip() else []
        direct_iocs = extract_iocs(text, extra_urls=user_direct_extra_urls)
        direct_url_set = set(direct_iocs.urls)
        extra_urls = [*user_direct_extra_urls, *qr_urls]
        iocs = extract_iocs(combined_text, extra_urls=extra_urls)
        untrusted_media_only_url_set = {u for u in iocs.urls if u not in direct_url_set}

        matched_rules: list[BlockRule] = self.repo.match_active_block_rules(iocs)
        block_hit = len(matched_rules) > 0
        if block_hit:
            evidence.append(
                EvidenceItem(
                    source="fraud_ops_radar",
                    severity="CRITICAL",
                    title="Trùng khớp danh sách chặn rủi ro của hệ thống",
                    detail=(
                        f"Dấu hiệu {matched_rules[0].masked_value} đang nằm trong danh sách chặn "
                        "trên toàn hệ thống."
                    ),
                )
            )

        vqr_accounts = [
            vqr.account_number.strip()
            for vqr in vietqr_list
            if vqr.account_number and vqr.account_number.strip()
        ]
        if vqr_accounts:
            iocs.bank_accounts = _prepend_unique_accounts(vqr_accounts, iocs.bank_accounts)
            vqr_rules = self.repo.match_active_block_rules(
                ExtractedIOCs(bank_accounts=vqr_accounts)
            )
            existing_vqr_rids = {r.rule_id for r in matched_rules}
            new_vqr_rules = [r for r in vqr_rules if r.rule_id not in existing_vqr_rids]
            if new_vqr_rules:
                matched_rules.extend(new_vqr_rules)
                block_hit = True
                evidence.append(
                    EvidenceItem(
                        source="fraud_ops_radar",
                        severity="CRITICAL",
                        title="Tài khoản trên mã VietQR trùng danh sách chặn",
                        detail=(
                            f"Số tài khoản {new_vqr_rules[0].masked_value} trên mã VietQR "
                            "đang nằm trong danh sách chặn của hệ thống."
                        ),
                    )
                )

        url_findings: list[UrlFinding] = []
        block_live_net_ephemeral = persistence_mode == "ephemeral_private"
        live_net_budget = 4
        candidate_urls = iocs.urls[:MAX_EXTRACTED_URLS]
        live_net_indices: set[int] = set()
        if self.settings.enable_live_network_checks and not block_live_net_ephemeral:
            non_official_indices: list[int] = []
            official_indices: list[int] = []
            for idx, cand_u in enumerate(candidate_urls):
                if cand_u in untrusted_media_only_url_set:
                    continue
                cand_host = _extract_safe_redirect_host(cand_u)
                if cand_host and self.repo.is_protected_ioc("domain", raw_value=cand_host):
                    official_indices.append(idx)
                else:
                    non_official_indices.append(idx)
            live_net_indices = set((*non_official_indices, *official_indices)[:live_net_budget])

        for idx, candidate_url in enumerate(candidate_urls):
            # Security invariant: NEVER auto-visit URLs extracted solely from OCR/QR/STT media,
            # and NEVER emit outbound URL visits in ephemeral_private mode (even with AI opt-in)!
            allow_net = idx in live_net_indices
            uf = await inspect_url(candidate_url, enable_network=allow_net)
            url_findings.append(uf)
            for reason in uf.reasons:
                evidence.append(
                    EvidenceItem(
                        source="url_inspector",
                        severity="CRITICAL" if uf.risk_points >= 75 else "HIGH",
                        title="Phát hiện rủi ro từ đường dẫn trang web",
                        detail=reason,
                        snippet=candidate_url[:140],
                    )
                )

        sandbox_res: SandboxInspection | None = None
        sandbox_eligible = [u for u in url_findings if u.url not in untrusted_media_only_url_set]
        if (
            sandbox_eligible
            and self.settings.enable_playwright_sandbox
            and persistence_mode != "ephemeral_private"
        ):
            top_u = max(sandbox_eligible, key=lambda item: item.risk_points)
            if top_u.risk_points >= 40 and not top_u.is_blocked_ssrf:
                sandbox_res = await detonate_url_in_sandbox(top_u.url, enabled=True)
                if (sandbox_res.available or sandbox_res.blocked_ssrf) and sandbox_res.risk_points > 0:
                    for s_reason in sandbox_res.reasons:
                        evidence.append(
                            EvidenceItem(
                                source="phishing_sandbox",
                                severity="CRITICAL" if sandbox_res.risk_points >= 75 else "HIGH",
                                title="Phát hiện trang web giả mạo trong môi trường cách ly",
                                detail=s_reason,
                            )
                        )

        initial_ioc_domains = {
            h for d in iocs.domains if (h := normalize_ioc_value("domain", d))
        }
        new_redirect_domains: list[str] = []
        fallback_redirect_domains: list[str] = []
        seen_redirect_domains: set[str] = set()

        def _add_redirect_host(raw_cand: str | None) -> None:
            host = _extract_safe_redirect_host(raw_cand)
            if not host or host in seen_redirect_domains:
                return
            seen_redirect_domains.add(host)
            if host not in initial_ioc_domains:
                new_redirect_domains.append(host)
            else:
                fallback_redirect_domains.append(host)

        if sandbox_res is not None:
            _add_redirect_host(sandbox_res.final_url)
        for uf in url_findings:
            _add_redirect_host(uf.final_url)
            for hop_dom in uf.redirect_domains:
                _add_redirect_host(hop_dom)
        for uf in url_findings:
            _add_redirect_host(uf.normalized_ascii_domain)
        redirect_domains = [*new_redirect_domains, *fallback_redirect_domains]
        if redirect_domains:
            redir_rules = self.repo.match_active_block_rules(
                ExtractedIOCs(domains=redirect_domains)
            )
            existing_rids = {r.rule_id for r in matched_rules}
            new_redir_rules = [r for r in redir_rules if r.rule_id not in existing_rids]
            if new_redir_rules:
                matched_rules.extend(new_redir_rules)
                block_hit = True
                evidence.append(
                    EvidenceItem(
                        source="fraud_ops_radar",
                        severity="CRITICAL",
                        title="Đích chuyển hướng trùng khớp danh sách chặn rủi ro",
                        detail=(
                            f"Tên miền đích {new_redir_rules[0].masked_value} sau chuyển hướng "
                            "đang nằm trong danh sách chặn trên toàn hệ thống."
                        ),
                    )
                )

        has_susp_url = any(u.risk_points > 0 or u.is_blocked_ssrf for u in url_findings)
        guardrails = evaluate_guardrails(
            combined_text,
            has_suspicious_url=has_susp_url,
            extra_urls=extra_urls,
        )
        if not guardrails.prompt_injection_detected and ocr_text_chunks:
            for chunk in ocr_text_chunks:
                chunk_guard = evaluate_guardrails(
                    chunk,
                    has_suspicious_url=has_susp_url,
                    extra_urls=extra_urls,
                )
                if chunk_guard.prompt_injection_detected:
                    guardrails = chunk_guard
                    break
        evidence.extend(guardrails.evidence)

        sec_warn = block_hit or has_susp_url or guardrails.prompt_injection_detected
        sec_step = TraceStep(
            step_id="cyber_guardrails",
            title="Kiểm tra đường dẫn đáng ngờ và danh sách chặn",
            status="warning" if sec_warn else "done",
            detail=(
                f"Ghi nhận {len(iocs.phones)} số điện thoại, {len(iocs.bank_accounts)} số tài khoản "
                f"và {len(url_findings)} đường dẫn."
            ),
            duration_ms=int((time.perf_counter() - t_sec) * 1000),
        )
        trace.append(sec_step)
        yield {"event": "trace", "data": sec_step.model_dump()}

        # Step 3: Dual-Head ONNX Classifier, Receipt Logic & Hybrid KB Retrieval
        t_onnx = time.perf_counter()
        clf_out, query_emb = await asyncio.to_thread(self.classifier.predict, combined_text)
        matched_pbs = self.kb.match_playbooks(
            combined_text,
            mode=mode,
            query_embedding=query_emb,
            top_k=3,
        )

        receipt_logic: ReceiptLogicResult | None = None
        receipt_dhash_for_save: str | None = None
        receipt_sha256_for_save: str | None = None
        receipt_priority_accounts: list[str] = []
        img_sha256_list: list[str] = [
            hashlib.sha256(raw_b).hexdigest() for raw_b, _fn, _mime in imgs
        ]
        if mode == "merchant" or img_forensics_list:
            candidate_pairs: list[
                tuple[ImageForensicsResult | None, str, list[OcrBox] | None, str | None]
            ] = (
                [
                    (fr, fr.ocr_text, boxes, sha_hex)
                    for fr, boxes, sha_hex in zip(
                        img_forensics_list, ocr_boxes_list, img_sha256_list, strict=True
                    )
                ]
                if img_forensics_list
                else [(None, text, None, None)]
            )
            evaluated_receipts: list[
                tuple[ReceiptLogicResult, ImageForensicsResult | None, str | None]
            ] = []
            for fr_item, src_txt, src_boxes, sha_hex in candidate_pairs:
                prelim = validate_receipt_logic(
                    ocr_text=src_txt,
                    ocr_boxes=src_boxes,
                    reference_now=reference_now,
                    expected_merchant_account=expected_merchant_account,
                    is_replayed_hash=False,
                    replay_checked=False,
                )
                replay_ref = prelim.reference_code if prelim.reference_valid else None
                has_replay_probe = bool((fr_item and fr_item.dhash_hex) or replay_ref)
                replay_lookup_ran = (
                    (not is_demo_fixture) and (not is_simulation) and has_replay_probe
                )
                if not replay_lookup_ran:
                    replayed = False
                else:
                    replayed = self.repo.is_receipt_replayed(
                        fr_item.dhash_hex if fr_item else None,
                        prelim.bank_detected,
                        replay_ref,
                    )
                rl_item = validate_receipt_logic(
                    ocr_text=src_txt,
                    ocr_boxes=src_boxes,
                    reference_now=reference_now,
                    expected_merchant_account=expected_merchant_account,
                    is_replayed_hash=replayed,
                    replay_checked=replay_lookup_ran,
                )
                evaluated_receipts.append((rl_item, fr_item, sha_hex))
                rcpt_acct = (rl_item.extracted_recipient_account or "").strip()
                if rcpt_acct:
                    receipt_priority_accounts.append(rcpt_acct)
                    iocs.bank_accounts = _prepend_unique_accounts([rcpt_acct], iocs.bank_accounts)
                    rcpt_rules = self.repo.match_active_block_rules(
                        ExtractedIOCs(bank_accounts=[rcpt_acct])
                    )
                    existing_rids = {r.rule_id for r in matched_rules}
                    new_rcpt_rules = [r for r in rcpt_rules if r.rule_id not in existing_rids]
                    if new_rcpt_rules:
                        matched_rules.extend(new_rcpt_rules)
                        block_hit = True
                        evidence.append(
                            EvidenceItem(
                                source="fraud_ops_radar",
                                severity="CRITICAL",
                                title="Tài khoản trên biên lai trùng danh sách chặn",
                                detail=(
                                    f"Số tài khoản nhận {new_rcpt_rules[0].masked_value} trên biên lai "
                                    "đang nằm trong danh sách chặn của hệ thống."
                                ),
                            )
                        )
                for r_reason in rl_item.reasons:
                    evidence.append(
                        EvidenceItem(
                            source="receipt_validator",
                            severity="CRITICAL" if rl_item.logic_risk_points >= 65 else "HIGH",
                            title="Phát hiện bất thường khi đối chiếu biên lai",
                            detail=r_reason,
                        )
                    )

            receipt_candidates = [pair for pair in evaluated_receipts if pair[0].is_receipt_candidate]
            if receipt_candidates:
                best_rl, best_fr, best_sha = max(
                    receipt_candidates,
                    key=lambda p: (
                        p[0].logic_risk_points,
                        int(p[0].is_replayed),
                        int(p[0].beneficiary_mismatch),
                    ),
                )
                receipt_logic = best_rl
                receipt_dhash_for_save = best_fr.dhash_hex if best_fr else None
                receipt_sha256_for_save = best_sha
            elif evaluated_receipts:
                receipt_logic = evaluated_receipts[0][0]

        onnx_step = TraceStep(
            step_id="onnx_and_kb",
            title="Đối chiếu nội dung với các kịch bản lừa đảo phổ biến",
            status="done",
            detail=(
                f"Đã phân loại ngữ cảnh và ghi nhận {len(matched_pbs)} kịch bản tương tự."
                if clf_out.available
                else f"Đã đối chiếu kho kịch bản ({len(matched_pbs)} kịch bản tương tự)."
            ),
            duration_ms=int((time.perf_counter() - t_onnx) * 1000),
        )
        trace.append(onnx_step)
        yield {"event": "trace", "data": onnx_step.model_dump()}

        # Compute deterministic Tier-1 score using max() across signals (no double-counting)
        tier1_score = _compute_tier1_score(
            url_findings=url_findings,
            sandbox_res=sandbox_res,
            img_forensics_list=img_forensics_list,
            receipt_logic=receipt_logic,
            vietqr_list=vietqr_list,
            matched_pbs=matched_pbs,
            guardrails=guardrails,
            clf_out=clf_out,
        )

        # Step 4: Tier-2 Multimodal Reasoning + Cloud-Transcript IOC Re-Check + Calibration
        t_llm = time.perf_counter()
        llm_images = [(raw_b, mime) for raw_b, _fn, mime in imgs] or None
        llm_audios = [(raw_b, mime) for raw_b, _fn, mime in auds] or None
        llm_res = await run_gemini_reasoning(
            settings=self.settings,
            text=llm_input_text or guardrails.normalized_text or combined_text,
            mode=mode,
            guardrails=guardrails,
            classifier=clf_out if clf_out.available else None,
            iocs=iocs,
            url_findings=url_findings,
            vietqr_findings=vietqr_list,
            image_forensics=img_forensics,
            receipt_logic=receipt_logic,
            matched_playbooks=matched_pbs,
            sandbox=sandbox_res,
            active_block_rule_hit=block_hit,
            image_bytes=(imgs[0][0] if (imgs and allow_external_media_ai) else None),
            image_mime=imgs[0][2] if imgs else "image/jpeg",
            audio_bytes=(auds[0][0] if (auds and allow_external_media_ai) else None),
            audio_mime=auds[0][2] if auds else "audio/wav",
            images=llm_images if allow_external_media_ai else None,
            audios=llm_audios if allow_external_media_ai else None,
            local_transcript=local_transcript,
            ocr_incomplete=(ocr_failed or ocr_unreadable_image_only),
            stt_incomplete=(stt_failed or stt_unreadable_audio_only),
            sanitize_egress_text=(persistence_mode == "ephemeral_private"),
            local_only=not allow_external_media_ai,
        )
        for vis_anom in llm_res.bill_visual_anomalies[:3]:
            evidence.append(
                EvidenceItem(
                    source="gemini_vision",
                    severity="HIGH",
                    title="Phát hiện điểm bất thường trên hình ảnh biên lai",
                    detail=vis_anom,
                )
            )

        if (
            auds
            and llm_res.transcript
            and llm_res.transcript.strip()
            and llm_res.transcript.strip() != (local_transcript or "").strip()
        ):
            cloud_transcript = llm_res.transcript.strip()
            enriched_text = f"{combined_text}\n{cloud_transcript}".strip()
            iocs = extract_iocs(enriched_text, extra_urls=extra_urls)
            post_rules = self.repo.match_active_block_rules(iocs)
            high_trust_accounts: list[str] = []
            if receipt_logic and receipt_logic.extracted_recipient_account:
                high_trust_accounts.append(receipt_logic.extracted_recipient_account)
            high_trust_accounts.extend(receipt_priority_accounts)
            high_trust_accounts.extend(vqr_accounts)
            if high_trust_accounts:
                iocs.bank_accounts = _prepend_unique_accounts(
                    high_trust_accounts, iocs.bank_accounts
                )
            existing_post_rids = {r.rule_id for r in matched_rules}
            new_post_rules = [r for r in post_rules if r.rule_id not in existing_post_rids]
            if new_post_rules:
                matched_rules.extend(new_post_rules)
                block_hit = True
                evidence.append(
                    EvidenceItem(
                        source="fraud_ops_radar",
                        severity="CRITICAL",
                        title="Thông tin trong cuộc gọi trùng danh sách chặn",
                        detail=(
                            f"Dấu hiệu {new_post_rules[0].masked_value} trong cuộc gọi "
                            "đang nằm trong danh sách chặn của hệ thống."
                        ),
                    )
                )

            existing_url_set = {u.url for u in url_findings}
            seen_t_url_hosts: set[str] = {
                h for u in url_findings if (h := _extract_safe_redirect_host(u.url))
            }
            primary_t_urls: list[str] = []
            secondary_t_urls: list[str] = []
            for cand_u in extract_candidate_urls(cloud_transcript):
                if cand_u in existing_url_set:
                    continue
                existing_url_set.add(cand_u)
                c_host = _extract_safe_redirect_host(cand_u)
                if not c_host or c_host not in seen_t_url_hosts:
                    if c_host:
                        seen_t_url_hosts.add(c_host)
                    primary_t_urls.append(cand_u)
                else:
                    secondary_t_urls.append(cand_u)
            new_transcript_urls = [*primary_t_urls, *secondary_t_urls][:4]
            transcript_url_domains: list[str] = []
            seen_t_doms = {
                h for d in iocs.domains if (h := normalize_ioc_value("domain", d))
            }
            for cand_u in new_transcript_urls:
                uf = await inspect_url(cand_u, enable_network=False)
                url_findings.append(uf)
                t_host = _extract_safe_redirect_host(uf.normalized_ascii_domain)
                if t_host and t_host not in seen_t_doms:
                    seen_t_doms.add(t_host)
                    transcript_url_domains.append(t_host)
                for reason in uf.reasons:
                    evidence.append(
                        EvidenceItem(
                            source="url_inspector",
                            severity="CRITICAL" if uf.risk_points >= 75 else "HIGH",
                            title="Phát hiện rủi ro từ đường dẫn trong nội dung cuộc gọi",
                            detail=reason,
                            snippet=cand_u[:140],
                        )
                    )
            if transcript_url_domains:
                t_url_rules = self.repo.match_active_block_rules(
                    ExtractedIOCs(domains=transcript_url_domains)
                )
                existing_t_rids = {r.rule_id for r in matched_rules}
                new_t_rules = [r for r in t_url_rules if r.rule_id not in existing_t_rids]
                if new_t_rules:
                    matched_rules.extend(new_t_rules)
                    block_hit = True
                    evidence.append(
                        EvidenceItem(
                            source="fraud_ops_radar",
                            severity="CRITICAL",
                            title="Thông tin trong cuộc gọi trùng danh sách chặn",
                            detail=(
                                f"Dấu hiệu {new_t_rules[0].masked_value} trong cuộc gọi "
                                "đang nằm trong danh sách chặn của hệ thống."
                            ),
                        )
                    )
            has_susp_url = any(u.risk_points > 0 or u.is_blocked_ssrf for u in url_findings)

            prev_inj = guardrails.prompt_injection_detected
            prev_inj_patterns = list(guardrails.matched_patterns) if prev_inj else []
            new_guardrails = evaluate_guardrails(
                enriched_text,
                has_suspicious_url=has_susp_url,
                extra_urls=extra_urls,
            )
            if prev_inj and not new_guardrails.prompt_injection_detected:
                new_guardrails = new_guardrails.model_copy(
                    update={
                        "prompt_injection_detected": True,
                        "safety_advisory_detected": False,
                        "advisory_vetoed": True,
                        "matched_patterns": prev_inj_patterns,
                        "evidence": [],
                    }
                )
            guardrails = new_guardrails
            if not guardrails.safety_advisory_detected:
                evidence = [
                    ev
                    for ev in evidence
                    if not (ev.source == "guardrails" and ev.severity == "INFO")
                ]
            evidence.extend(guardrails.evidence)

            clf_out, query_emb = await asyncio.to_thread(self.classifier.predict, enriched_text)
            matched_pbs = self.kb.match_playbooks(
                enriched_text,
                mode=mode,
                query_embedding=query_emb,
                top_k=3,
            )
            tier1_score = _compute_tier1_score(
                url_findings=url_findings,
                sandbox_res=sandbox_res,
                img_forensics_list=img_forensics_list,
                receipt_logic=receipt_logic,
                vietqr_list=vietqr_list,
                matched_pbs=matched_pbs,
                guardrails=guardrails,
                clf_out=clf_out,
            )

        cal = calibrate_risk(
            mode=mode,
            tier1_score=tier1_score,
            classifier=clf_out if clf_out.available else None,
            ai_score=llm_res.ai_score,
            guardrails=guardrails,
            url_findings=url_findings,
            vietqr_findings=vietqr_list,
            sandbox=sandbox_res,
            image_forensics=img_forensics,
            receipt_logic=receipt_logic,
            active_block_rule_hit=block_hit,
            in_active_call=in_active_call,
            has_visual_bill_anomaly=bool(llm_res.bill_visual_anomalies),
            ocr_failed=ocr_failed,
            ocr_unreadable_image_only=ocr_unreadable_image_only,
            stt_failed=stt_failed,
            stt_unreadable_audio_only=stt_unreadable_audio_only,
        )
        actions = build_action_bundle(
            mode=mode,
            verdict=cal.verdict,
            risk_score=cal.final_score,
            in_active_call=in_active_call,
            active_block_rule_hit=block_hit,
            receipt_status=cal.receipt_verification_status,
            matched_playbooks=matched_pbs,
            llm_result=llm_res,
        )
        ocr_incomplete_final = (ocr_failed or ocr_unreadable_image_only) and llm_res.degraded_mode
        safe_summary = _guard_merchant_summary(
            llm_res.summary_vi,
            mode=mode,
            receipt_status=cal.receipt_verification_status,
            has_qr_beneficiary_mismatch=any(v.beneficiary_mismatch for v in vietqr_list),
            has_ocr_beneficiary_mismatch=bool(
                receipt_logic and receipt_logic.beneficiary_mismatch
            ),
            ocr_incomplete=ocr_incomplete_final,
        )

        verdict_vi = _VERDICT_SHORT_VI.get(cal.verdict, "đã đánh giá")
        fallback_note = " · chế độ phân tích nhanh nội bộ" if llm_res.degraded_mode else ""
        llm_step = TraceStep(
            step_id="multimodal_calibration",
            title="Tổng hợp bằng chứng và đánh giá mức độ rủi ro",
            status="warning" if llm_res.degraded_mode else "done",
            detail=f"Mức độ rủi ro: {cal.final_score}/100 ({verdict_vi}){fallback_note}",
            duration_ms=int((time.perf_counter() - t_llm) * 1000),
        )
        trace.append(llm_step)
        yield {"event": "trace", "data": llm_step.model_dump()}

        comm_hits = 0 if is_simulation else self.repo.count_ioc_hits(iocs)
        raw_report = AnalysisReport(
            case_id=case_id_override or generate_case_id(),
            created_at=datetime.now(UTC).isoformat(),
            mode=mode,
            in_active_call=in_active_call,
            risk_score=cal.final_score,
            verdict=cal.verdict,
            confidence=cal.confidence,
            degraded_mode=llm_res.degraded_mode,
            safety_advisory_detected=guardrails.safety_advisory_detected,
            prompt_injection_detected=guardrails.prompt_injection_detected,
            active_block_rule_hit=block_hit,
            matched_block_rules=matched_rules,
            is_simulation=is_simulation,
            receipt_verification_status=cal.receipt_verification_status,
            summary_vi=safe_summary,
            transcript=llm_res.transcript if auds else None,
            classifier=clf_out if clf_out.available else None,
            matched_playbooks=[str(pb["name_vi"]) for pb in matched_pbs],
            manipulation_tactics=llm_res.manipulation_tactics
            or [t for pb in matched_pbs[:2] for t in pb.get("psychological_tactics", [])[:2]],
            highlighted_phrases=llm_res.highlighted_phrases,
            iocs=iocs,
            vietqr_findings=vietqr_list,
            url_findings=url_findings,
            sandbox=sandbox_res,
            image_forensics=img_forensics,
            image_forensics_list=img_forensics_list,
            receipt_logic=receipt_logic,
            evidence=_dedupe_evidence(evidence),
            actions=actions,
            trace=trace,
            community_hits=comm_hits,
            llm_provider=llm_res.llm_provider,
            llm_model=llm_res.llm_model,
            llm_latency_ms=llm_res.llm_latency_ms,
            llm_attempts=llm_res.llm_attempts,
            llm_failed_attempts=llm_res.llm_failed_attempts,
            llm_error=llm_res.llm_error,
        )
        if is_simulation or persistence_mode == "ephemeral_private":
            # Zero DB writes; compute pre-hashed IOCs & replay fingerprints BEFORE redact_report_pii
            prehashed_iocs = self._build_prehashed_iocs(raw_report)
            replay_fps = self._build_replay_fingerprints(
                receipt_logic=receipt_logic,
                receipt_dhash=receipt_dhash_for_save,
                receipt_sha256=receipt_sha256_for_save,
            )
            saved_report = redact_report_pii(raw_report, strip_visual_blobs=False)
            if _ephemeral_out is not None:
                staged_redacted = strip_visual_blobs_copy(saved_report)
                _ephemeral_out.append(
                    EphemeralAnalysisBundle(
                        live_report=saved_report,
                        staged_redacted_report=staged_redacted,
                        prehashed_iocs=prehashed_iocs,
                        replay_fingerprints=replay_fps,
                    )
                )
        elif persistence_mode == "persist_private_case":
            saved_report = self.repo.save_report(
                raw_report,
                receipt_dhash=None,
                track_replay=False,
                owner_channel=owner_channel,
                owner_chat_hash=owner_chat_hash,
                contributes_to_radar=False,
                is_demo=is_demo,
            )
        else:
            saved_report = self.repo.save_report(
                raw_report,
                receipt_dhash=(
                    receipt_dhash_for_save
                    if (receipt_dhash_for_save and receipt_logic and receipt_logic.is_receipt_candidate)
                    else None
                ),
                track_replay=(
                    (not is_demo)
                    and bool(imgs)
                    and bool(receipt_logic and receipt_logic.is_receipt_candidate)
                ),
                owner_channel=owner_channel,
                owner_chat_hash=owner_chat_hash,
                contributes_to_radar=not is_demo,
                is_demo=is_demo,
            )
        yield {"event": "result", "data": saved_report.model_dump()}

    def _build_prehashed_iocs(self, raw_report: AnalysisReport) -> list[dict[str, str]]:
        """Pre-compute keyed HMAC hashes & masked previews before PII redaction (0 raw PII)."""
        seen: set[str] = set()
        out: list[dict[str, str]] = []
        candidates: list[tuple[IocType, str]] = [
            *[("phone", ph) for ph in raw_report.iocs.phones],
            *[("bank_account", acct) for acct in raw_report.iocs.bank_accounts],
            *[("domain", dom) for dom in raw_report.iocs.domains],
        ]
        for vqr in raw_report.vietqr_findings:
            if vqr.account_number:
                candidates.append(("bank_account", vqr.account_number))
        if raw_report.receipt_logic and raw_report.receipt_logic.extracted_recipient_account:
            candidates.append(("bank_account", raw_report.receipt_logic.extracted_recipient_account))

        for ioc_type, raw_val in candidates:
            cleaned = raw_val.strip()
            if not cleaned or "****" in cleaned or not normalize_ioc_value(ioc_type, cleaned):
                continue
            if self.repo.is_protected_ioc(ioc_type, raw_value=cleaned):
                continue
            h = self.repo.hash_ioc_value(ioc_type, cleaned)
            if h in seen:
                continue
            seen.add(h)
            out.append(
                {
                    "ioc_type": ioc_type,
                    "ioc_hash": h,
                    "masked_value": mask_ioc(ioc_type, cleaned),
                }
            )
        return out

    def _build_replay_fingerprints(
        self,
        *,
        receipt_logic: ReceiptLogicResult | None,
        receipt_dhash: str | None,
        receipt_sha256: str | None,
    ) -> list[dict[str, str]]:
        """Collect pre-computed receipt replay hashes without retaining raw image bytes."""
        out: list[dict[str, str]] = []
        if not (receipt_dhash and receipt_logic and receipt_logic.is_receipt_candidate):
            return out
        entry: dict[str, str] = {
            "kind": "dhash",
            "fingerprint": f"dhash:{receipt_dhash}",
            "phash": receipt_dhash,
        }
        if receipt_sha256:
            entry["sha256"] = receipt_sha256
        out.append(entry)
        if receipt_logic.reference_valid and receipt_logic.reference_code:
            ref_code = receipt_logic.reference_code.strip()
            out.append(
                {
                    "kind": "ref",
                    "fingerprint": self.repo.hash_receipt_ref_fingerprint(
                        receipt_logic.bank_detected,
                        ref_code,
                    ),
                }
            )
        return out

    async def run_ephemeral(
        self,
        *,
        mode: AnalyzeMode = "personal",
        text: str = "",
        url: str | None = None,
        image_bytes: bytes | None = None,
        image_filename: str = "upload.jpg",
        image_mime: str = "image/jpeg",
        audio_bytes: bytes | None = None,
        audio_filename: str = "call.wav",
        audio_mime: str = "audio/wav",
        image_items: list[MediaItem] | None = None,
        audio_items: list[MediaItem] | None = None,
        in_active_call: bool = False,
        expected_merchant_account: str | None = None,
        reference_now: datetime | None = None,
        allow_external_media_ai: bool = False,
        is_demo: bool = False,
        media_prevalidated: bool = False,
    ) -> EphemeralAnalysisBundle:
        """Execute ephemeral_private analysis with 0 DB writes and local-only media default."""
        collector: list[EphemeralAnalysisBundle] = []
        async for _item in self.stream(
            mode=mode,
            text=text,
            url=url,
            image_bytes=image_bytes,
            image_filename=image_filename,
            image_mime=image_mime,
            audio_bytes=audio_bytes,
            audio_filename=audio_filename,
            audio_mime=audio_mime,
            image_items=image_items,
            audio_items=audio_items,
            in_active_call=in_active_call,
            is_simulation=False,
            expected_merchant_account=expected_merchant_account,
            reference_now=reference_now,
            persistence_mode="ephemeral_private",
            allow_external_media_ai=allow_external_media_ai,
            is_demo_override=is_demo,
            media_prevalidated=media_prevalidated,
            _ephemeral_out=collector,
        ):
            pass
        if not collector:
            raise RuntimeError("Ephemeral pipeline completed without producing a bundle.")
        return collector[-1]

    async def run(self, *, media_prevalidated: bool = False, **kwargs: Any) -> AnalysisReport:
        """Execute full pipeline and return the final persisted AnalysisReport."""
        final_data: dict[str, Any] | None = None
        async for item in self.stream(media_prevalidated=media_prevalidated, **kwargs):
            if item["event"] == "result":
                final_data = item["data"]
        if final_data is None:
            raise RuntimeError("Pipeline completed without emitting a result event.")
        return AnalysisReport.model_validate(final_data)
