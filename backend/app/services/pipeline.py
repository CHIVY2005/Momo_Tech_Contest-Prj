"""3-Tier async analysis pipeline with modular OCR, URL provenance isolation, and SSE streaming."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import Settings
from app.core.security import InvalidMediaError, UploadTooLargeError, validate_upload_bytes
from app.db.repository import CaseRepository, redact_report_pii
from app.schemas import (
    AnalysisReport,
    AnalyzeMode,
    BlockRule,
    DemoScenario,
    EvidenceItem,
    ImageForensicsResult,
    ReceiptLogicResult,
    SandboxInspection,
    TraceStep,
    UrlFinding,
    VietQRInfo,
)
from app.services.action_copilot import build_action_bundle
from app.services.ai_orchestrator import run_gemini_reasoning
from app.services.guardrails import evaluate_guardrails
from app.services.image_forensics import analyze_image_forensics
from app.services.ioc_extractor import extract_candidate_urls, extract_iocs
from app.services.knowledge_base import KnowledgeBaseRetriever
from app.services.local_stt import run_local_stt
from app.services.ocr import OcrBox, OcrOrchestrator, OcrResult
from app.services.phishing_detonator import detonate_url_in_sandbox
from app.services.receipt_validator import build_trusted_merchant_summary, validate_receipt_logic
from app.services.risk_calibrator import calibrate_risk
from app.services.scam_classifier import ScamClassifier
from app.services.url_inspector import inspect_url
from app.services.vietqr_parser import parse_qr_payload

MediaItem = tuple[bytes, str, str]  # (raw_bytes, filename, mime_type)


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


class AnalysisPipeline:
    """Coordinates Tier 1 (Security/Forensics/OCR/ONNX), Tier 2 (Gemini), and Tier 3 (Copilot/DB)."""

    def __init__(self, settings: Settings, repo: CaseRepository) -> None:
        self.settings = settings
        self.repo = repo
        data_dir = Path(__file__).resolve().parent.parent / "data"
        self._data_dir = data_dir

        model_dir = Path(settings.model_dir)
        if not model_dir.is_absolute():
            model_dir = Path(__file__).resolve().parents[2] / settings.model_dir
        self.classifier = ScamClassifier(str(model_dir))
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

        total_bytes = 0
        for raw_b, _fn, mime in imgs:
            validate_upload_bytes(
                raw_b, self.settings.max_upload_bytes, kind="image", declared_mime=mime
            )
            total_bytes += len(raw_b)
        for raw_b, _fn, mime in auds:
            validate_upload_bytes(
                raw_b, self.settings.max_upload_bytes, kind="audio", declared_mime=mime
            )
            total_bytes += len(raw_b)
        if total_bytes > 2 * self.settings.max_upload_bytes:
            raise UploadTooLargeError("Tổng dung lượng các tệp đính kèm vượt quá giới hạn cho phép.")
        return imgs, auds

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
    ) -> AsyncIterator[dict[str, Any]]:
        """Execute full 3-tier pipeline yielding live SSE trace steps and final AnalysisReport."""
        is_demo = bool(demo_id and demo_id.strip())
        if is_demo and demo_id is not None:
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

        imgs, auds = self._resolve_media_lists(
            image_bytes=image_bytes,
            image_filename=image_filename,
            image_mime=image_mime,
            audio_bytes=audio_bytes,
            audio_filename=audio_filename,
            audio_mime=audio_mime,
            image_items=image_items,
            audio_items=audio_items,
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

        if imgs:
            # Physical forensics + QR decoding first so we know if image-only has no QR before OCR fallback
            forensics_raw = await asyncio.gather(
                *(
                    asyncio.to_thread(analyze_image_forensics, raw_b, fn, False)
                    for raw_b, fn, _mime in imgs
                )
            )
            has_any_qr = any(bool(fr.qr_payloads) for fr in forensics_raw)
            is_image_only_no_qr = (
                not text.strip() and not (url and url.strip()) and not auds and not has_any_qr
            )
            ocr_results = await self.ocr_orchestrator.extract_batch(
                [(raw_b, mime) for raw_b, _fn, mime in imgs],
                allow_empty_fallback=is_image_only_no_qr,
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

        if auds:
            stt_segments: list[str] = []
            for idx, (aud_b, aud_fn, _aud_mime) in enumerate(auds, start=1):
                try:
                    stt_res = await asyncio.wait_for(
                        asyncio.to_thread(
                            run_local_stt,
                            aud_b,
                            aud_fn,
                            self.settings.enable_local_stt,
                        ),
                        timeout=15.0,
                    )
                    if stt_res.available and stt_res.transcript.strip():
                        seg = stt_res.transcript.strip()
                        stt_segments.append(f"[Ghi âm {idx}] {seg}" if len(auds) > 1 else seg)
                except TimeoutError:
                    continue
            if stt_segments:
                local_transcript = "\n".join(stt_segments)

        img_forensics: ImageForensicsResult | None = (
            max(img_forensics_list, key=lambda item: (item.tamper_score, len(item.ocr_text)))
            if img_forensics_list
            else None
        )

        ocr_failed = bool(
            self.settings.enable_local_ocr
            and any(r.status in ("timeout", "error", "unavailable") for r in ocr_results)
        )
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
        if ocr_failed:
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

        media_step = TraceStep(
            step_id="media_forensics",
            title="Phân tích tính xác thực của hình ảnh, mã QR và ghi âm",
            status="warning" if ocr_failed else ("done" if (imgs or auds) else "skipped"),
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
        direct_text = "\n".join(
            part for part in (text, "\n".join(qr_text_parts), local_transcript or "") if part.strip()
        )
        combined_text = "\n".join(part for part in (direct_text, all_ocr_text) if part.strip())
        # Preserve clear untrusted OCR delineation for Gemini prompt isolation
        llm_input_text = direct_text
        if all_ocr_text:
            ocr_block = f"[OCR_EXTRACTED_UNTRUSTED_TEXT]\n{all_ocr_text}"
            llm_input_text = f"{direct_text}\n\n{ocr_block}" if direct_text else ocr_block

        extra_urls = [*([url] if url and url.strip() else []), *qr_urls]
        direct_iocs = extract_iocs(direct_text, extra_urls=extra_urls)
        direct_url_set = set(direct_iocs.urls)
        iocs = extract_iocs(combined_text, extra_urls=extra_urls)
        ocr_only_url_set = {u for u in iocs.urls if u not in direct_url_set}

        for vqr in vietqr_list:
            if vqr.account_number and vqr.account_number not in iocs.bank_accounts:
                iocs.bank_accounts.append(vqr.account_number)

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

        url_findings: list[UrlFinding] = []
        for candidate_url in iocs.urls[:4]:
            # Security invariant: NEVER auto-visit URLs extracted solely from OCR text!
            allow_net = (
                self.settings.enable_live_network_checks
                and candidate_url not in ocr_only_url_set
            )
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
        sandbox_eligible = [u for u in url_findings if u.url not in ocr_only_url_set]
        if sandbox_eligible and self.settings.enable_playwright_sandbox:
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

        has_susp_url = any(u.risk_points > 0 or u.is_blocked_ssrf for u in url_findings)
        guardrails = evaluate_guardrails(combined_text, has_suspicious_url=has_susp_url)
        if not guardrails.prompt_injection_detected and ocr_text_chunks:
            for chunk in ocr_text_chunks:
                chunk_guard = evaluate_guardrails(chunk, has_suspicious_url=has_susp_url)
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
        if mode == "merchant" or img_forensics_list:
            candidate_pairs: list[tuple[ImageForensicsResult | None, str, list[OcrBox] | None]] = (
                [
                    (fr, fr.ocr_text, boxes)
                    for fr, boxes in zip(img_forensics_list, ocr_boxes_list, strict=True)
                ]
                if img_forensics_list
                else [(None, text, None)]
            )
            evaluated_receipts: list[tuple[ReceiptLogicResult, ImageForensicsResult | None]] = []
            for fr_item, src_txt, src_boxes in candidate_pairs:
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
                replay_lookup_ran = (not is_demo) and (not is_simulation) and has_replay_probe
                replayed = (
                    False
                    if not replay_lookup_ran
                    else self.repo.claim_receipt_replay(
                        fr_item.dhash_hex if fr_item else None,
                        prelim.bank_detected,
                        replay_ref,
                        register_if_new=prelim.is_receipt_candidate,
                    )
                )
                rl_item = validate_receipt_logic(
                    ocr_text=src_txt,
                    ocr_boxes=src_boxes,
                    reference_now=reference_now,
                    expected_merchant_account=expected_merchant_account,
                    is_replayed_hash=replayed,
                    replay_checked=replay_lookup_ran,
                )
                evaluated_receipts.append((rl_item, fr_item))
                if (
                    rl_item.extracted_recipient_account
                    and rl_item.extracted_recipient_account not in iocs.bank_accounts
                ):
                    iocs.bank_accounts.append(rl_item.extracted_recipient_account)
                    rcpt_rules = self.repo.match_active_block_rules(iocs)
                    existing_rids = {r.rule_id for r in matched_rules}
                    new_rcpt_rules = [r for r in rcpt_rules if r.rule_id not in existing_rids]
                    if new_rcpt_rules:
                        matched_rules.extend(new_rcpt_rules)
                    if not block_hit and rcpt_rules:
                        block_hit = True
                        evidence.append(
                            EvidenceItem(
                                source="fraud_ops_radar",
                                severity="CRITICAL",
                                title="Tài khoản trên biên lai trùng danh sách chặn",
                                detail=(
                                    f"Số tài khoản nhận {rcpt_rules[0].masked_value} trên biên lai "
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
                best_rl, best_fr = max(
                    receipt_candidates,
                    key=lambda p: (
                        p[0].logic_risk_points,
                        int(p[0].is_replayed),
                        int(p[0].beneficiary_mismatch),
                    ),
                )
                receipt_logic = best_rl
                receipt_dhash_for_save = best_fr.dhash_hex if best_fr else None
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
            image_bytes=imgs[0][0] if imgs else None,
            image_mime=imgs[0][2] if imgs else "image/jpeg",
            audio_bytes=auds[0][0] if auds else None,
            audio_mime=auds[0][2] if auds else "audio/wav",
            images=llm_images,
            audios=llm_audios,
            local_transcript=local_transcript,
            ocr_incomplete=(ocr_failed or ocr_unreadable_image_only),
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

        if not local_transcript and llm_res.transcript and llm_res.transcript.strip():
            enriched_text = f"{combined_text}\n{llm_res.transcript.strip()}".strip()
            iocs = extract_iocs(enriched_text, extra_urls=extra_urls)
            for vqr in vietqr_list:
                if vqr.account_number and vqr.account_number not in iocs.bank_accounts:
                    iocs.bank_accounts.append(vqr.account_number)
            post_rules = self.repo.match_active_block_rules(iocs)
            existing_post_rids = {r.rule_id for r in matched_rules}
            new_post_rules = [r for r in post_rules if r.rule_id not in existing_post_rids]
            if new_post_rules:
                matched_rules.extend(new_post_rules)
            if not block_hit and post_rules:
                block_hit = True
                evidence.append(
                    EvidenceItem(
                        source="fraud_ops_radar",
                        severity="CRITICAL",
                        title="Thông tin trong cuộc gọi trùng danh sách chặn",
                        detail=(
                            f"Dấu hiệu {post_rules[0].masked_value} trong cuộc gọi "
                            "đang nằm trong danh sách chặn của hệ thống."
                        ),
                    )
                )
            guardrails = evaluate_guardrails(enriched_text, has_suspicious_url=has_susp_url)

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

        comm_hits = self.repo.count_ioc_hits(iocs)
        raw_report = AnalysisReport(
            case_id=case_id_override or f"vs_{uuid.uuid4().hex[:12]}",
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
            transcript=llm_res.transcript,
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
        if is_simulation:
            # Simulations evaluate active block rules without polluting real statistics or graph sightings
            saved_report = redact_report_pii(raw_report, strip_visual_blobs=False)
        else:
            saved_report = self.repo.save_report(
                raw_report,
                receipt_dhash=(
                    receipt_dhash_for_save
                    if (receipt_dhash_for_save and receipt_logic and receipt_logic.is_receipt_candidate)
                    else None
                ),
                track_replay=not is_demo,
            )
        yield {"event": "result", "data": saved_report.model_dump()}

    async def run(self, **kwargs: Any) -> AnalysisReport:
        """Execute full pipeline and return the final persisted AnalysisReport."""
        final_data: dict[str, Any] | None = None
        async for item in self.stream(**kwargs):
            if item["event"] == "result":
                final_data = item["data"]
        if final_data is None:
            raise RuntimeError("Pipeline completed without emitting a result event.")
        return AnalysisReport.model_validate(final_data)
