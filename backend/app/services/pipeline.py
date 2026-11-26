"""3-Tier async analysis pipeline with live SSE TraceStep streaming."""

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
from app.core.security import InvalidMediaError, validate_upload_bytes
from app.db.repository import CaseRepository
from app.schemas import (
    AnalysisReport,
    AnalyzeMode,
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
from app.services.ioc_extractor import extract_iocs
from app.services.knowledge_base import KnowledgeBaseRetriever
from app.services.local_ocr import run_local_ocr
from app.services.local_stt import run_local_stt
from app.services.phishing_detonator import detonate_url_in_sandbox
from app.services.receipt_validator import build_trusted_merchant_summary, validate_receipt_logic
from app.services.risk_calibrator import calibrate_risk
from app.services.scam_classifier import ScamClassifier
from app.services.url_inspector import inspect_url
from app.services.vietqr_parser import parse_qr_payload


class UnknownDemoError(KeyError):
    """Raised when a requested demo_id does not exist."""


_guard_merchant_summary = build_trusted_merchant_summary


class AnalysisPipeline:
    """Coordinates Tier 1 (Security/Forensics/ONNX), Tier 2 (Gemini), and Tier 3 (Copilot/DB)."""

    def __init__(self, settings: Settings, repo: CaseRepository) -> None:
        self.settings = settings
        self.repo = repo
        data_dir = Path(__file__).resolve().parent.parent / "data"
        self._data_dir = data_dir

        model_dir = Path(settings.model_dir)
        if not model_dir.is_absolute():
            model_dir = Path(__file__).resolve().parents[2] / settings.model_dir
        self.classifier = ScamClassifier(str(model_dir))

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
        demo_id: str | None = None,
        in_active_call: bool = False,
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
            # Strictly isolate fixture runs from any caller-supplied uploads
            image_bytes = None
            audio_bytes = None
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

        if image_bytes is not None:
            validate_upload_bytes(image_bytes, self.settings.max_upload_bytes, kind="image")
        if audio_bytes is not None:
            validate_upload_bytes(audio_bytes, self.settings.max_upload_bytes, kind="audio")

        if (
            not text.strip()
            and not (url and url.strip())
            and image_bytes is None
            and audio_bytes is None
        ):
            raise InvalidMediaError("At least one non-empty evidence input is required.")

        trace: list[TraceStep] = []
        evidence: list[EvidenceItem] = []
        _ = transfer_amount

        # Step 1: Media Forensics, Local OCR/STT & VietQR Decoding
        t_media = time.perf_counter()
        img_forensics: ImageForensicsResult | None = None
        ocr_boxes = None
        vietqr_list: list[VietQRInfo] = []
        qr_urls: list[str] = []
        local_transcript: str | None = None

        if image_bytes is not None:
            ocr_res = await asyncio.to_thread(
                run_local_ocr,
                image_bytes,
                self.settings.enable_local_ocr,
            )
            ocr_boxes = ocr_res.boxes
            img_forensics = await asyncio.to_thread(
                analyze_image_forensics,
                image_bytes,
                image_filename,
                False,
            )
            img_forensics = img_forensics.model_copy(
                update={"ocr_text": ocr_res.full_text, "ocr_height_cv": ocr_res.height_cv}
            )
            for reason in img_forensics.reasons:
                evidence.append(
                    EvidenceItem(
                        source="image_forensics",
                        severity="HIGH" if img_forensics.tamper_score >= 45 else "MEDIUM",
                        title="Phát hiện bất thường pháp y vật lý ảnh",
                        detail=reason,
                    )
                )
            for raw_qr in img_forensics.qr_payloads:
                vqr, vqr_ev = parse_qr_payload(
                    raw_qr,
                    accompanying_text=text,
                    expected_merchant_account=expected_merchant_account,
                )
                vietqr_list.append(vqr)
                evidence.extend(vqr_ev)
                if vqr.kind == "URL_QR":
                    qr_urls.append(vqr.raw)

        if audio_bytes is not None:
            stt_res = await asyncio.to_thread(
                run_local_stt,
                audio_bytes,
                audio_filename,
                self.settings.enable_local_stt,
            )
            if stt_res.available and stt_res.transcript:
                local_transcript = stt_res.transcript

        media_step = TraceStep(
            step_id="media_forensics",
            title="Pháp y ảnh (ELA/dHash/VietQR) & Chuyển ngữ cục bộ",
            status="done" if (image_bytes or audio_bytes) else "skipped",
            detail=(
                f"Đã quét ảnh ({len(vietqr_list)} mã QR) / âm thanh cục bộ."
                if (image_bytes or audio_bytes)
                else "Không có tệp đa phương thức đính kèm."
            ),
            duration_ms=int((time.perf_counter() - t_media) * 1000),
        )
        trace.append(media_step)
        yield {"event": "trace", "data": media_step.model_dump()}

        # Step 2: IOC Extraction, Active Block Rules, URL Inspection & Sandbox
        t_sec = time.perf_counter()
        combined_text = "\n".join(
            part
            for part in (
                text,
                img_forensics.ocr_text if img_forensics else "",
                local_transcript or "",
            )
            if part.strip()
        )
        extra_urls = [*([url] if url and url.strip() else []), *qr_urls]
        iocs = extract_iocs(combined_text, extra_urls=extra_urls)
        for vqr in vietqr_list:
            if vqr.account_number and vqr.account_number not in iocs.bank_accounts:
                iocs.bank_accounts.append(vqr.account_number)

        matched_rules = self.repo.match_active_block_rules(iocs)
        block_hit = len(matched_rules) > 0
        if block_hit:
            evidence.append(
                EvidenceItem(
                    source="fraud_ops_radar",
                    severity="CRITICAL",
                    title="Trùng khớp Danh sách Chặn Khẩn cấp (/radar)",
                    detail=f"Thực thể {matched_rules[0].masked_value} đang bị khóa bởi Fraud Ops.",
                )
            )

        url_findings: list[UrlFinding] = []
        for candidate_url in iocs.urls[:3]:
            uf = await inspect_url(
                candidate_url,
                enable_network=self.settings.enable_live_network_checks,
            )
            url_findings.append(uf)
            for reason in uf.reasons:
                evidence.append(
                    EvidenceItem(
                        source="url_inspector",
                        severity="CRITICAL" if uf.risk_points >= 75 else "HIGH",
                        title="Phát hiện rủi ro đường dẫn / tên miền",
                        detail=reason,
                        snippet=candidate_url[:140],
                    )
                )

        sandbox_res: SandboxInspection | None = None
        if url_findings and self.settings.enable_playwright_sandbox:
            top_u = max(url_findings, key=lambda item: item.risk_points)
            if top_u.risk_points >= 40 and not top_u.is_blocked_ssrf:
                sandbox_res = await detonate_url_in_sandbox(top_u.url, enabled=True)
                if (sandbox_res.available or sandbox_res.blocked_ssrf) and sandbox_res.risk_points > 0:
                    for s_reason in sandbox_res.reasons:
                        evidence.append(
                            EvidenceItem(
                                source="phishing_sandbox",
                                severity="CRITICAL" if sandbox_res.risk_points >= 75 else "HIGH",
                                title="Buồng cô lập trình duyệt bắt quả tang bẫy Phishing",
                                detail=s_reason,
                            )
                        )

        has_susp_url = any(u.risk_points > 0 or u.is_blocked_ssrf for u in url_findings)
        guardrails = evaluate_guardrails(combined_text, has_suspicious_url=has_susp_url)
        evidence.extend(guardrails.evidence)

        sec_warn = block_hit or has_susp_url or guardrails.prompt_injection_detected
        sec_step = TraceStep(
            step_id="cyber_guardrails",
            title="Kiểm tra Block Rules, SSRF/Punycode URL & Guardrails",
            status="warning" if sec_warn else "done",
            detail=(
                f"Trích xuất {len(iocs.phones)} SĐT, {len(iocs.bank_accounts)} STK, "
                f"{len(url_findings)} URL."
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
        if mode == "merchant" or image_bytes is not None:
            # Separate receipt-printed OCR text from caller narrative when an image is uploaded
            receipt_source_text = (
                img_forensics.ocr_text if img_forensics is not None else text
            )
            prelim = validate_receipt_logic(
                ocr_text=receipt_source_text,
                ocr_boxes=ocr_boxes,
                reference_now=reference_now,
                expected_merchant_account=expected_merchant_account,
                is_replayed_hash=False,
                replay_checked=False,
            )
            replay_ref = prelim.reference_code if prelim.reference_valid else None
            has_replay_probe = bool((img_forensics and img_forensics.dhash_hex) or replay_ref)
            replay_lookup_ran = (not is_demo) and has_replay_probe
            replayed = (
                False
                if not replay_lookup_ran
                else self.repo.claim_receipt_replay(
                    img_forensics.dhash_hex if img_forensics else None,
                    prelim.bank_detected,
                    replay_ref,
                    register_if_new=prelim.is_receipt_candidate,
                )
            )
            receipt_logic = validate_receipt_logic(
                ocr_text=receipt_source_text,
                ocr_boxes=ocr_boxes,
                reference_now=reference_now,
                expected_merchant_account=expected_merchant_account,
                is_replayed_hash=replayed,
                replay_checked=replay_lookup_ran,
            )
            if (
                receipt_logic.extracted_recipient_account
                and receipt_logic.extracted_recipient_account not in iocs.bank_accounts
            ):
                iocs.bank_accounts.append(receipt_logic.extracted_recipient_account)
                if not block_hit:
                    rcpt_rules = self.repo.match_active_block_rules(iocs)
                    if rcpt_rules:
                        block_hit = True
                        evidence.append(
                            EvidenceItem(
                                source="fraud_ops_radar",
                                severity="CRITICAL",
                                title="Trùng khớp Danh sách Chặn Khẩn cấp trên biên lai (/radar)",
                                detail=(
                                    f"Tài khoản nhận {rcpt_rules[0].masked_value} trên biên lai "
                                    "đang bị khóa bởi Fraud Ops."
                                ),
                            )
                        )
            for r_reason in receipt_logic.reasons:
                evidence.append(
                    EvidenceItem(
                        source="receipt_validator",
                        severity="CRITICAL" if receipt_logic.logic_risk_points >= 65 else "HIGH",
                        title="Bất thường logic nghiệp vụ biên lai",
                        detail=r_reason,
                    )
                )

        onnx_step = TraceStep(
            step_id="onnx_and_kb",
            title="Phân loại Ngữ nghĩa E5 ONNX & Đối chiếu 20 Kịch bản VN",
            status="done",
            detail=(
                f"ONNX: {clf_out.predicted_label} ({clf_out.latency_ms}ms) · "
                f"Khớp {len(matched_pbs)} kịch bản."
                if clf_out.available
                else f"Đối chiếu từ điển ngữ nghĩa ({len(matched_pbs)} kịch bản khớp)."
            ),
            duration_ms=int((time.perf_counter() - t_onnx) * 1000),
        )
        trace.append(onnx_step)
        yield {"event": "trace", "data": onnx_step.model_dump()}

        # Compute deterministic Tier-1 score (including browser sandbox risk)
        tier1_score = 0
        if url_findings:
            tier1_score = max(tier1_score, max(u.risk_points for u in url_findings))
        if sandbox_res and (sandbox_res.available or sandbox_res.blocked_ssrf):
            tier1_score = max(tier1_score, sandbox_res.risk_points)
        if img_forensics:
            tier1_score = max(tier1_score, img_forensics.tamper_score)
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
        llm_res = await run_gemini_reasoning(
            settings=self.settings,
            text=combined_text,
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
            image_bytes=image_bytes,
            image_mime=image_mime,
            audio_bytes=audio_bytes,
            audio_mime=audio_mime,
            local_transcript=local_transcript,
        )
        for vis_anom in llm_res.bill_visual_anomalies[:3]:
            evidence.append(
                EvidenceItem(
                    source="gemini_vision",
                    severity="HIGH",
                    title="Bất thường thị giác trên chứng từ",
                    detail=vis_anom,
                )
            )

        # Re-evaluate IOCs & active block rules when cloud transcription supplies new audio text
        if not local_transcript and llm_res.transcript and llm_res.transcript.strip():
            enriched_text = f"{combined_text}\n{llm_res.transcript.strip()}".strip()
            iocs = extract_iocs(enriched_text, extra_urls=extra_urls)
            for vqr in vietqr_list:
                if vqr.account_number and vqr.account_number not in iocs.bank_accounts:
                    iocs.bank_accounts.append(vqr.account_number)
            if not block_hit:
                post_rules = self.repo.match_active_block_rules(iocs)
                if post_rules:
                    block_hit = True
                    evidence.append(
                        EvidenceItem(
                            source="fraud_ops_radar",
                            severity="CRITICAL",
                            title="Trùng khớp Danh sách Chặn Khẩn cấp qua lời thoại (/radar)",
                            detail=(
                                f"Thực thể {post_rules[0].masked_value} trong cuộc gọi "
                                "đang bị khóa bởi Fraud Ops."
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
        safe_summary = _guard_merchant_summary(
            llm_res.summary_vi,
            mode=mode,
            receipt_status=cal.receipt_verification_status,
            has_qr_beneficiary_mismatch=any(v.beneficiary_mismatch for v in vietqr_list),
            has_ocr_beneficiary_mismatch=bool(
                receipt_logic and receipt_logic.beneficiary_mismatch
            ),
        )

        llm_badge = (
            " [Chế độ dự phòng Tầng 1]"
            if llm_res.degraded_mode
            else f" [{llm_res.llm_model or self.settings.gemini_model}]"
        )
        llm_step = TraceStep(
            step_id="multimodal_calibration",
            title="Thẩm định Đa phương thức & Hiệu chuẩn Điểm Rủi ro",
            status="warning" if llm_res.degraded_mode else "done",
            detail=f"Điểm hiệu chuẩn: {cal.final_score}/100 ({cal.verdict}){llm_badge}",
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
            receipt_logic=receipt_logic,
            evidence=evidence,
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
        saved_report = self.repo.save_report(
            raw_report,
            receipt_dhash=(
                img_forensics.dhash_hex
                if (img_forensics and receipt_logic and receipt_logic.is_receipt_candidate)
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
