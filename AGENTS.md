# AGENTS.md — VeriShield AI v2.0 Engineering & Security Constitution

This file is the binding contract for both **Antigravity (Implementer)** and **Codex CLI (Reviewer)** in this repository.

## 1. Canonical References
- Contest Problem Statement: `docs/momo.md`
- Product & API Specification (v2.0): `docs/PROPOSAL.md`
- Architecture & Monorepo Design Spec: `docs/superpowers/specs/2026-11-25-verishield-v2-architecture-and-codex-workflow-design.md`
- Task-by-Task TDD Plan: `docs/IMPLEMENTATION_PLAN.md`

Always evaluate diffs against these v2.0 documents.

## 2. Hard Architectural & Legal Invariants
1. **Zero Trademark Infringement (Rule 6.5):** Product name (`VeriShield AI`), package names, UI branding, and team identifiers MUST NOT include `"MoMo"` as part of our brand name (referencing official Vietnamese banks/wallets inside `vn_scam_kb.json` domain/BIN dictionaries for anti-phishing verification is expected).
2. **Clean Licensing Only (Rules 12.5, 28, 31):** Only permissive/open licenses (`MIT`, `Apache-2.0`, `BSD`, `LGPL-3.0`, `Bitstream Vera`) are allowed. Never introduce `uitnlp/visobert` (research-only) or `vinai/phobert*` (`AGPL-3.0`). Custom NLP backbone is `intfloat/multilingual-e5-small` (`MIT`).
3. **100% Synthetic / Public-Advisory Data (Rule 12.4):** All training data, demo scenarios, benchmark cases, and seed IOCs must be synthetic. Never commit real personal data (PII) or `.env` secrets.
4. **Runtime vs Training Separation:** `backend/requirements.txt` MUST NEVER include `torch` or `transformers`. Production CPU inference uses `onnxruntime` with `SessionOptions.enable_cpu_mem_arena = False` and `SessionOptions.enable_mem_pattern = False`. Model artifacts committed to Git must remain `< 50 MB`.
5. **Merchant Receipt Honesty Guardrail:** An unverified transfer receipt screenshot MUST NEVER be presented as proof that funds arrived. Even when `verdict == "SAFE"` (`risk_score <= 24`, no tampering detected), `receipt_verification_status` MUST be `"UNVERIFIED_SCREENSHOT"` and `actions.merchant_balance_warning` MUST instruct the merchant to verify actual account balance / Soundbox before handing over goods.
6. **Cybersecurity Hardening:**
   - Enforce `max_upload_bytes <= 10 MB` (`HTTP 413` on oversize, `HTTP 400` on empty/corrupt media).
   - Block all non-public IPs (loopback, RFC1918, link-local `169.254.0.0/16`, CGNAT `100.64.0.0/10`, multicast, IPv4-mapped IPv6 `::ffff:...`) on initial URL AND every redirect hop (`httpx`) AND every sub-request (`Playwright` route interceptor).
   - Mask PII (`mask_ioc`) on all public radar/case payloads; never store raw phones/bank accounts in public graph tables.
   - Protect canonical SAFE demo IOCs from `/radar` block rules (`HTTP 409`), validate `analyst_pin` (`HTTP 403` on mismatch) and `X-Telegram-Bot-Api-Secret-Token`, and enforce TTL expiry (`30 min` default) on transient block rules.
   - Wrap untrusted text inside `<UNTRUSTED_USER_CONTENT>` tags when prompting Gemini, and degrade gracefully (`HTTP 200`, `degraded_mode=True`) if Gemini errors, times out, or returns `FinishReason.SAFETY`.

## 3. Code Quality & Modularity Standards
- Keep service modules focused and concise (target `< 280` lines per service file) with 1-to-1 unit tests in `backend/tests/unit/`.
- Maintain strict static typing: `mypy` (`strict = true`) + `ruff` in Python; `tsc --noEmit` (`"strict": true`) in TypeScript.
- Windows PowerShell 5.1 compatibility: do not use `&&` inside `.ps1` scripts.

## 4. Mandatory Verification Gate
Before marking any task complete or approving a commit, run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
```

On Linux / CI / VPS:

```bash
bash scripts/verify.sh
```
