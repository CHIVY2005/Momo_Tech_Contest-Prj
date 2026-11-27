"""Request-scoped entity vault and unified outbound LLM egress sanitizer."""

from __future__ import annotations

import json
import re
import secrets
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final, Literal
from urllib.parse import urlsplit

from app.services import assistant_vault_patterns as vp
from app.services import ioc_extractor as ioc
from app.services.guardrails import strip_xml_breakout_tags
from app.services.vietqr_parser import parse_qr_payload

VaultEntityType = Literal["url", "vietqr", "phone", "bank_account"]


def _dns_labels(host: str) -> list[str]:
    if not host:
        return []
    try:
        asc = host.encode("idna").decode("ascii").lower() if not host.isascii() else host.lower()
    except UnicodeError:
        return []
    ls = [x for x in asc.split(".") if x]
    return ls if len(ls) >= 2 and all(vp.DNS_LBL_RE.match(x) for x in ls) else []


class _ShieldBox:
    def __init__(self) -> None:
        self._tag = "".join(chr(65 + (b % 26)) for b in secrets.token_bytes(6))
        self._items: list[tuple[str, str]] = []

    def put(self, value: str) -> str:
        k = f"VSSHIELD{self._tag}{f'{len(self._items):04x}'.translate(vp.HEX_ALPHA)}END"
        self._items.append((k, value))
        return k

    def shield_refs(self, text: str) -> str:
        def _ok(m: re.Match[str]) -> str:
            sh, p = vp.REF_SHAPES.get(m.group("k")), m.group("p")
            ok = sh is not None and "***" in p and sum(c.isdigit() for c in p) <= 6 and sh.fullmatch(p)
            return self.put(m.group(0)) if ok else m.group(0)
        return vp.SREF_RE.sub(_ok, text)

    def restore(self, text: str) -> str:
        for key, val in reversed(self._items):
            text = text.replace(key, val)
        return text


@lru_cache(maxsize=1)
def _load_official_bare_domains() -> frozenset[str]:
    base, out = Path(__file__).resolve().parent.parent / "data", set(vp.FALLBACK_DOMS)
    for rel, key in (("vn_scam_kb.json", "official_brands"), ("models/assistant_kb_index.json", "chunks")):
        if (p := base / rel).exists():
            for it in json.loads(p.read_text("utf-8")).get(key, []):
                out.update(h for d in it.get("official_domains", [])
                           if _dns_labels(h := str(d).strip().lower().rstrip(".")))
    return frozenset(out)


def _strict_preview(raw: str, prefix: str, seed: str) -> str:
    c = re.sub(r"[^A-Za-z0-9*._-]", "", raw)[:32]
    return c if c and "***" in c and sum(ch.isdigit() for ch in c) <= 6 else (
        f"{prefix}_{ioc.hash_ioc('domain', seed)[:4]}***")


def _refang_url(token: str) -> tuple[str, str]:
    core = token.rstrip(vp.TRAIL_PUNCT)
    core = core.rstrip(")") if core.endswith(")") and core.count(")") > core.count("(") else core
    u = re.sub(r"^(h(?:tt|xx)ps?|ftps?|sftp|wss?|file|javascript)\[:\]//", r"\1://", core, flags=re.I)
    u = vp.UDOT_RE.sub(".", vp.DFG_RE.sub(".", re.sub(r"^hxxp(s?)://", r"http\1://", u, flags=re.I)))
    return u, token[len(core) :]


def _mask_url_preview(refanged: str) -> str:
    try:
        parts = urlsplit(refanged)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return f"url_{ioc.hash_ioc('domain', refanged)[:4]}***"
    if not host:
        return f"url_{ioc.hash_ioc('domain', refanged)[:4]}***"
    tag = "ipv6" if ":" in host or "[" in parts.netloc else ("ip" if vp.IP_RADIX_RE.fullmatch(host) else "")
    if tag:
        return f"{tag}_{ioc.hash_ioc('domain', host)[:4]}***"
    asc_host = host
    if not host.isascii():
        try:
            asc_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return f"dom_{ioc.hash_ioc('domain', host)[:4]}***"
    return _strict_preview(ioc.mask_ioc("domain", asc_host), "dom", asc_host)


def _url_email_pass(
    text: str, sh: _ShieldBox, *, keep_official: bool, on_http: Callable[[str, str], str],
) -> str:
    official = _load_official_bare_domains() if keep_official else frozenset()

    def _emit(tok: str, scheme: str = "", *, redact_only: bool = False) -> str:
        u, tr = _refang_url(tok)
        full, prev = f"{scheme}{u}", _mask_url_preview(f"{scheme}{u}")
        try:
            _ = urlsplit(full).port
            ok = not redact_only and full.lower().startswith(("http://", "https://"))
        except ValueError:
            ok = False
        return f"{sh.put(on_http(full, prev) if ok else f'[URL_REDACTED:{prev}]')}{tr}"

    def _sub_bare(m: re.Match[str]) -> str:
        tok = m.group(0)
        is_dfg = bool(vp.DFG_RE.search(tok) or vp.UDOT_RE.search(tok))
        refanged, tr = _refang_url(tok)
        try:
            parts = urlsplit(f"https://{refanged}")
            port, host = parts.port, (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            return _emit(tok, "https://", redact_only=True)
        has_auth = bool(parts.username or parts.password)
        has_sfx = bool((parts.path and parts.path != "/") or parts.query or parts.fragment
                       or port is not None or refanged.endswith("/") or has_auth)
        if not (lbls := _dns_labels(host)):
            return _emit(tok, "https://", redact_only=True) if (has_auth or has_sfx) else tok
        tld = lbls[-1]
        if not is_dfg and tld in vp.NON_TLD_EXTS and not has_auth and port is None:
            return tok
        if not is_dfg and not has_sfx and not host.startswith("www."):
            if tld not in vp.PUBLIC_SUFFIXES and not tld.startswith("xn--"):
                return tok
            if keep_official and host.isascii() and (
                host in official or any(host.endswith(f".{d}") for d in official)
            ):
                return f"{sh.put(refanged)}{tr}"
        return _emit(tok, "https://")

    out = vp.PROTO_REL_RE.sub(lambda m: _emit(m.group(0), "https:", redact_only=True),
                              vp.EXPLICIT_URL_RE.sub(lambda m: _emit(m.group(0)), text))
    out = vp.URL_SYNTAX_RE.sub(_sub_bare, vp.BARE_IP_RE.sub(lambda m: _emit(m.group(0), "http://"), out))
    return vp.SCHEMELESS_RE.sub(_sub_bare, vp.EMAIL_RE.sub(lambda _: sh.put("[EMAIL_REDACTED]"), out))


def _secrets_pass(text: str, sh: _ShieldBox) -> str:
    out = vp.OTP_PW_RE.sub(lambda m: f"{m.group('p')}{sh.put('[OTP_REDACTED]')}", text)
    out = vp.CARD_LBL_RE.sub(lambda m: f"{m.group('p')}{sh.put('[CARD_REDACTED]')}", out)
    out = vp.CCCD_LBL_RE.sub(lambda m: f"{m.group('p')}{sh.put('[CCCD_REDACTED]')}", out)
    out = vp.CARD16_RE.sub(
        lambda m: m.group(0) if vp.ACCT_PRE_RE.search(m.string[max(0, m.start() - 32) : m.start()])
        else sh.put("[CARD_REDACTED]"), out)
    return vp.NAPAS_BIN_RE.sub(lambda m: sh.put(m.group(0)), out)


@dataclass(frozen=True, slots=True)
class VaultEntity:
    ref_id: str
    entity_type: VaultEntityType
    raw_value: str
    masked_preview: str


class RequestEntityVault:
    """Per-request RAM vault replacing raw URLs/VietQR/phones/accounts with strict ref tokens."""

    _PFX: Final[dict[VaultEntityType, str]] = {
        "url": "URL_REF", "vietqr": "VIETQR_REF", "phone": "PHONE_REF", "bank_account": "ACCT_REF"}

    def __init__(self) -> None:
        self._entities: dict[str, VaultEntity] = {}

    def _ref(self, etype: VaultEntityType, raw: str, preview: str) -> str:
        for ex in self._entities.values():
            if ex.entity_type == etype and ex.raw_value == raw:
                return f"[{ex.ref_id} ({ex.masked_preview})]"
        rid = f"{self._PFX[etype]}_{sum(1 for e in self._entities.values() if e.entity_type == etype) + 1}"
        self._entities[rid] = VaultEntity(rid, etype, raw, preview)
        return f"[{rid} ({preview})]"

    def get(self, ref_id: str) -> VaultEntity | None:
        return self._entities.get(ref_id)

    def list_public_refs(self) -> list[dict[str, str]]:
        return [{"ref_id": e.ref_id, "entity_type": e.entity_type, "masked_preview": e.masked_preview}
                for e in self._entities.values()]

    @classmethod
    def extract_from_message(cls, raw_message: str) -> tuple[str, RequestEntityVault]:
        vault, sh = cls(), _ShieldBox()
        out = vp.FAKE_REF_RE.sub(lambda _: sh.put("[REF_LITERAL_REDACTED]"),
                                 unicodedata.normalize("NFC", vp.INVIS_RE.sub("", raw_message)))

        def _vqr(m: re.Match[str]) -> str:
            if (rq := m.group(0))[-8:-4] != "6304":
                return sh.put("[VIETQR_REDACTED]")
            info, _ = parse_qr_payload(rq)
            b = f"qr_{ioc.mask_ioc('bank_account', info.account_number)}" if info.account_number else ""
            return sh.put(vault._ref("vietqr", rq, _strict_preview(b, "qr", rq)))

        def _acct(d: str) -> str:
            prev = _strict_preview(ioc.mask_ioc("bank_account", d), "ac", d)
            return sh.put(vault._ref("bank_account", d, prev))

        def _lbl(m: re.Match[str]) -> str:
            if m.group("explicit_label") is None or not ioc.is_labeled_account_match(m.string, m):
                return m.group(0)
            d = ioc.normalize_ioc_value("bank_account", m.group("acct"))
            return f"{m.group('prefix')}{_acct(d)}" if 6 <= len(d) <= 19 else m.group(0)

        def _ph(m: re.Match[str]) -> str:
            d = f"0{m.group('h')}{re.sub(r'\D', '', m.group('r'))}"
            return sh.put(vault._ref("phone", d, _strict_preview(ioc.mask_ioc("phone", d), "ph", d)))

        out = _url_email_pass(vp.VQR_RE.sub(_vqr, out), sh, keep_official=False,
                              on_http=lambda u, p: vault._ref("url", u, p))
        out = ioc.LABELED_ACCOUNT_SPAN_RE.sub(_lbl, _secrets_pass(out, sh))
        out = vp.VN_CCCD_RE.sub(lambda _: sh.put("[CCCD_REDACTED]"), vp.VN_PHONE_RE.sub(_ph, out))
        out = vp.BARE_ACCT_RE.sub(
            lambda m: _acct(d) if not vp.DATE_RE.fullmatch(m.group(0))
            and 8 <= len(d := re.sub(r"\D", "", m.group(0))) <= 19 else m.group(0), out)
        return sh.restore(out), vault


def sanitize_untrusted_delimiters(text: str, *, preserve_strict_vault_refs: bool = False) -> str:
    """Neutralize XML breakouts, fake section headers, and spoofed vault ref tokens."""
    if not text:
        return ""
    sh, out = _ShieldBox(), strip_xml_breakout_tags(text)
    out = sh.shield_refs(out) if preserve_strict_vault_refs else out
    return sh.restore(vp.FAKE_REF_RE.sub("[REF_LITERAL_REDACTED]",
                                         vp.FAKE_SEC_RE.sub("[SECTION_LABEL_REDACTED]", out)))


def sanitize_llm_egress_text(
    text: str, *, preserve_official_bare_domains: bool = False, preserve_strict_vault_refs: bool = False,
) -> str:
    """Unified outbound egress sanitizer for all prompt channels and final wire chokepoint."""
    if not text:
        return ""
    sh, out = _ShieldBox(), unicodedata.normalize("NFC", vp.INVIS_RE.sub("", text))
    out = vp.FAKE_REF_RE.sub(lambda _: sh.put("[REF_LITERAL_REDACTED]"),
                             sh.shield_refs(out) if preserve_strict_vault_refs else out)
    out = _url_email_pass(vp.VQR_RE.sub(lambda _: sh.put("[VIETQR_REDACTED]"), out), sh,
                          keep_official=preserve_official_bare_domains,
                          on_http=lambda _u, p: f"[URL_REDACTED:{p}]")
    out = vp.VN_CCCD_RE.sub(
        lambda m: m.group(0) if vp.ACCT_PRE_RE.search(m.string[max(0, m.start() - 32) : m.start()])
        else sh.put("[CCCD_REDACTED]"), _secrets_pass(out, sh))
    return sh.restore(ioc.scrub_free_text_pii(out))
