/**
 * Pure-TS Vietnamese text normalization & semantic follow-up deduplication for Trợ lý VeriShield.
 * Mirrors backend intent/concept rules so multi-turn conversations (including 5-10+ turns beyond
 * the backend's 6-pair history cap) never re-suggest asked or semantically answered questions.
 */

const MD_NOISE_RE = /[*_`#~>|]+/g;
const PUNCT_RE = /[^\p{L}\p{N}\s]+/gu;
const WS_RE = /\s+/g;
const PREFIX_RE =
  /^(?:(?:xin\s+hoi|cho\s+(?:toi|minh|em|anh|chi)\s+hoi|ban\s+cho\s+hoi|cho\s+hoi|hay\s+cho\s+biet|vui\s+long|lam\s+on|tu\s+van\s+giup|giup\s+(?:toi|minh)|hay)\s+)+/;

const STOPWORDS = new Set([
  "toi", "minh", "em", "anh", "chi", "ban", "ho", "nguoi", "nay", "do", "kia", "la", "va",
  "hoac", "hay", "thi", "da", "vua", "moi", "dang", "se", "roi", "chua", "khong", "co",
  "nen", "can", "phai", "duoc", "cho", "voi", "cua", "trong", "ngoai", "tren", "duoi",
  "de", "khi", "neu", "vi", "tai", "sao", "the", "nao", "gi", "nhu", "cach", "lam",
  "ngay", "luon", "bay", "gio", "them", "nua", "mot", "nhung", "cac", "nhieu", "it",
  "mat", "bi", "tu", "den", "ve", "vao", "ra", "o", "ma", "nha", "nhe", "a", "oi",
]);

const INTENT_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  [
    "merchant_handover",
    /\b(?:giao|dua)\s+hang\b|\bcho\s+khach\s+(?:lay|mang)\s+hang\b|\b(?:bien\s+lai|bill|anh\s+chuyen\s+khoan).{0,25}\b(?:that|gia|giao\s+hang)\b/,
  ],
  [
    "merchant_balance_verify",
    /\b(?:doi\s+chieu|kiem\s+tra|xac\s+minh).{0,30}\b(?:tien|so\s+du|soundbox|sao\s+ke)\b|\b(?:so\s+du\s+thuc\s+te|loa\s+soundbox|tien\s+(?:da\s+)?(?:ve|vao)(?:\s+tai\s+khoan)?)\b/,
  ],
  [
    "merchant_customer_pressure",
    /\b(?:hoi\s+thuc|giuc\s+giao|nghen\s+mang|bao\s+tri\s+ngan\s+hang|shipper\s+dang\s+doi)\b/,
  ],
  [
    "merchant_qr_counter",
    /\b(?:bang\s+ma\s+qr|dan\s+de|trao\s+(?:ma\s+)?qr|qr\s+tai\s+quay|quay\s+thu\s+ngan)\b/,
  ],
  [
    "explain_forensics",
    /\b(?:ela|exif|chinh\s+sua\s+anh|bat\s+thuong\s+(?:tren\s+)?bien\s+lai|anh\s+bi\s+sua)\b/,
  ],
  [
    "explain_report_signals",
    /\b(?:giai\s+thich|tom\s+tat).{0,30}\b(?:ket\s+qua|ho\s+so|bao\s+cao|dau\s+hieu|rui\s+ro)\b|\b(?:vi\s+sao|tai\s+sao).{0,30}\b(?:nguy\s+hiem|rui\s+ro|canh\s+bao|lua\s+dao)\b/,
  ],
  [
    "incident_transferred_money",
    /\b(?:lo|da|vua|bi\s+lua)\s+(?:chuyen|nop)\s+(?:nham\s+)?(?:tien|khoan)\b|\bchuyen\s+(?:tien|khoan)\s+(?:nham|roi|cho\s+ke\s+(?:gian|lua))\b|\b60\s+phut\b/,
  ],
  [
    "incident_otp_password",
    /\b(?:lo|doc|cung\s+cap|chia\s+se|gui|nhap)\s+(?:ma\s+)?(?:xac\s+thuc\s+)?(?:otp|smartotp|pin|cvv|cvc|mat\s+khau)\b|\b(?:otp|smartotp|mat\s+khau|cvv).{0,25}\b(?:xu\s+ly|khoa\s+(?:tai\s+khoan|the))\b/,
  ],
  [
    "incident_apk_malware",
    /\b(?:cai|tai|go)\s+(?:dat\s+)?(?:tep|file|app|ung\s+dung)?\s*\.?apk\b|\b(?:chia\s+se\s+man\s+hinh|dieu\s+khien\s+tu\s+xa|quyen\s+tro\s+nang|ngat\s+mang)\b/,
  ],
  [
    "incident_cccd_ekyc",
    /\b(?:cccd|cmnd|can\s+cuoc|video\s+khuon\s+mat|ekyc|tttb|1414)\b/,
  ],
  [
    "incident_social_hijack",
    /\b(?:mat\s+nick|bi\s+hack|chiem\s+quyen)\s+(?:tai\s+khoan\s+)?(?:zalo|facebook|telegram)\b|\b(?:tai\s+khoan\s+)?(?:zalo|facebook)\s+bi\s+(?:chiem|hack)\b/,
  ],
  [
    "incident_preserve_evidence",
    /\b(?:luu|thu\s+thap|giu\s+lai|chuan\s+bi|sao\s+luu).{0,25}\b(?:bang\s+chung|chung\s+cu|giay\s+to)\b|\b(?:bang\s+chung|chung\s+cu).{0,20}\b(?:trinh\s+bao|nop|cong\s+an)\b/,
  ],
  [
    "incident_report_police",
    /\b(?:quy\s+trinh|cach|huong\s+dan).{0,25}\b(?:trinh\s+bao|to\s+giac|tra\s+soat)\b|\b(?:trinh\s+bao\s+cong\s+an|cuc\s+a05|yeu\s+cau\s+ngan\s+hang\s+tra\s+soat|phong\s+toa\s+tai\s+khoan)\b/,
  ],
  [
    "incident_recovery_scam",
    /\b(?:lay\s+lai\s+tien|thu\s+hoi\s+tien|lua\s+dao\s+lan\s+(?:2|hai)|dich\s+vu\s+hoan\s+tien)\b/,
  ],
  [
    "verify_domain_url",
    /\b(?:ten\s+mien|duong\s+dan|duong\s+link|link\s+gia|website|trang\s+web|gov\s+vn|url)\b.{0,35}\b(?:that|gia|phan\s+biet|kiem\s+tra|nhan\s+biet|chinh\s+thuc|lua\s+dao)\b|\b(?:phan\s+biet|kiem\s+tra|nhan\s+biet).{0,25}\b(?:ten\s+mien|duong\s+dan|duong\s+link|link|website|trang\s+web)\b/,
  ],
  [
    "verify_vietqr_bin",
    /\b(?:vietqr|bin\s+napas|quet\s+(?:ma\s+)?qr|ma\s+qr.{0,20}(?:hoan\s+tien|kiem\s+tra|nguoi\s+nhan))\b/,
  ],
  [
    "verify_safe_epistemic",
    /\b(?:rui\s+ro\s+thap|muc\s+an\s+toan).{0,25}\b(?:chac\s+chan|an\s+toan|khong)\b|\bchac\s+chan\s+an\s+toan\b|\ban\s+toan\s+(?:tuyet\s+doi|100)\b/,
  ],
  [
    "verify_official_channel",
    /\b(?:tu\s+kiem\s+chung|kiem\s+chung\s+them|xac\s+minh\s+them|kenh\s+chinh\s+thuc|buoc\s+nao\s+truoc\s+khi\s+(?:chuyen|giao\s+dich))\b/,
  ],
  [
    "scam_education",
    /\b(?:thu\s+doan|kich\s+ban\s+lua\s+dao|chieu\s+tro|hoat\s+dong\s+nhu\s+the\s+nao|nhan\s+biet\s+som|doi\s+kich\s+ban)\b/,
  ],
  [
    "active_call_handling",
    /\b(?:dang\s+(?:nghe|goi)\s+dien\s+thoai|bi\s+giuc\s+chuyen\s+tien|cup\s+may|co\s+lap)\b/,
  ],
  [
    "family_protection",
    /\b(?:nguoi\s+than|gia\s+dinh|canh\s+bao\s+nguoi\s+nha|nguoi\s+lon\s+tuoi)\b/,
  ],
];

const CONCEPT_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ["c_receipt", /\b(?:bien\s+lai|bill|anh\s+chuyen\s+(?:khoan|tien))\b/],
  ["c_handover", /\b(?:giao\s+hang|dua\s+hang|lay\s+hang)\b/],
  ["c_balance", /\b(?:so\s+du|soundbox|sao\s+ke|tien\s+(?:da\s+)?(?:ve|vao))\b/],
  ["c_transfer", /\b(?:chuyen\s+tien|chuyen\s+khoan|nop\s+tien)\b/],
  ["c_incident", /\b(?:lo|nham|bi\s+lua|xu\s+ly|60\s+phut)\b/],
  ["c_otp", /\b(?:otp|smartotp|mat\s+khau|pin|cvv|cvc|xac\s+thuc)\b/],
  ["c_apk", /\b(?:apk|chia\s+se\s+man\s+hinh|dieu\s+khien\s+tu\s+xa|ma\s+doc)\b/],
  ["c_evidence", /\b(?:bang\s+chung|chung\s+cu|chup\s+man\s+hinh|giay\s+to)\b/],
  ["c_police", /\b(?:trinh\s+bao|to\s+giac|cong\s+an|a05|tra\s+soat|phong\s+toa)\b/],
  ["c_recovery", /\b(?:lay\s+lai\s+tien|thu\s+hoi\s+tien|lan\s+hai|lan\s+2)\b/],
  ["c_domain", /\b(?:ten\s+mien|duong\s+dan|duong\s+link|link|website|trang\s+web|url)\b/],
  ["c_vietqr", /\b(?:vietqr|ma\s+qr|bin\s+napas|nguoi\s+thu\s+huong)\b/],
  ["c_safety", /\b(?:rui\s+ro\s+thap|chac\s+chan\s+an\s+toan|an\s+toan\s+tuyet\s+doi)\b/],
  ["c_verify", /\b(?:kiem\s+chung|xac\s+minh|doi\s+chieu|kenh\s+chinh\s+thuc)\b/],
  ["c_explain", /\b(?:giai\s+thich|dau\s+hieu\s+rui\s+ro|ket\s+qua|ho\s+so|bao\s+cao)\b/],
  ["c_tactic", /\b(?:thu\s+doan|kich\s+ban|chieu\s+tro|nhan\s+biet)\b/],
  ["c_pressure", /\b(?:hoi\s+thuc|giuc|nghen\s+mang|bao\s+tri)\b/],
];

export function normalizeFollowupText(text: string): string {
  if (!text) return "";
  const lower = text.normalize("NFC").toLowerCase().replace(/đ/g, "d");
  const stripped = lower.normalize("NFD").replace(/\p{Mn}+/gu, "");
  const cleaned = stripped.replace(MD_NOISE_RE, " ").replace(PUNCT_RE, " ");
  const compact = cleaned.replace(WS_RE, " ").trim();
  return compact.replace(PREFIX_RE, "").trim();
}

export function extractFollowupIntents(text: string): Set<string> {
  const norm = normalizeFollowupText(text);
  const out = new Set<string>();
  if (!norm) return out;
  for (const [intent, pat] of INTENT_PATTERNS) {
    if (pat.test(norm)) {
      out.add(intent);
    }
  }
  return out;
}

export function extractSemanticConcepts(text: string): Set<string> {
  const norm = normalizeFollowupText(text);
  const out = new Set<string>();
  if (!norm) return out;
  for (const [concept, pat] of CONCEPT_RULES) {
    if (pat.test(norm)) {
      out.add(concept);
    }
  }
  return out;
}

function contentTokens(normText: string): Set<string> {
  const out = new Set<string>();
  for (const tok of normText.split(" ")) {
    if (tok.length >= 2 && !STOPWORDS.has(tok)) {
      out.add(tok);
    }
  }
  return out;
}

function setIntersectionSize(a: ReadonlySet<string>, b: ReadonlySet<string>): number {
  let count = 0;
  for (const item of a) {
    if (b.has(item)) count += 1;
  }
  return count;
}

export function isDuplicateFollowup(
  candidate: string,
  askedTexts: readonly string[],
  coveredIntents?: ReadonlySet<string>,
): boolean {
  const normCand = normalizeFollowupText(candidate);
  if (!normCand) return true;

  const candIntents = extractFollowupIntents(normCand);
  if (coveredIntents) {
    for (const intent of candIntents) {
      if (coveredIntents.has(intent)) return true;
    }
  }

  const candConcepts = extractSemanticConcepts(normCand);
  const candTokens = contentTokens(normCand);

  for (const asked of askedTexts) {
    const normAsked = normalizeFollowupText(asked);
    if (!normAsked) continue;

    if (normCand === normAsked) return true;
    if (
      normCand.length >= 12 &&
      normAsked.length >= 12 &&
      (normCand.includes(normAsked) || normAsked.includes(normCand))
    ) {
      return true;
    }

    const askedIntents = extractFollowupIntents(normAsked);
    if (setIntersectionSize(candIntents, askedIntents) > 0) {
      return true;
    }

    const askedConcepts = extractSemanticConcepts(normAsked);
    if (candConcepts.size > 0 && askedConcepts.size > 0) {
      const sharedC = setIntersectionSize(candConcepts, askedConcepts);
      const minC = Math.min(candConcepts.size, askedConcepts.size);
      const unionC = candConcepts.size + askedConcepts.size - sharedC;
      if (sharedC >= 2 && (sharedC / minC >= 0.65 || sharedC / unionC >= 0.5)) {
        return true;
      }
    }

    const askedTokens = contentTokens(normAsked);
    if (candTokens.size > 0 && askedTokens.size > 0) {
      const sharedT = setIntersectionSize(candTokens, askedTokens);
      const minT = Math.min(candTokens.size, askedTokens.size);
      const unionT = candTokens.size + askedTokens.size - sharedT;
      if (sharedT >= 3 && (sharedT / minT >= 0.72 || sharedT / unionT >= 0.58)) {
        return true;
      }
    }
  }

  return false;
}

export interface FilterFollowupsOptions {
  askedTexts: readonly string[];
  coveredIntents?: ReadonlySet<string>;
  maxSuggestions?: number;
}

export function filterFollowupSuggestions(
  candidates: readonly string[],
  options: FilterFollowupsOptions,
): string[] {
  const limit = Math.max(0, Math.min(3, options.maxSuggestions ?? 3));
  if (limit === 0 || candidates.length === 0) return [];

  const covered = new Set<string>(options.coveredIntents ?? []);
  for (const asked of options.askedTexts) {
    for (const intent of extractFollowupIntents(asked)) {
      covered.add(intent);
    }
  }

  const selected: string[] = [];
  for (const raw of candidates) {
    if (selected.length >= limit) break;
    const trimmed = raw.trim();
    if (!trimmed) continue;
    if (isDuplicateFollowup(trimmed, options.askedTexts, covered)) continue;
    if (isDuplicateFollowup(trimmed, selected, covered)) continue;
    selected.push(trimmed);
    for (const intent of extractFollowupIntents(trimmed)) {
      covered.add(intent);
    }
  }
  return selected;
}
