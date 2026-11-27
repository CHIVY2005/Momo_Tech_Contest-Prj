import type {
  AnalyzeMode,
  IocType,
  QrKind,
  RadarNode,
  ReceiptVerificationStatus,
  SeverityLevel,
  VerdictLevel,
} from "./types";

export const BRAND_COPY = {
  name: "VeriShield AI",
  tagline: "Trợ lý phòng chống lừa đảo trực tuyến",
  pageTitle: "VeriShield AI — Kiểm tra trước khi chuyển tiền",
  pageDescription:
    "Phát hiện dấu hiệu lừa đảo trong tin nhắn, đường dẫn, mã QR, biên lai và cuộc gọi đáng ngờ.",
  heroHeading: "Kiểm tra trước khi chuyển tiền.",
  heroDescription:
    "Phát hiện dấu hiệu lừa đảo trong tin nhắn, đường dẫn, mã QR, biên lai và cuộc gọi đáng ngờ.",
  footerSummary:
    "Trợ lý hỗ trợ nhận diện dấu hiệu lừa đảo trước khi chuyển tiền.",
  footerLimitation:
    "Kết quả chỉ mang tính tham khảo, không thay thế việc xác minh trực tiếp từ ngân hàng hoặc cơ quan chức năng.",
} as const;

export const SHARED_DISCLAIMERS = {
  merchantHonestyHeading: "Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp",
  merchantHonestyFallback:
    "Ảnh chụp màn hình biên lai không phải là bằng chứng tiền đã vào tài khoản. Hãy kiểm tra trực tiếp biến động số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền trước khi giao hàng.",
  referenceOnly:
    "Kết quả chỉ mang tính hỗ trợ tham khảo, không đảm bảo an toàn tuyệt đối. Hãy tự xác minh qua kênh chính thức trước khi giao dịch.",
} as const;

export const VERDICT_COPY: Record<
  VerdictLevel,
  {
    label: string;
    shortLabel: string;
  }
> = {
  SAFE: {
    label: "Chưa phát hiện dấu hiệu bất thường",
    shortLabel: "Mức rủi ro thấp",
  },
  SUSPICIOUS: {
    label: "Cần thận trọng — nên xác minh thêm",
    shortLabel: "Cần thận trọng",
  },
  HIGH_RISK: {
    label: "Cảnh báo rủi ro cao — tạm dừng giao dịch",
    shortLabel: "Rủi ro cao",
  },
  CRITICAL_SCAM: {
    label: "Cảnh báo rủi ro rất cao — có nhiều dấu hiệu lừa đảo",
    shortLabel: "Rủi ro rất cao",
  },
};

export const MODE_COPY: Record<
  AnalyzeMode,
  {
    label: string;
    shortLabel: string;
    hint: string;
  }
> = {
  personal: {
    label: "Tin nhắn và đường dẫn",
    shortLabel: "Tin nhắn & đường dẫn",
    hint: "Kiểm tra tin nhắn, đường dẫn, mã QR hoặc tệp ghi âm cuộc gọi",
  },
  merchant: {
    label: "Xác minh thanh toán",
    shortLabel: "Xác minh thanh toán",
    hint: "Kiểm tra ảnh biên lai chuyển khoản và đối chiếu mã VietQR",
  },
  wallet_transfer: {
    label: "Trước khi chuyển tiền",
    shortLabel: "Trước chuyển tiền",
    hint: "Đánh giá rủi ro và nhắc tạm dừng 30 giây khi đang nghe điện thoại",
  },
};

export const SEVERITY_COPY: Record<SeverityLevel, string> = {
  CRITICAL: "Rất nghiêm trọng",
  HIGH: "Nghiêm trọng",
  MEDIUM: "Cần lưu ý",
  LOW: "Thấp",
  INFO: "Thông tin bổ sung",
};

export const RECEIPT_STATUS_COPY: Record<ReceiptVerificationStatus, string> = {
  NOT_APPLICABLE: "Không áp dụng",
  UNVERIFIED_SCREENSHOT: "Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp",
  BENEFICIARY_MISMATCH: "Thông tin người nhận không khớp",
  TAMPER_OR_LOGIC_ANOMALY: "Ảnh biên lai có dấu hiệu chỉnh sửa hoặc sai lệch thông tin",
  REPLAYED_RECEIPT: "Ảnh biên lai đã từng xuất hiện trước đó",
};

export const QR_KIND_COPY: Record<QrKind, string> = {
  VALID_VIETQR: "Mã chuyển khoản VietQR đúng định dạng",
  INVALID_CRC_VIETQR: "Mã VietQR lỗi cấu trúc hoặc sai mã kiểm tra",
  URL_QR: "Mã QR dẫn tới trang web",
  TEXT_QR: "Mã QR chứa văn bản thông thường",
};

export const IOC_TYPE_COPY: Record<IocType, string> = {
  bank_account: "Số tài khoản ngân hàng",
  domain: "Tên miền trang web",
  phone: "Số điện thoại",
};

export const RADAR_KIND_COPY: Record<
  RadarNode["kind"],
  {
    label: string;
    shortLabel: string;
    shapeLabel: string;
  }
> = {
  campaign: {
    label: "Nhóm chiến dịch nghi vấn",
    shortLabel: "Chiến dịch",
    shapeLabel: "Hình lục giác",
  },
  bank_account: {
    label: "Số tài khoản (đã che giấu)",
    shortLabel: "Số tài khoản",
    shapeLabel: "Hình tròn",
  },
  domain: {
    label: "Tên miền đáng ngờ",
    shortLabel: "Tên miền",
    shapeLabel: "Hình thoi",
  },
  phone: {
    label: "Số điện thoại nghi vấn",
    shortLabel: "Số điện thoại",
    shapeLabel: "Hình vuông",
  },
};

const EVIDENCE_SOURCE_COPY: Record<string, string> = {
  image_forensics: "Phân tích tính xác thực của hình ảnh",
  vietqr_parser: "Kiểm tra mã QR chuyển khoản",
  url_inspector: "Kiểm tra đường dẫn trang web",
  phishing_sandbox: "Kiểm tra trang web trong môi trường cách ly",
  receipt_validator: "Đối chiếu biên lai chuyển khoản",
  fraud_ops_radar: "Danh sách chặn rủi ro hệ thống",
  guardrails: "Kiểm tra an toàn nội dung",
  ocr_engine: "Trích xuất văn bản từ hình ảnh (OCR)",
  gemini_vision: "Phân tích ngữ cảnh AI",
  pipeline: "Hệ thống tổng hợp",
};

export function formatEvidenceSource(source: string): string {
  return EVIDENCE_SOURCE_COPY[source] ?? "Hệ thống kiểm tra";
}

const CLASSIFIER_LABEL_COPY: Record<string, string> = {
  authority_impersonation: "Giả mạo cơ quan nhà nước hoặc công an",
  fake_bill: "Biên lai chuyển khoản giả hoặc bị chỉnh sửa",
  phishing_link: "Đường dẫn hoặc trang web giả mạo",
  investment_job_scam: "Lừa đảo đầu tư hoặc việc làm trực tuyến",
  safe_legitimate: "Giao dịch hoặc thông báo thông thường",
};

export function formatClassifierLabel(label: string): string {
  return CLASSIFIER_LABEL_COPY[label] ?? label;
}

export const TRACE_STAGES: Array<{ step_id: string; defaultTitle: string }> = [
  {
    step_id: "media_forensics",
    defaultTitle: "Phân tích tính xác thực của hình ảnh, mã QR và ghi âm",
  },
  {
    step_id: "cyber_guardrails",
    defaultTitle: "Kiểm tra đường dẫn đáng ngờ và danh sách chặn",
  },
  {
    step_id: "onnx_and_kb",
    defaultTitle: "Đối chiếu nội dung với các kịch bản lừa đảo phổ biến",
  },
  {
    step_id: "multimodal_calibration",
    defaultTitle: "Tổng hợp bằng chứng và đánh giá mức độ rủi ro",
  },
];
