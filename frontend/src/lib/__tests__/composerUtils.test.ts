import assert from "node:assert/strict";
import test from "node:test";

import {
  ATTACHMENT_LIMITS,
  extractClipboardImages,
  extractUrlsFromText,
  formatAttachmentSize,
  inferAnalyzeMode,
  validateAttachmentBatch,
} from "../composerUtils.ts";

function makeFakeFile(name: string, type: string, sizeBytes: number): File {
  const bytes = new Uint8Array(sizeBytes);
  return new File([bytes], name, { type });
}

test("extractUrlsFromText detects explicit http(s) and scheme-less web domains without duplicates or filenames", () => {
  const txt =
    "Truy cập https://napas-diemthuong-247.top/verify, xem lại www.vneid-check.vip hoặc " +
    "https://napas-diemthuong-247.top/verify. Đừng nhầm ảnh bill.jpg hay app.apk.";
  const urls = extractUrlsFromText(txt);
  assert.deepEqual(urls, [
    "https://napas-diemthuong-247.top/verify",
    "https://www.vneid-check.vip",
  ]);
});

test("extractClipboardImages extracts image blobs, synthesizes filenames, and flags whether plain text exists", () => {
  const pngFile = makeFakeFile("", "image/png", 1024);
  const resImgOnly = extractClipboardImages({
    getData: (fmt: string) => (fmt === "text/plain" ? "" : ""),
    items: [
      {
        kind: "file",
        type: "image/png",
        getAsFile: () => pngFile,
      },
    ],
    files: [pngFile],
  });
  assert.equal(resImgOnly.hasPlainText, false);
  assert.equal(resImgOnly.images.length, 1);
  assert.match(resImgOnly.images[0]!.name, /^clipboard-image-1\.png$/);

  // Normal plain text paste must report hasPlainText=true and 0 images
  const resTextOnly = extractClipboardImages({
    getData: (fmt: string) => (fmt === "text/plain" ? "Xin chào bạn" : ""),
    items: [
      {
        kind: "string",
        type: "text/plain",
        getAsFile: () => null,
      },
    ],
    files: [],
  });
  assert.equal(resTextOnly.hasPlainText, true);
  assert.equal(resTextOnly.images.length, 0);
});

test("validateAttachmentBatch enforces count, per-file size, total size, and MIME/extension allowlists", () => {
  const okImg = makeFakeFile("bill.png", "image/png", 2048);
  const okAud = makeFakeFile("call.wav", "audio/wav", 2048);

  const ok = validateAttachmentBatch([], [], [okImg, okAud]);
  assert.equal(ok.acceptedImages.length, 1);
  assert.equal(ok.acceptedAudios.length, 1);
  assert.equal(ok.errors.length, 0);

  // Exceeding MAX_IMAGES (4) rejects extras cleanly
  const existingFour = [1, 2, 3, 4].map((i) => makeFakeFile(`img${i}.jpg`, "image/jpeg", 512));
  const overImg = validateAttachmentBatch(existingFour, [], [makeFakeFile("img5.jpg", "image/jpeg", 512)]);
  assert.equal(overImg.acceptedImages.length, 0);
  assert.ok(overImg.errors[0]?.includes(String(ATTACHMENT_LIMITS.maxImages)));

  // Disallowed SVG/EXE rejected
  const badSvg = validateAttachmentBatch([], [], [makeFakeFile("xss.svg", "image/svg+xml", 256)]);
  assert.equal(badSvg.acceptedImages.length, 0);
  assert.equal(badSvg.errors.length, 1);

  // Oversize single file (> 10 MB) rejected
  const tooBig = makeFakeFile("huge.png", "image/png", ATTACHMENT_LIMITS.maxFileBytes + 1);
  const resBig = validateAttachmentBatch([], [], [tooBig]);
  assert.equal(resBig.acceptedImages.length, 0);
  assert.equal(resBig.errors.length, 1);

  // Total batch cap (> 20 MB) enforced across multiple valid files
  const nineMb = makeFakeFile("a.jpg", "image/jpeg", 9 * 1024 * 1024);
  const nineMb2 = makeFakeFile("b.jpg", "image/jpeg", 9 * 1024 * 1024);
  const fourMb = makeFakeFile("c.jpg", "image/jpeg", 4 * 1024 * 1024);
  const resTotal = validateAttachmentBatch([nineMb, nineMb2], [], [fourMb]);
  assert.equal(resTotal.acceptedImages.length, 0);
  assert.ok(resTotal.errors[0]?.includes("20 MB"));
});

test("inferAnalyzeMode selects merchant, wallet_transfer, or personal automatically (Option A)", () => {
  assert.equal(
    inferAnalyzeMode({
      expectedMerchantAccount: "190311112222",
      transferAmount: "",
      inActiveCall: false,
    }),
    "merchant",
  );
  assert.equal(
    inferAnalyzeMode({
      expectedMerchantAccount: "",
      transferAmount: "15000000",
      inActiveCall: false,
    }),
    "wallet_transfer",
  );
  assert.equal(
    inferAnalyzeMode({
      expectedMerchantAccount: "",
      transferAmount: "",
      inActiveCall: true,
    }),
    "wallet_transfer",
  );
  assert.equal(
    inferAnalyzeMode({
      expectedMerchantAccount: "",
      transferAmount: "",
      inActiveCall: false,
    }),
    "personal",
  );
});

test("formatAttachmentSize formats B, KB, and MB cleanly", () => {
  assert.equal(formatAttachmentSize(512), "512 B");
  assert.equal(formatAttachmentSize(2048), "2.0 KB");
  assert.equal(formatAttachmentSize(2 * 1024 * 1024), "2.00 MB");
});
