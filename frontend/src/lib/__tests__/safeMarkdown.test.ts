import assert from "node:assert/strict";
import test from "node:test";

import {
  parseSafeMarkdownBlocks,
  type SafeMarkdownBlock,
  type SafeMarkdownListItem,
} from "../safeMarkdown.ts";

function itemPlainText(item: SafeMarkdownListItem): string {
  return item.tokens.map((tok) => tok.value).join("");
}

test("parseSafeMarkdownBlocks keeps loose ordered lists in a single <ol> without resetting to 1,1,1", () => {
  const md = [
    "1. **Liên hệ ngân hàng ngay** để khóa giao dịch.",
    "",
    "2. **Lưu giữ toàn bộ bằng chứng** gồm ảnh chụp màn hình và mã giao dịch.",
    "",
    "3. **Trình báo Công an xã/phường** gần nhất.",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.type, "ol");
  if (blocks[0]?.type === "ol") {
    assert.equal(blocks[0].start, 1);
    assert.equal(blocks[0].items.length, 3);
    assert.equal(itemPlainText(blocks[0].items[0]!), "Liên hệ ngân hàng ngay để khóa giao dịch.");
    assert.equal(
      itemPlainText(blocks[0].items[1]!),
      "Lưu giữ toàn bộ bằng chứng gồm ảnh chụp màn hình và mã giao dịch.",
    );
    assert.equal(itemPlainText(blocks[0].items[2]!), "Trình báo Công an xã/phường gần nhất.");
  }
});

test("parseSafeMarkdownBlocks preserves parent ordered list numbering across nested unordered lists (2-space and 3-space indent)", () => {
  for (const indent of ["  ", "   "]) {
    const md = [
      "1. **Kiểm tra ứng dụng ngân hàng:**",
      `${indent}- Mở ứng dụng chính thức của ngân hàng`,
      `${indent}- Đối chiếu biến động số dư thực tế`,
      "",
      "2. **Lưu giữ bằng chứng:**",
      `${indent}- Chụp ảnh biên lai và cuộc trò chuyện`,
      `${indent}- Ghi nhận số tài khoản và thời gian`,
      "",
      "3. **Trình báo cơ quan chức năng:**",
      `${indent}- Đến Công an phường gần nhất`,
    ].join("\n");

    const blocks = parseSafeMarkdownBlocks(md);
    assert.equal(blocks.length, 1, `Expected single <ol> for indent=${indent.length}`);
    assert.equal(blocks[0]?.type, "ol");
    if (blocks[0]?.type === "ol") {
      assert.equal(blocks[0].start, 1);
      assert.equal(blocks[0].items.length, 3);

      const firstItem = blocks[0].items[0]!;
      assert.equal(itemPlainText(firstItem), "Kiểm tra ứng dụng ngân hàng:");
      assert.equal(firstItem.children.length, 1);
      assert.equal(firstItem.children[0]?.type, "ul");
      if (firstItem.children[0]?.type === "ul") {
        assert.equal(firstItem.children[0].items.length, 2);
        assert.equal(
          itemPlainText(firstItem.children[0].items[0]!),
          "Mở ứng dụng chính thức của ngân hàng",
        );
      }

      const secondItem = blocks[0].items[1]!;
      assert.equal(itemPlainText(secondItem), "Lưu giữ bằng chứng:");
      assert.equal(secondItem.children.length, 1);
      assert.equal(secondItem.children[0]?.type, "ul");
      if (secondItem.children[0]?.type === "ul") {
        assert.equal(secondItem.children[0].items.length, 2);
      }

      const thirdItem = blocks[0].items[2]!;
      assert.equal(itemPlainText(thirdItem), "Trình báo cơ quan chức năng:");
      assert.equal(thirdItem.children.length, 1);
    }
  }
});

test("parseSafeMarkdownBlocks supports multi-level nested ordered lists without flattening", () => {
  const md = [
    "1. Xử lý tài khoản ngân hàng",
    "   1. Gọi tổng đài in mặt sau thẻ",
    "   2. Khóa thẻ và đổi mật khẩu",
    "      1. Đổi mật khẩu ứng dụng ngân hàng",
    "      2. Đổi mã PIN SmartOTP",
    "2. Thu thập chứng cứ trình báo",
    "   1. Xuất sao kê giao dịch",
    "   2. Tải báo cáo PDF từ VeriShield",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.type, "ol");
  if (blocks[0]?.type === "ol") {
    assert.equal(blocks[0].start, 1);
    assert.equal(blocks[0].items.length, 2);

    const item1 = blocks[0].items[0]!;
    assert.equal(itemPlainText(item1), "Xử lý tài khoản ngân hàng");
    assert.equal(item1.children.length, 1);
    const subOl1 = item1.children[0];
    assert.equal(subOl1?.type, "ol");
    if (subOl1?.type === "ol") {
      assert.equal(subOl1.items.length, 2);
      assert.equal(itemPlainText(subOl1.items[0]!), "Gọi tổng đài in mặt sau thẻ");
      assert.equal(itemPlainText(subOl1.items[1]!), "Khóa thẻ và đổi mật khẩu");
      assert.equal(subOl1.items[1]!.children.length, 1);
      const subSubOl = subOl1.items[1]!.children[0];
      assert.equal(subSubOl?.type, "ol");
      if (subSubOl?.type === "ol") {
        assert.equal(subSubOl.items.length, 2);
        assert.equal(itemPlainText(subSubOl.items[1]!), "Đổi mã PIN SmartOTP");
      }
    }

    const item2 = blocks[0].items[1]!;
    assert.equal(itemPlainText(item2), "Thu thập chứng cứ trình báo");
    assert.equal(item2.children[0]?.type, "ol");
    if (item2.children[0]?.type === "ol") {
      assert.equal(item2.children[0].items.length, 2);
    }
  }
});

test("parseSafeMarkdownBlocks preserves ordered list start when interrupted by unindented paragraph or sibling list", () => {
  const md = [
    "1. Bước đầu tiên",
    "- Ý phụ không thụt lề A",
    "- Ý phụ không thụt lề B",
    "",
    "2. Bước thứ hai",
    "",
    "Đoạn lưu ý tách biệt ở cấp gốc.",
    "",
    "3. Bước thứ ba",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  const olBlocks = blocks.filter((b): b is Extract<SafeMarkdownBlock, { type: "ol" }> => b.type === "ol");
  assert.equal(olBlocks.length, 3);
  assert.equal(olBlocks[0]?.start, 1);
  assert.equal(olBlocks[1]?.start, 2);
  assert.equal(olBlocks[2]?.start, 3);
});

test("parseSafeMarkdownBlocks keeps indented continuation paragraphs and code blocks inside ordered list items", () => {
  const md = [
    "1. **Kiểm tra số thuê bao chính chủ**",
    "",
    "   Soạn tin nhắn theo cú pháp chuẩn để kiểm tra thuê bao đăng ký bằng CCCD:",
    "",
    "   ```text",
    "   TTTB gửi 1414",
    "   ```",
    "",
    "2. **Đối chiếu tài khoản ngân hàng**",
    "   Mở ứng dụng ngân hàng chính thức thay vì bấm liên kết lạ.",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.type, "ol");
  if (blocks[0]?.type === "ol") {
    assert.equal(blocks[0].start, 1);
    assert.equal(blocks[0].items.length, 2);

    const item1 = blocks[0].items[0]!;
    assert.equal(itemPlainText(item1), "Kiểm tra số thuê bao chính chủ");
    assert.equal(item1.children.length, 2);
    assert.equal(item1.children[0]?.type, "paragraph");
    assert.equal(item1.children[1]?.type, "code_block");
    if (item1.children[1]?.type === "code_block") {
      assert.equal(item1.children[1].language, "text");
      assert.equal(item1.children[1].code, "TTTB gửi 1414");
    }

    const item2 = blocks[0].items[1]!;
    assert.ok(itemPlainText(item2).includes("Đối chiếu tài khoản ngân hàng"));
    assert.ok(itemPlainText(item2).includes("Mở ứng dụng ngân hàng chính thức"));
  }
});

test("parseSafeMarkdownBlocks parses fenced code blocks preserving indentation and blank lines", () => {
  const md = [
    "Đoạn mẫu:",
    "",
    "```json",
    "{",
    '  "status": "verify",',
    "",
    '  "steps": [1, 2]',
    "}",
    "```",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 2);
  assert.equal(blocks[1]?.type, "code_block");
  if (blocks[1]?.type === "code_block") {
    assert.equal(blocks[1].language, "json");
    assert.equal(blocks[1].code, '{\n  "status": "verify",\n\n  "steps": [1, 2]\n}');
  }
});

test("parseSafeMarkdownBlocks supports verified official hyperlinks while neutralizing untrusted and dangerous links", () => {
  const md = [
    "Tra cứu tại [Cổng cảnh báo](https://canhbao.khonggianmang.vn) hoặc [VNeID](https://vneid.gov.vn/huong-dan) và [Giám sát](/radar).",
    "",
    "Không bấm [trang giả](https://evil-bank.top/login) hay [xss](javascript:alert(1)).",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 2);

  assert.equal(blocks[0]?.type, "paragraph");
  if (blocks[0]?.type === "paragraph") {
    const links = blocks[0].tokens.filter((t) => t.type === "link");
    assert.equal(links.length, 3);
    assert.deepEqual(links[0], {
      type: "link",
      value: "Cổng cảnh báo",
      href: "https://canhbao.khonggianmang.vn/",
      external: true,
    });
    assert.deepEqual(links[1], {
      type: "link",
      value: "VNeID",
      href: "https://vneid.gov.vn/huong-dan",
      external: true,
    });
    assert.deepEqual(links[2], {
      type: "link",
      value: "Giám sát",
      href: "/radar",
      external: false,
    });
  }

  assert.equal(blocks[1]?.type, "paragraph");
  if (blocks[1]?.type === "paragraph") {
    const serialized = JSON.stringify(blocks[1]);
    assert.ok(!serialized.includes('"href"'), "Untrusted/dangerous links must not emit href");
    assert.ok(!serialized.includes('"link"'), "Untrusted/dangerous links must not emit link tokens");
    assert.ok(!/javascript:/i.test(serialized));
    const joined = blocks[1].tokens.map((t) => t.value).join("");
    assert.equal(joined, "Không bấm trang giả (https://evil-bank.top/login) hay xss.");
  }
});

test("parseSafeMarkdownBlocks keeps masked IOC asterisks verbatim without corrupting adjacent bold text", () => {
  const md = "Tài khoản 19****01 và SĐT 091****678 đang ở mức **rủi ro cao** cần **19****01** đối chiếu.";
  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.type, "paragraph");
  if (blocks[0]?.type === "paragraph") {
    assert.deepEqual(blocks[0].tokens, [
      { type: "text", value: "Tài khoản 19****01 và SĐT 091****678 đang ở mức " },
      { type: "bold", value: "rủi ro cao" },
      { type: "text", value: " cần " },
      { type: "bold", value: "19****01" },
      { type: "text", value: " đối chiếu." },
    ]);
  }
});

test("parseSafeMarkdownBlocks produces consistent AST across multi-chunk streaming and final text", () => {
  const fullMarkdown = [
    "### Hướng dẫn xử lý",
    "",
    "1. **Kiểm tra số dư thực tế**",
    "   - Mở ứng dụng ngân hàng chính thức",
    "   - Kiểm tra loa Soundbox",
    "",
    "2. **Thu thập chứng cứ**",
    "   - Lưu ảnh chụp tin nhắn",
    "   - Tải báo cáo tại [Cổng cảnh báo](https://canhbao.khonggianmang.vn)",
    "",
    "3. **Gửi cú pháp kiểm tra**",
    "   ```text",
    "   TTTB gửi 1414",
    "   ```",
  ].join("\n");

  const expectedFinal = parseSafeMarkdownBlocks(fullMarkdown);
  assert.equal(expectedFinal.length, 2);
  assert.equal(expectedFinal[1]?.type, "ol");
  if (expectedFinal[1]?.type === "ol") {
    assert.equal(expectedFinal[1].items.length, 3);
  }

  // Stream in 7-character chunks (splits mid-word, mid-marker, mid-fence, mid-link)
  let accumulated = "";
  let prevOlCount = 0;
  for (let offset = 0; offset < fullMarkdown.length; offset += 7) {
    accumulated += fullMarkdown.slice(offset, offset + 7);
    const partialBlocks = parseSafeMarkdownBlocks(accumulated);
    assert.ok(Array.isArray(partialBlocks));
    const olBlocks = partialBlocks.filter((b) => b.type === "ol");
    // Ordered list must NEVER fragment into multiple <ol> blocks during streaming
    assert.ok(
      olBlocks.length <= 1,
      `Ordered list fragmented into ${olBlocks.length} <ol> blocks at offset ${offset}: ${JSON.stringify(partialBlocks)}`,
    );
    if (olBlocks[0]?.type === "ol") {
      assert.ok(olBlocks[0].items.length >= prevOlCount);
      prevOlCount = olBlocks[0].items.length;
    }
  }

  // Final streamed parse MUST equal single-shot parse identically
  assert.deepEqual(parseSafeMarkdownBlocks(accumulated), expectedFinal);
});
