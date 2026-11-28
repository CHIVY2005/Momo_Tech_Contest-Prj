import assert from "node:assert/strict";
import test from "node:test";

import {
  filterFollowupSuggestions,
  isDuplicateFollowup,
  normalizeFollowupText,
} from "../assistantFollowups.ts";
import {
  applyFollowupSelection,
  buildSessionKey,
  createAssistantSessionStore,
  reconcileAssistantMessages,
  type AssistantSessionMessage,
} from "../assistantSession.ts";
import { parseSafeMarkdownBlocks } from "../safeMarkdown.ts";

test("normalizeFollowupText and isDuplicateFollowup catch exact and semantic Vietnamese duplicates", () => {
  assert.equal(
    normalizeFollowupText("Xin hỏi: Tôi lỡ chuyển tiền rồi, cần làm gì ngay?!"),
    normalizeFollowupText("toi lo chuyen tien roi can lam gi ngay"),
  );

  assert.equal(
    isDuplicateFollowup(
      "Tôi lỡ chuyển tiền rồi thì cần làm gì ngay trong 60 phút đầu?",
      ["Mình vừa chuyển khoản nhầm cho kẻ gian mất rồi, bây giờ xử lý sao?"],
    ),
    true,
  );
  assert.equal(
    isDuplicateFollowup(
      "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?",
      ["Khách đưa ảnh bill chuyển tiền, mình giao hàng luôn được chưa?"],
    ),
    true,
  );
  assert.equal(
    isDuplicateFollowup(
      "Cần thu thập và lưu những bằng chứng nào để trình báo Công an?",
      ["Tôi nên giữ lại giấy tờ hay chụp màn hình chứng cứ gì để nộp?"],
    ),
    true,
  );
  assert.equal(
    isDuplicateFollowup(
      "Cách kiểm tra mã VietQR và thông tin người thụ hưởng trước khi chuyển tiền?",
      ["Tôi lỡ chuyển tiền cho kẻ lừa đảo rồi thì cần làm gì ngay?"],
    ),
    false,
  );
});

test("continuous 10-turn conversation never repeats asked or semantically covered follow-ups beyond backend 6-pair window", () => {
  const serverPool = [
    "Tôi lỡ chuyển tiền rồi thì cần làm gì ngay trong 60 phút đầu?",
    "Tôi lỡ cung cấp mã OTP hoặc mật khẩu ngân hàng thì xử lý sao?",
    "Tôi lỡ cài tệp .apk hoặc chia sẻ màn hình thì cần ngắt mạng và gỡ thế nào?",
    "Cần thu thập và lưu những bằng chứng nào để trình báo Công an?",
    "Quy trình trình báo Công an và yêu cầu ngân hàng tra soát như thế nào?",
    "Làm sao tránh bẫy dịch vụ lấy lại tiền bị lừa lần hai trên mạng?",
    "Làm sao phân biệt tên miền ngân hàng thật và trang giả mạo?",
    "Cách kiểm tra mã VietQR và thông tin người thụ hưởng trước khi chuyển tiền?",
    "Nên cảnh báo gì cho người thân để tránh mắc cùng kịch bản này?",
    "Thủ đoạn lừa đảo liên quan hoạt động như thế nào và làm sao phòng tránh sớm?",
  ];

  let messages: AssistantSessionMessage[] = [];
  let askedQuestions: string[] = [];

  for (let turn = 0; turn < 10; turn += 1) {
    // Turn 0..2 use paraphrases; later turns pick from remaining suggestions
    const userPrompt =
      turn === 0
        ? "Mình vừa chuyển khoản nhầm cho kẻ gian, giờ cần làm gì?"
        : turn === 1
          ? "Em lỡ đọc mã OTP cho người lạ rồi phải khóa tài khoản thế nào?"
          : messages[messages.length - 1]?.suggestedFollowups?.[0] ??
            `Câu hỏi bổ sung lượt ${turn + 1}`;

    const selected = applyFollowupSelection(messages, askedQuestions, userPrompt);
    messages = selected.messages;
    askedQuestions = selected.askedQuestions;

    // Immediately after selection, NO existing assistant message may retain suggestions
    for (const m of messages) {
      if (m.role === "assistant") {
        assert.deepEqual(m.suggestedFollowups ?? [], []);
      }
    }

    const replyMd = [
      `1. **Bước xử lý chính lượt ${turn + 1}**`,
      "   - Kiểm tra trực tiếp trên ứng dụng ngân hàng",
      "   - Ghi nhận thời gian và mã giao dịch",
      "",
      "2. **Bước tiếp theo**",
      "   - Lưu toàn bộ bằng chứng liên quan",
    ].join("\n");

    // Verify Markdown keeps single <ol> across all 10 turns
    const parsed = parseSafeMarkdownBlocks(replyMd);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]?.type, "ol");
    if (parsed[0]?.type === "ol") {
      assert.equal(parsed[0].items.length, 2);
    }

    messages = reconcileAssistantMessages(
      [
        ...messages,
        { id: `u-${turn}`, role: "user", content: userPrompt },
        {
          id: `a-${turn}`,
          role: "assistant",
          content: replyMd,
          isStreaming: false,
          // Simulate backend sending full pool (e.g. after Turn 1 drops off 6-pair backend window!)
          suggestedFollowups: serverPool,
        },
      ],
      { askedQuestions },
    );

    const latest = messages[messages.length - 1]!;
    const fups = latest.suggestedFollowups ?? [];
    assert.ok(fups.length <= 3);
    for (const q of fups) {
      assert.equal(
        isDuplicateFollowup(q, askedQuestions),
        false,
        `Turn ${turn + 1} re-suggested previously asked/paraphrased question: ${q}`,
      );
    }
  }

  // After all 10 distinct topics are asked, no follow-ups remain -> []
  const exhausted = filterFollowupSuggestions(serverPool, { askedTexts: askedQuestions });
  assert.deepEqual(exhausted, []);
});

test("reconcileAssistantMessages shows follow-ups only on latest completed non-errored assistant turn", () => {
  const streamingThread = reconcileAssistantMessages(
    [
      { id: "u1", role: "user", content: "Giải thích hồ sơ này?" },
      {
        id: "a1",
        role: "assistant",
        content: "Phản hồi 1",
        isStreaming: false,
        suggestedFollowups: ["Câu hỏi 1?"],
      },
      { id: "u2", role: "user", content: "Hỏi tiếp?" },
      {
        id: "a2",
        role: "assistant",
        content: "Đang viết...",
        isStreaming: true,
        suggestedFollowups: ["Câu hỏi 2?"],
      },
    ],
    {},
  );
  assert.deepEqual(streamingThread[1]?.suggestedFollowups, []);
  assert.deepEqual(streamingThread[3]?.suggestedFollowups, []);

  const erroredThread = reconcileAssistantMessages(
    [
      { id: "u1", role: "user", content: "Hỏi?" },
      {
        id: "a1",
        role: "assistant",
        content: "",
        isStreaming: false,
        errorMessage: "Lỗi kết nối",
        suggestedFollowups: ["Câu hỏi 1?"],
      },
    ],
    {},
  );
  assert.deepEqual(erroredThread[1]?.suggestedFollowups, []);
});

test("session store isolates history between cases and detached mode, and reconciles cleanly on conversation reload", () => {
  const store = createAssistantSessionStore(4);
  const keyCaseA = buildSessionKey("vs_case_a", false);
  const keyCaseB = buildSessionKey("vs_case_b", false);
  const keyGeneral = buildSessionKey("vs_case_a", true);

  assert.notEqual(keyCaseA, keyCaseB);
  assert.notEqual(keyCaseA, keyGeneral);

  // Populate Case A with 2 turns
  store.save({
    sessionKey: keyCaseA,
    askedQuestions: ["Tôi lỡ chuyển tiền rồi cần làm gì ngay?"],
    messages: [
      { id: "u1", role: "user", content: "Tôi lỡ chuyển tiền rồi cần làm gì ngay?" },
      {
        id: "a1",
        role: "assistant",
        content: "1. Gọi ngân hàng\n\n2. Lưu bằng chứng",
        isStreaming: false,
        suggestedFollowups: [
          "Tôi lỡ chuyển tiền rồi thì cần làm gì ngay trong 60 phút đầu?",
          "Cần thu thập và lưu những bằng chứng nào để trình báo Công an?",
        ],
      },
    ],
  });

  // Switching to Case B or detached general mode starts cleanly isolated
  assert.equal(store.get(keyCaseB), null);
  assert.equal(store.get(keyGeneral), null);

  // Populate Case B independently
  store.save({
    sessionKey: keyCaseB,
    askedQuestions: ["Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?"],
    messages: [
      {
        id: "ub1",
        role: "user",
        content: "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?",
      },
      {
        id: "ab1",
        role: "assistant",
        content: "Kiểm tra số dư thực tế trước khi giao hàng.",
        isStreaming: false,
        suggestedFollowups: ["Cách đối chiếu tiền đã thực sự vào tài khoản và loa Soundbox?"],
      },
    ],
  });

  // Reloading Case A restores Case A only, reconciles follow-ups (stripping duplicate transfer question),
  // and keeps Case B completely untouched!
  const reloadedA = store.reload(keyCaseA);
  assert.ok(reloadedA !== null);
  assert.equal(reloadedA.messages.length, 2);
  assert.equal(reloadedA.messages[0]?.content, "Tôi lỡ chuyển tiền rồi cần làm gì ngay?");
  assert.deepEqual(reloadedA.messages[1]?.suggestedFollowups, [
    "Cần thu thập và lưu những bằng chứng nào để trình báo Công an?",
  ]);

  const reloadedB = store.reload(keyCaseB);
  assert.ok(reloadedB !== null);
  assert.equal(reloadedB.messages.length, 2);
  assert.equal(
    reloadedB.messages[0]?.content,
    "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?",
  );

  // Deleting Case A leaves Case B intact
  store.delete(keyCaseA);
  assert.equal(store.get(keyCaseA), null);
  assert.ok(store.get(keyCaseB) !== null);
});
