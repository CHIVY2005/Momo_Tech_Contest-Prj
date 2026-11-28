# VeriShield — Đo hiệu năng kéo khung chat

## Nguyên nhân

- `pointermove` gọi `setPreferredWidth`, đưa mỗi lần thay đổi chiều rộng qua React. Drawer dựng lại JSX cho header, composer và toàn bộ message list; renderer Markdown còn phân tích lại cả các tin nhắn không đổi.
- Chiều rộng thực sự thay đổi nên trình duyệt phải layout lại văn bản, kể cả Markdown đang ngoài vùng nhìn. `ResizeObserver`, hiệu ứng theo nội dung và `onScroll` còn đọc geometry, ghi `scrollTop` và cập nhật React trong lúc kéo. Các số CDP bên dưới đo tổng layout; không tách riêng phần layout đồng bộ bị cưỡng bức theo call stack.
- Không có width transition hoặc backdrop blur trên khung docked. Không thấy ghi `localStorage` trong lúc kéo ở baseline; shadow và hiệu ứng màu được giữ nguyên.

## Thay đổi

- `useAssistantPanel.ts` giữ Pointer Capture và tọa độ mới nhất bằng ref. Mỗi frame chỉ ghi CSS width khi giá trị thay đổi, không đọc layout và không cập nhật React. Khi kết thúc, áp dụng tọa độ cuối ngay, hủy frame chờ, giải phóng capture và chỉ lưu khi kích thước thay đổi. Đóng hoặc đổi chế độ trong lúc kéo dọn trạng thái tạm.
- `useAssistantScroll.ts` tạm ngưng auto-scroll và đo vị trí đọc trong lúc kéo. Trình duyệt tự giữ điểm neo khi có thể; ứng dụng khôi phục vị trí tương đối hoặc trạng thái bám đáy sau khi thả. Với từ 20 tin nhắn, đọc kích thước các message trong một lượt trước khi ghi và dùng `content-visibility: auto` trong lúc kéo để bỏ qua phần ngoài vùng nhìn. Không tháo message khỏi DOM và không đổi ngữ nghĩa danh sách.
- `globals.css` giữ biến chiều rộng không kế thừa để tránh invalidation xuống toàn bộ cây con, chỉ bật containment khi cần. `AssistantDrawer.tsx` nối vòng đời kéo với scroll; `SafeMarkdown.tsx` memo hóa kết quả render khi `content` và `className` không đổi. Không thêm dependency hoặc thay đổi luồng API.

## Kết quả trước → sau

Windows, Edge headless 158, production build cục bộ, viewport 1440 × 850. Mỗi kịch bản kéo qua min/max rồi đổi hướng nhanh (106 bước đầu vào); Markdown và SSE là fixture tổng hợp. Commit đếm bằng React DevTools hook; p95 là khoảng thời gian giữa hai callback `requestAnimationFrame` liên tiếp; layout/script là tổng thời gian theo CDP trong toàn lượt đo, không phải thời gian trên một frame.

| Kịch bản | React commit trong lúc giữ chuột | p95 giữa hai frame | Layout tổng | Script tổng | Khoảng frame >25 ms | Long task |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 tin, đang stream | 94 → 1 | 7,0 → 7,1 ms | 3,9 → 44,0 ms | 76,4 → 21,3 ms | 1 → 1 | 0 → 0 |
| 50 tin, đã hoàn tất | 139 → 0 | 41,7 → 7,1 ms | 601,1 → 98,7 ms | 742,1 → 28,4 ms | 106 → 1 | 6 → 0 |
| 50 tin, đang stream | 142 → 1 | 48,7 → 7,1 ms | 611,4 → 98,0 ms | 707,8 → 28,0 ms | 111 → 1 | 17 → 1 |

Bản trung gian không bật containment đã bỏ các React commit do kéo nhưng p95 của cả hai kịch bản 50 tin vẫn là 27,8 ms. Bản cuối cũng thực hiện nhiều layout pass hơn ở kịch bản ngắn; p95 của kịch bản này gần như không đổi. Mỗi kịch bản stream còn một commit trong lúc giữ chuột do nội dung SSE thay đổi. Bản cuối chờ thêm hai RAF sau release để đo cả bước khôi phục vị trí đọc.

Đây là kết quả trên một môi trường headless, không phải cam kết FPS trên mọi thiết bị. p95 của kịch bản dài dưới ngân sách 16,67 ms trong lần đo này, nhưng vẫn có outlier; chưa xác minh trên màn hình vật lý 60/120/144 Hz hoặc với LLM thật.

## Tái lập

Khởi động frontend từ production build theo `frontend/package.json`, rồi chạy từ repo root:

```powershell
backend/.venv/Scripts/python.exe scripts/verify_assistant_workspace.py --channel msedge --profile-resize --expect-optimized
backend/.venv/Scripts/python.exe scripts/verify_assistant_workspace.py --channel msedge
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
```

Để đo baseline, chạy cùng harness trên production build trước thay đổi và bỏ `--expect-optimized`. Hồi quy xác minh min/max width, vị trí đọc, không auto-scroll khi kéo, streaming không gửi lại request, keyboard, fullscreen, standalone, Markdown và không tràn ngang tại 375/768/1024/1440/1920 px. Gate dự án đạt Ruff, Mypy, TypeScript strict, 432 backend tests, 72 frontend tests và production build.
