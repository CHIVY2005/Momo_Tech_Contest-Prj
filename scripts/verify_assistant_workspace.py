"""Exercise the chat UX in a real browser with synthetic case and SSE fixtures."""

import argparse
import base64
import json
import time
from collections.abc import Callable

from playwright.sync_api import Browser, BrowserContext, Page, Route, expect, sync_playwright

FIRST_QUESTION = "Tại sao hồ sơ này có rủi ro?"
SECOND_QUESTION = "Tôi nên lưu bằng chứng nào?"
SOURCE = "Nguồn tư vấn mẫu"
MARKDOWN = (
    "## Kiểm tra liên kết\n\n"
    "Tên miền example.top và phần mở rộng `.top`.\n\n"
    "3. Mục thứ ba\n   - Mục lồng nhau\n4. Mục thứ tư\n\n"
    + f"[{'https://vietcombank.com.vn/' + 'a' * 420}]({'https://vietcombank.com.vn/' + 'a' * 420})\n\n"
    + f"`{'b' * 500}`\n\n```text\n{'c' * 500}\n```\n\n"
    + "\n\n".join(f"**Đoạn {index}:** " + "Nội dung thử nghiệm. " * 8 for index in range(20))
)


def report(case_id: str, score: int) -> dict:
    return {
        "case_id": case_id,
        "created_at": "2026-11-27T00:00:00Z",
        "mode": "personal",
        "in_active_call": False,
        "risk_score": score,
        "verdict": "SUSPICIOUS",
        "confidence": 0.9,
        "degraded_mode": False,
        "safety_advisory_detected": False,
        "prompt_injection_detected": False,
        "active_block_rule_hit": False,
        "receipt_verification_status": "NOT_APPLICABLE",
        "summary_vi": "Hồ sơ tổng hợp cho kiểm thử giao diện.",
        "transcript": None,
        "classifier": None,
        "matched_playbooks": [],
        "manipulation_tactics": [],
        "highlighted_phrases": [],
        "iocs": {"phones": [], "bank_accounts": [], "urls": [], "domains": [], "brands": []},
        "vietqr_findings": [],
        "url_findings": [],
        "sandbox": None,
        "image_forensics": None,
        "receipt_logic": None,
        "evidence": [],
        "actions": {
            "counter_replies": [],
            "family_shield_message": "",
            "urgent_steps": [],
            "merchant_balance_warning": None,
            "pre_transfer": {
                "should_hold_transfer": False,
                "cooling_off_seconds": 0,
                "triggered_by_active_call": False,
                "blocked_by_ops_rule": False,
                "warning_headline": "",
                "verification_questions": [],
            },
        },
        "trace": [],
        "community_hits": 0,
    }


def frame(event: str, value: object) -> str:
    return f"event: {event}\ndata: {json.dumps(value)}\n\n"


def stream_fixture() -> str:
    values = json.dumps({
        "markdown": MARKDOWN, "suggestions": [FIRST_QUESTION, SECOND_QUESTION], "source": SOURCE,
    })
    return f"const fixture = {values};\n" + """
        window.chatFixture = { calls: [], streams: [] };
        const originalFetch = window.fetch;
        window.fetch = (input, init) => {
          if (new URL(String(input), location.href).pathname !== '/api/v1/assistant/chat/stream') {
            return originalFetch(input, init);
          }
          const payload = JSON.parse(init.body);
          chatFixture.calls.push({
            payload, hasHeader: new Headers(init.headers).has('X-Case-Access-Token'),
          });
          const encoder = new TextEncoder();
          const body = new ReadableStream({ start(controller) {
            const emit = (event, data) => controller.enqueue(encoder.encode(
              `event: ${event}\\ndata: ${JSON.stringify(data)}\\n\\n`
            ));
            emit('delta', {text: fixture.markdown});
            emit('citation', {items: [{id: 'fixture', source_type: 'kb', title: fixture.source}]});
            chatFixture.streams.push({
              add: () => emit('delta', {text: '\\n\\nĐoạn nhận thêm trong lúc đang đọc.'}),
              finish: () => {
                emit('done', {
                  degraded_mode: false, output_tier: 2, suggested_followups: fixture.suggestions,
                });
                controller.close();
              },
            });
            const signal = init.signal;
            signal?.addEventListener('abort', () => controller.error(signal.reason), {once: true});
          } });
          return Promise.resolve(new Response(body, {headers: {'Content-Type': 'text/event-stream'}}));
        };
        """


def check_layout(page: Page) -> None:
    panel = page.locator("#assistant-chat-panel")
    handle = page.get_by_role("separator", name="Chiều rộng khung chat")
    for width in (375, 768, 1024, 1440, 1920):
        page.set_viewport_size({"width": width, "height": 850})
        if width == 375:
            expect(handle).to_have_count(0)
            expect(panel).to_have_css("width", "375px")
        else:
            expect(handle).to_be_visible()
            handle.press("Home")
            expect(panel).to_have_css("width", "400px")
            handle.press("End")
            expect(panel).to_have_css("width", f"{int(width * 0.85)}px")
            handle.press("Enter")
            expect(panel).to_have_css("width", "620px")
        markdown = page.locator(".assistant-markdown").first
        assert markdown.evaluate("node => node.scrollWidth <= node.clientWidth + 1")
        expect(markdown.locator("ol[start='3'] > li > div > ul > li")).to_have_text("Mục lồng nhau")
        assert markdown.locator("pre").evaluate("node => node.scrollWidth > node.clientWidth")
        inline = markdown.locator(".assistant-inline-code").first
        expect(inline).to_have_text(".top")
        assert inline.evaluate("""node => {
          const range = document.createRange();
          range.selectNodeContents(node);
          return range.getClientRects().length === 1;
        }""")
    print("PASS: 375 / 768 / 1024 / 1440 / 1920px, keyboard bounds, inline code, nested list, overflow")


def profile_resize(
    context: BrowserContext, page: Page, base_url: str, analyze: Callable[[], None], optimized: bool,
) -> None:
    cdp = context.new_cdp_session(page)
    cdp.send("Performance.enable")

    def metrics() -> dict[str, float]:
        return {item["name"]: item["value"] for item in cdp.send("Performance.getMetrics")["metrics"]}

    for history_size, streaming in ((0, True), (50, False), (48, True)):
        if page.url != "about:blank":
            page.evaluate("sessionStorage.clear()")
        page.goto(base_url)
        analyze()
        if history_size:
            page.wait_for_function("() => sessionStorage.getItem('verishield.chat.home') !== null")
            page.evaluate("""({count, markdown}) => {
                const {id} = JSON.parse(sessionStorage.getItem('verishield.chat.home'));
                const key = `verishield.chat.${id}`;
                const record = JSON.parse(sessionStorage.getItem(key));
                record.snapshot.messages = Array.from({length: count}, (_, index) => ({
                    id: `profile-${index}`, role: index % 2 ? 'assistant' : 'user',
                    content: index % 2 ? markdown : `Synthetic question ${index}`,
                }));
                sessionStorage.setItem(key, JSON.stringify(record));
            }""", {"count": history_size, "markdown": MARKDOWN})
            page.reload()
        if streaming:
            composer = page.locator("#assistant-composer-input")
            composer.fill(FIRST_QUESTION)
            composer.press("Enter")
        thread = page.locator(".assistant-thread")
        message_count = history_size + (2 if streaming else 0)
        expect(thread.locator("[data-chat-message]")).to_have_count(message_count)
        handle = page.get_by_role("separator")
        box = handle.bounding_box()
        assert box
        center = box["x"] + box["width"] / 2
        height = box["y"] + box["height"] / 2
        page.mouse.move(center, height)
        thread.evaluate("node => node.scrollTop = node.scrollHeight * 0.35")
        expect(page.locator('button[title="Cuộn xuống cuối hội thoại"]')).to_be_visible()
        reading_position = """thread => {
            const top = thread.getBoundingClientRect().top;
            const message = [...thread.querySelectorAll('[data-chat-message]')]
                .find(node => node.getBoundingClientRect().bottom > top);
            const rect = message.getBoundingClientRect();
            return {id: message.dataset.chatMessage, ratio: (top - rect.top) / rect.height};
        }"""
        reading = thread.evaluate(reading_position)
        page.evaluate("""() => {
            const panel = document.querySelector('.assistant-panel');
            const probe = window.resizeProbe = {frames: [], widths: 0, commits: 0, writes: 0, longTasks: 0};
            const setItem = Storage.prototype.setItem;
            Storage.prototype.setItem = function(key, value) {
                if (key === 'verishield.assistant.width') probe.writes++;
                return setItem.call(this, key, value);
            };
            const styles = new MutationObserver(records => { probe.widths += records.length; });
            styles.observe(panel, {attributes: true, attributeFilter: ['style']});
            const tasks = new PerformanceObserver(list => { probe.longTasks += list.getEntries().length; });
            tasks.observe({entryTypes: ['longtask']});
            let previous;
            const tick = now => {
                if (previous) probe.frames.push(now - previous);
                previous = now;
                probe.frame = requestAnimationFrame(tick);
            };
            probe.frame = requestAnimationFrame(tick);
            probe.stop = () => {
                cancelAnimationFrame(probe.frame);
                styles.disconnect();
                tasks.disconnect();
                Storage.prototype.setItem = setItem;
            };
        }""")
        before = metrics()
        page.mouse.down()
        panel = page.locator(".assistant-panel")
        page.mouse.move(center - 900, height, steps=20)
        expect(panel).to_have_css("width", "1224px")
        page.mouse.move(center + 320, height, steps=27)
        expect(panel).to_have_css("width", "400px")
        if streaming:
            page.evaluate("chatFixture.streams[0].add()")
        page.mouse.move(center - 300, height, steps=23)
        page.mouse.move(center + 130, height, steps=21)
        page.mouse.move(center - 140, height, steps=15)
        drag_commits = page.evaluate("resizeProbe.commits")
        assert page.evaluate("resizeProbe.writes") == 0
        page.mouse.up()
        expect(panel).to_have_css("width", "760px")
        wait_for_paint(page)
        after = metrics()
        probe = page.evaluate("() => { resizeProbe.stop(); return resizeProbe; }")
        frames = sorted(probe["frames"])
        print(json.dumps({
            "messages": message_count, "streaming": streaming,
            "drag_commits": drag_commits, "width_writes": probe["widths"], "long_tasks": probe["longTasks"],
            "frame_p95_ms": round(frames[int(0.95 * (len(frames) - 1))], 2),
            "frames_over_25ms": sum(frame > 25 for frame in frames), "frames": len(frames),
            **{
                key: round((after[key] - before[key]) * (1000 if key.endswith("Duration") else 1), 2)
                for key in (
                    "LayoutCount", "RecalcStyleCount", "LayoutDuration", "ScriptDuration", "TaskDuration",
                )
            },
        }), flush=True)
        if optimized:
            assert drag_commits <= (2 if streaming else 0), drag_commits
            assert probe["writes"] == 1, probe["writes"]
            assert page.evaluate("chatFixture.calls.length") == int(streaming)
            after_reading = thread.evaluate(reading_position)
            assert after_reading["id"] == reading["id"], (after_reading, reading)
            assert abs(after_reading["ratio"] - reading["ratio"]) < 0.03, (after_reading, reading)
            assert thread.evaluate("node => node.scrollWidth <= node.clientWidth + 1")
        page.evaluate("localStorage.removeItem('verishield.assistant.width')")


def wait_for_paint(page: Page) -> None:
    page.evaluate("""() => new Promise(resolve => {
        requestAnimationFrame(() => requestAnimationFrame(resolve));
    })""")


def verify(browser: Browser, base_url: str, profile: bool = False, optimized: bool = False) -> None:
    context = browser.new_context(viewport={"width": 1440, "height": 850}, reduced_motion="reduce")
    context.add_init_script(stream_fixture())
    if profile:
        context.add_init_script("""window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {
            supportsFiber: true,
            inject() { return 1; },
            onCommitFiberRoot() { if (window.resizeProbe) resizeProbe.commits++; },
        };""")
    cases: dict[str, tuple[dict, str]] = {}
    auth_requests: list[str] = []
    denied_cases: set[str] = set()

    def handle_api(route: Route) -> None:
        path = route.request.url.split("/api/v1/", 1)[1]
        if path == "analyze/stream":
            case_id = f"vs_{len(cases) + 1:032x}"
            data = report(case_id, 46 + len(cases))
            expiry = int(time.time()) + 3600
            claims = base64.urlsafe_b64encode(json.dumps({"cid": case_id, "exp": expiry}).encode())
            access = claims.decode().rstrip("=") + ".synthetic-fixture"
            cases[case_id] = (data, access)
            body = frame("result", data) + frame("session", {
                "case_id": case_id, "case_access_token": access, "expires_at": "2099-01-01T02:00:00Z",
            })
            route.fulfill(status=200, content_type="text/event-stream", body=body)
        elif path.startswith("cases/"):
            case_id = path.split("/", 1)[1]
            data, access = cases[case_id]
            auth_requests.append(case_id)
            allowed = (
                route.request.headers.get("x-case-access-token") == access and case_id not in denied_cases
            )
            route.fulfill(status=200 if allowed else 403, json=data if allowed else {})
        elif path == "demos":
            route.fulfill(status=200, json=[])
        else:
            route.fulfill(status=503, json={})

    context.route("**/api/v1/**", handle_api)
    page = context.new_page()
    page.goto(base_url)

    def analyze() -> None:
        page.locator("textarea").first.fill("Tình huống giả lập do kiểm thử tạo.")
        page.locator("form").first.locator("button[type='submit']").click()
        page.locator("#assistant-launcher").click()

    if profile:
        profile_resize(context, page, base_url, analyze, optimized)
        context.close()
        return

    analyze()
    composer = page.locator("#assistant-composer-input")
    composer.fill(FIRST_QUESTION)
    composer.press("Enter")
    panel = page.locator("#assistant-chat-panel")
    expect(panel).to_have_css("width", "620px")
    expect(page.get_by_role("button", name="Dừng trả lời")).to_be_visible()
    region = page.get_by_role("region", name="Nội dung hội thoại")
    expect(region.locator(".assistant-markdown")).to_be_visible()
    check_layout(page)

    page.set_viewport_size({"width": 1440, "height": 850})
    handle = page.get_by_role("separator", name="Chiều rộng khung chat")
    region.evaluate("node => { node.scrollTop = 0; }")
    expect(page.get_by_role("button", name="Xuống cuối hội thoại")).to_be_visible()
    coordinates = handle.bounding_box()
    assert coordinates
    center = coordinates["x"] + coordinates["width"] / 2
    page.mouse.move(center, 380)
    page.mouse.down()
    page.mouse.move(center - 230, 380, steps=20)
    page.evaluate("chatFixture.streams[0].add()")
    page.mouse.move(center - 140, 380, steps=15)
    page.mouse.up()
    expect(panel).to_have_css("width", "760px")
    assert not page.evaluate("getSelection().toString()")
    assert region.evaluate("node => node.scrollTop <= 2")
    page.get_by_role("button", name="Mở rộng toàn màn hình").click()
    expect(panel).to_have_css("width", "1440px")
    assert region.locator(":scope > div").evaluate("node => node.clientWidth <= 880")
    assert region.evaluate("node => node.scrollTop <= 2")
    for _ in range(10):
        page.keyboard.press("Tab")
        assert panel.evaluate("node => node.contains(document.activeElement)")
    page.get_by_role("button", name="Thu về khung bên phải").click()
    expect(panel).to_have_css("width", "760px")
    handle.dblclick()
    expect(panel).to_have_css("width", "620px")
    handle.press("ArrowLeft")
    expect(panel).to_have_css("width", "644px")
    page.get_by_role("button", name="Xuống cuối hội thoại").click()
    expect(page.get_by_role("button", name="Xuống cuối hội thoại")).to_have_count(0)
    assert page.evaluate("chatFixture.calls.length") == 1

    coordinates = handle.bounding_box()
    assert coordinates
    center = coordinates["x"] + coordinates["width"] / 2
    page.mouse.move(center, 380)
    page.mouse.down()
    expect(panel).to_have_attribute("data-resizing", "true")
    previous_top = region.evaluate("node => node.scrollTop")
    page.evaluate("chatFixture.streams[0].add()")
    expect(region.get_by_text("Đoạn nhận thêm trong lúc đang đọc.", exact=True)).to_have_count(2)
    wait_for_paint(page)
    assert abs(region.evaluate("node => node.scrollTop") - previous_top) <= 1
    page.mouse.up()
    wait_for_paint(page)
    assert region.evaluate("node => node.scrollHeight - node.clientHeight - node.scrollTop <= 1")
    assert not page.evaluate("document.documentElement.hasAttribute('data-assistant-resizing')")
    print("PASS: pointer capture, scrolling, focus, reset, and mode switches during an active stream")

    with page.expect_popup() as popup:
        page.get_by_role("button", name="Mở hội thoại trong tab mới").click()
    tab = popup.value
    tab.wait_for_url("**/chat/*")
    standalone = tab.locator("#assistant-chat-panel")
    expect(standalone).to_be_visible()
    assert tab.evaluate("window.opener === null && !location.hash && !location.search")
    assert tab.evaluate("Object.values(localStorage).every(value => /^\\d+(:\\d+)?$/.test(value))")
    expect(standalone.get_by_text("46/100", exact=True)).to_be_visible()
    expect(tab.get_by_text("Trợ lý đang trả lời ở một tab khác.")).to_be_visible()
    tab_input = tab.locator("#assistant-composer-input")
    tab_input.fill("Không được tạo lượt song song")
    tab_input.press("Enter")
    assert tab.evaluate("chatFixture.calls.length") == 0

    page.evaluate("chatFixture.streams[0].finish()")
    expect(standalone.get_by_role("button", name=SECOND_QUESTION, exact=True)).to_be_visible()
    expect(standalone.get_by_role("button", name=FIRST_QUESTION, exact=True)).to_have_count(0)
    expect(standalone.get_by_text(SOURCE, exact=False)).to_be_visible()
    tab.get_by_role("button", name=SECOND_QUESTION, exact=True).click()
    tab.wait_for_function("chatFixture.calls.length === 1")
    request = tab.evaluate("chatFixture.calls[0]")
    assert request["hasHeader"] and request["payload"]["history"][0]["content"] == FIRST_QUESTION
    assert request["payload"]["case_id"] in cases
    tab.evaluate("chatFixture.streams[0].finish()")
    expect(panel.get_by_text(SECOND_QUESTION, exact=True)).to_be_visible()
    expect(panel.get_by_role("button", name=SECOND_QUESTION, exact=True)).to_have_count(0)
    tab_url = tab.url
    tab.reload()
    expect(standalone.get_by_text(SECOND_QUESTION, exact=True)).to_be_visible()
    expect(standalone.get_by_role("button", name=SECOND_QUESTION, exact=True)).to_have_count(0)
    expect(standalone.locator(".assistant-markdown ol[start='3']").first).to_be_visible()
    assert tab.evaluate("chatFixture.calls.length") == 0
    assert len(auth_requests) == 2

    page.reload()
    expect(panel.get_by_text(FIRST_QUESTION, exact=True)).to_be_visible()
    expect(panel).to_have_css("width", "644px")
    assert page.evaluate("chatFixture.calls.length") == 0
    print("PASS: standalone and docked reload, both-way sync, single flight, history, citations, dedup")

    isolated = context.new_page()
    isolated.goto(tab_url)
    expect(isolated.get_by_text("Hội thoại không khả dụng", exact=False)).to_be_visible()
    isolated.close()
    page.get_by_role("button", name="Mở rộng toàn màn hình").click()
    page.get_by_role("button", name="Đóng khung chat").press("Escape")
    expect(page.locator("#assistant-launcher")).to_be_focused()
    page.get_by_role("button", name="Chỉnh sửa thông tin", exact=True).click()
    analyze()
    expect(panel.get_by_text("47/100", exact=True).first).to_be_visible()
    expect(panel.get_by_text(FIRST_QUESTION, exact=True)).to_have_count(0)
    expect(standalone.get_by_text("46/100", exact=True)).to_be_visible()
    tab_input.fill("Test tải lại khi đang trả lời")
    tab_input.press("Enter")
    expect(tab.get_by_role("button", name="Dừng trả lời")).to_be_visible()
    tab.reload()
    expect(tab.get_by_text("Lượt trả lời đã bị gián đoạn.", exact=False)).to_be_visible()
    assert tab.evaluate("chatFixture.calls.length") == 0
    tab.get_by_role("button", name="Xóa hội thoại").click()
    expect(standalone.get_by_text(FIRST_QUESTION, exact=True)).to_have_count(0)
    tab.reload()
    expect(standalone.get_by_text(FIRST_QUESTION, exact=True)).to_have_count(0)
    denied_cases.add(next(iter(cases)))
    tab.reload()
    expect(tab.get_by_text("Phiên này không còn quyền truy cập hồ sơ", exact=False)).to_be_visible()
    print("PASS: URL authorization, case isolation, interrupted reload, history deletion")
    context.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:3000")
    parser.add_argument("--channel", help="Installed browser channel, e.g. msedge or chrome")
    parser.add_argument("--profile-resize", action="store_true", help="Measure resize in Chromium via CDP")
    parser.add_argument("--expect-optimized", action="store_true", help="Assert resize performance budget")
    args = parser.parse_args()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=args.channel)
        verify(browser, args.base_url, args.profile_resize, args.expect_optimized)
