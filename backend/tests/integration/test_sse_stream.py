import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_sse_stream_emits_live_trace_steps_and_final_result(tmp_path: Path) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "sse_test.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_stt=False,
    )
    client = TestClient(create_app(cfg))

    with client.stream(
        "POST",
        "/api/v1/analyze/stream",
        data={
            "mode": "personal",
            "text": "Tin nhắn NAPAS: Đổi điểm thưởng thẻ tại https://napas-diemthuong.top/verify",
        },
    ) as resp:
        assert resp.status_code == 200
        assert resp.headers.get("x-accel-buffering") == "no"
        raw_stream = "".join(resp.iter_text())

    events: list[tuple[str, dict]] = []
    for block in raw_stream.split("\n\n"):
        lines = [ln for ln in block.splitlines() if ln.strip()]
        ev_type = ""
        ev_data = ""
        for ln in lines:
            if ln.startswith("event:"):
                ev_type = ln.split(":", 1)[1].strip()
            elif ln.startswith("data:"):
                ev_data = ln.split(":", 1)[1].strip()
        if ev_type and ev_data:
            events.append((ev_type, json.loads(ev_data)))

    trace_events = [d for t, d in events if t == "trace"]
    result_events = [d for t, d in events if t == "result"]

    assert len(trace_events) >= 3
    assert len(result_events) == 1
    assert result_events[0]["degraded_mode"] is True
    assert result_events[0]["risk_score"] >= 80


async def test_sse_stream_flushes_first_trace_before_pipeline_completion(tmp_path: Path) -> None:
    import asyncio
    from collections.abc import AsyncIterator
    from typing import Any

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "sse_inc.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_stt=False,
    )
    app = create_app(cfg)
    from app.db.repository import CaseRepository
    from app.services.pipeline import AnalysisPipeline

    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    app.state.repo = repo
    app.state.pipeline = AnalysisPipeline(settings=cfg, repo=repo)

    release_gate = asyncio.Event()

    async def _gated_stream(**_kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {
            "event": "trace",
            "data": {
                "step_id": "step_1",
                "title": "Bước 1",
                "status": "done",
                "detail": "Đã xong bước 1",
                "duration_ms": 2,
            },
        }
        await release_gate.wait()
        yield {
            "event": "result",
            "data": {"case_id": "vs_gated_01", "risk_score": 5, "verdict": "SAFE"},
        }

    app.state.pipeline.stream = _gated_stream  # type: ignore[method-assign]

    # Exercise the real ASGI boundary directly (httpx.ASGITransport buffers until app() exits)
    form_body = b"mode=personal&text=Kiem+tra+SSE+tung+chang"
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/analyze/stream",
        "raw_path": b"/api/v1/analyze/stream",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(form_body)).encode("ascii")),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    body_sent = False

    async def _receive() -> dict[str, Any]:
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": form_body, "more_body": False}
        await asyncio.sleep(10.0)
        return {"type": "http.disconnect"}

    outbound: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    async def _send(message: dict[str, Any]) -> None:
        await outbound.put(message)

    asgi_task = asyncio.create_task(app(scope, _receive, _send))
    try:
        async with asyncio.timeout(1.5):
            start_msg = await outbound.get()
            assert start_msg["type"] == "http.response.start"
            assert start_msg["status"] == 200

            accumulated = ""
            while '"step_1"' not in accumulated:
                chunk_msg = await outbound.get()
                assert chunk_msg["type"] == "http.response.body"
                accumulated += bytes(chunk_msg.get("body", b"")).decode("utf-8")

        # First trace chunk flushed over ASGI BEFORE release_gate was set!
        assert not release_gate.is_set()
        release_gate.set()

        trailing = ""
        async with asyncio.timeout(1.5):
            while True:
                msg = await outbound.get()
                trailing += bytes(msg.get("body", b"")).decode("utf-8")
                if not msg.get("more_body", False):
                    break
        assert "event: result" in trailing
        await asyncio.wait_for(asgi_task, timeout=1.5)
    finally:
        release_gate.set()
        if not asgi_task.done():
            asgi_task.cancel()
