import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_sse_stream_emits_live_trace_steps_and_final_result(tmp_path: Path) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "sse_test.db"),
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
