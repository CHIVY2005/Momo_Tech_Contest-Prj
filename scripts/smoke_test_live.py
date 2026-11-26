"""End-to-end live HTTPS / local deployment smoke test for VeriShield AI v2.0."""

from __future__ import annotations

import argparse
import sys

import httpx


def run_smoke_test(base_url: str, analyst_pin: str = "2026") -> int:
    root = base_url.rstrip("/")
    print(f"==> [VeriShield Smoke Test] Target: {root}")

    with httpx.Client(timeout=35.0, follow_redirects=True) as client:
        # 1. Health & Security Headers
        h = client.get(f"{root}/api/v1/health")
        assert h.status_code == 200, f"Health returned {h.status_code}"
        assert h.headers.get("x-content-type-options") == "nosniff"
        assert h.headers.get("x-frame-options") == "DENY"
        print(f"  [1/5] Health & security headers OK: {h.json()}")

        # 2. Demos list
        demos = client.get(f"{root}/api/v1/demos")
        assert demos.status_code == 200 and len(demos.json()) == 5
        print("  [2/5] 5 Canonical 1-Click Demos OK")

        # 3. Live SSE stream
        with client.stream(
            "POST",
            f"{root}/api/v1/analyze/stream",
            data={"demo_id": demos.json()[0]["demo_id"]},
        ) as sse:
            assert sse.status_code == 200
            stream_body = "".join(sse.iter_text())
            assert "event: trace" in stream_body and "event: result" in stream_body
        print("  [3/5] Unbuffered SSE streaming (/api/v1/analyze/stream) OK")

        # 4. Upload 413 ceiling & SSRF protection
        big_payload = b"\x89PNG\r\n\x1a\n" + (b"0" * (10 * 1024 * 1024 + 4096))
        r_413 = client.post(
            f"{root}/api/v1/analyze",
            data={"mode": "merchant"},
            files={"image": ("oversize.png", big_payload, "image/png")},
        )
        assert r_413.status_code == 413, f"Expected 413 on >10MB upload, got {r_413.status_code}"

        r_ssrf = client.post(
            f"{root}/api/v1/analyze",
            data={
                "mode": "personal",
                "text": "Kiểm tra link",
                "url": "http://169.254.169.254/latest/meta-data/",
            },
        )
        assert r_ssrf.status_code == 200
        assert r_ssrf.json()["url_findings"][0]["is_blocked_ssrf"] is True
        print("  [4/5] 10MB Upload Guard (HTTP 413) & Cloud Metadata SSRF Block OK")

        # 5. Closed-loop /radar block & clean reset
        radar = client.get(f"{root}/api/v1/radar/graph")
        assert radar.status_code == 200
        blk = client.post(
            f"{root}/api/v1/radar/block-rules",
            json={
                "ioc_type": "bank_account",
                "value": "999888777666",
                "reason": "Smoke test transient block",
                "analyst_pin": analyst_pin,
            },
        )
        assert blk.status_code == 200
        rst = client.post(
            f"{root}/api/v1/radar/block-rules/reset",
            json={"analyst_pin": analyst_pin},
        )
        assert rst.status_code == 200
        print("  [5/5] Closed-Loop /radar Block Rule + Clean Reset OK")

    print("==> [VeriShield Smoke Test] ALL 5 LIVE CHECKS PASSED!")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test live VeriShield AI deployment.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--pin", default="2026")
    args = parser.parse_args()
    return run_smoke_test(args.base_url, args.pin)


if __name__ == "__main__":
    sys.exit(main())
