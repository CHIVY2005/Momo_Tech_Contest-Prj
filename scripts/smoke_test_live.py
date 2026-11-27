"""End-to-end live HTTPS / local deployment smoke test for VeriShield AI v2.0."""

from __future__ import annotations

import argparse
import json
import sys
import time

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
        print(f"  [1/6] Health & security headers OK: {h.json()}")

        # 2. Demos list
        demos = client.get(f"{root}/api/v1/demos")
        assert demos.status_code == 200 and len(demos.json()) == 5
        print("  [2/6] 5 Canonical 1-Click Demos OK")

        # 3. Incremental SSE stream ordering & case session token issuance
        first_trace_ts: float | None = None
        result_ts: float | None = None
        session_ts: float | None = None
        current_event = ""
        session_case_id = ""
        session_token = ""
        with client.stream(
            "POST",
            f"{root}/api/v1/analyze/stream",
            data={"demo_id": demos.json()[0]["demo_id"]},
        ) as sse:
            assert sse.status_code == 200
            for line in sse.iter_lines():
                if line.startswith("event:"):
                    current_event = line.split(":", 1)[1].strip()
                    if current_event == "trace" and first_trace_ts is None:
                        first_trace_ts = time.perf_counter()
                    elif current_event == "result" and result_ts is None:
                        result_ts = time.perf_counter()
                    elif current_event == "session" and session_ts is None:
                        session_ts = time.perf_counter()
                elif line.startswith("data:") and current_event == "session":
                    sess_data = json.loads(line.split(":", 1)[1].strip())
                    session_case_id = str(sess_data.get("case_id") or "")
                    session_token = str(sess_data.get("case_access_token") or "")
        assert first_trace_ts is not None and result_ts is not None and session_ts is not None
        assert first_trace_ts <= result_ts <= session_ts
        assert session_case_id.startswith("vs_") and session_token
        print("  [3/6] Incremental SSE streaming + session token (/api/v1/analyze/stream) OK")

        # 4. Unified X-Case-Access-Token enforcement on /cases/{id} and /report.pdf
        unauth_case = client.get(f"{root}/api/v1/cases/{session_case_id}")
        assert unauth_case.status_code == 403, (
            f"Expected 403 without token on /cases, got {unauth_case.status_code}"
        )
        unauth_pdf = client.get(f"{root}/api/v1/cases/{session_case_id}/report.pdf")
        assert unauth_pdf.status_code == 403, (
            f"Expected 403 without token on /report.pdf, got {unauth_pdf.status_code}"
        )

        auth_headers = {"X-Case-Access-Token": session_token}
        auth_case = client.get(f"{root}/api/v1/cases/{session_case_id}", headers=auth_headers)
        assert auth_case.status_code == 200, f"Expected 200 with token, got {auth_case.status_code}"
        assert "no-store" in auth_case.headers.get("cache-control", "").lower()
        assert "x-case-access-token" in auth_case.headers.get("vary", "").lower()

        auth_pdf = client.get(
            f"{root}/api/v1/cases/{session_case_id}/report.pdf", headers=auth_headers
        )
        assert auth_pdf.status_code == 200, (
            f"Expected 200 on PDF with token, got {auth_pdf.status_code}"
        )
        assert auth_pdf.content[:5] == b"%PDF-"
        print("  [4/6] Unified X-Case-Access-Token enforcement on /cases/* & /report.pdf OK")

        # 5. Upload 413 ceiling & SSRF protection
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
        print("  [5/6] 10MB Upload Guard (HTTP 413) & Cloud Metadata SSRF Block OK")

        # 6. Closed-loop /radar non-destructive single-rule create & revoke
        radar = client.get(f"{root}/api/v1/radar/graph")
        assert radar.status_code == 200
        smoke_acct = "999000111222"
        blk = client.post(
            f"{root}/api/v1/radar/block-rules",
            json={
                "ioc_type": "bank_account",
                "value": smoke_acct,
                "reason": "Smoke test isolated rule",
                "analyst_pin": analyst_pin,
                "ttl_minutes": 2,
            },
        )
        assert blk.status_code == 200
        rule_id = blk.json()["rule_id"]
        rev = client.post(
            f"{root}/api/v1/radar/block-rules/{rule_id}/revoke",
            json={"analyst_pin": analyst_pin},
        )
        assert rev.status_code == 200 and rev.json()["revoked"] is True
        print("  [6/6] Closed-Loop /radar Isolated Rule Create + Revoke OK")

    print("==> [VeriShield Smoke Test] ALL 6 LIVE CHECKS PASSED!")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test live VeriShield AI deployment.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--pin", default="2026")
    args = parser.parse_args()
    return run_smoke_test(args.base_url, args.pin)


if __name__ == "__main__":
    sys.exit(main())
