"""Regression tests for WP-3 deployment & reverse-proxy hardening (NV-07, NV-08, NV-11, NV-13)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parents[3]
CADDYFILE = REPO_ROOT / "deploy" / "Caddyfile"
DEV_COMPOSE = REPO_ROOT / "docker-compose.yml"
PROD_COMPOSE = REPO_ROOT / "docker-compose.prod.yml"
ENV_PROD_EXAMPLE = REPO_ROOT / "deploy" / ".env.prod.example"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
FRONTEND_DOCKERFILE = REPO_ROOT / "frontend" / "Dockerfile"
NEXT_CONFIG = REPO_ROOT / "frontend" / "next.config.ts"


def _load_compose_yaml(path: Path) -> dict[str, Any]:
    """Parse a Docker Compose YAML file supporting Compose Spec `!override` tags."""
    loader_cls: Any = type("_ComposeSafeLoader", (yaml.SafeLoader,), {})

    def _construct_override(loader: Any, node: Any) -> Any:
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    loader_cls.add_constructor("!override", _construct_override)
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=loader_cls)  # noqa: S506
    assert isinstance(loaded, dict)
    return loaded


def _env_list_to_map(env_entries: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in env_entries:
        assert "=" in item, f"Expected KEY=VAL entry in compose environment, got: {item!r}"
        key, value = item.split("=", 1)
        mapping[key] = value
    return mapping


def _extract_brace_block(text: str, header_pattern: str) -> str:
    match = re.search(header_pattern, text, flags=re.MULTILINE)
    assert match is not None, f"Could not find block matching {header_pattern!r}"
    brace_start = text.find("{", match.start())
    assert brace_start != -1
    depth = 0
    for idx in range(brace_start, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start + 1 : idx]
    raise AssertionError(f"Unbalanced braces for block matching {header_pattern!r}")


# ---------------------------------------------------------------------------
# NV-07: Caddyfile encoded path-separator guard & scoped request_body limits
# ---------------------------------------------------------------------------


def test_caddyfile_blocks_encoded_separators_on_raw_orig_uri_before_api() -> None:
    content = CADDYFILE.read_text(encoding="utf-8")

    # CRITICAL (Caddy 2.8): must inspect raw wire URI `{http.request.orig_uri}`,
    # never `{http.request.orig_uri.path}` which is already percent-decoded.
    assert "{http.request.orig_uri.path}" not in content
    assert "{http.request.orig_uri}" in content

    matcher_line_match = re.search(
        r"^\s*@encoded_path_sep\s+expression\s+`([^`]+)`",
        content,
        flags=re.MULTILINE,
    )
    assert matcher_line_match is not None, "Missing @encoded_path_sep expression matcher"
    expr = matcher_line_match.group(1)
    assert "{http.request.orig_uri}.split('?')[0].lowerAscii().contains('%2f')" in expr
    assert "{http.request.orig_uri}.split('?')[0].lowerAscii().contains('%5c')" in expr
    assert "{http.request.orig_uri}.split('?')[0].contains('\\\\')" in expr

    sep_handle_pos = content.find("handle @encoded_path_sep")
    api_handle_pos = content.find("handle /api/*")
    fallback_handle_match = re.search(r"^\s*handle\s*\{", content, flags=re.MULTILINE)
    assert sep_handle_pos != -1
    assert api_handle_pos != -1
    assert fallback_handle_match is not None
    assert sep_handle_pos < api_handle_pos < fallback_handle_match.start()

    sep_block = _extract_brace_block(content, r"^\s*handle\s+@encoded_path_sep\s*\{")
    assert 'respond "Bad Request" 400' in sep_block


def test_caddyfile_scopes_request_body_limits_per_route() -> None:
    content = CADDYFILE.read_text(encoding="utf-8")

    # Site-wide request_body must be removed so frontend cannot receive 22MB bodies.
    api_handle_pos = content.find("handle /api/*")
    assert api_handle_pos != -1
    before_handles = content[:api_handle_pos]
    assert "request_body" not in before_handles

    api_block = _extract_brace_block(content, r"^\s*handle\s+/api/\*\s*\{")
    api_body_pos = api_block.find("request_body")
    api_proxy_pos = api_block.find("reverse_proxy backend:8000")
    assert api_body_pos != -1 and api_proxy_pos != -1
    assert api_body_pos < api_proxy_pos
    assert "max_size 22MB" in api_block
    assert "flush_interval -1" in api_block
    assert "header_up X-Forwarded-For {remote_host}" in api_block

    frontend_block = _extract_brace_block(content, r"^\s*handle\s*\{")
    fe_body_pos = frontend_block.find("request_body")
    fe_proxy_pos = frontend_block.find("reverse_proxy frontend:3000")
    assert fe_body_pos != -1 and fe_proxy_pos != -1
    assert fe_body_pos < fe_proxy_pos
    assert "max_size 1MB" in frontend_block
    assert "22MB" not in frontend_block


# ---------------------------------------------------------------------------
# NV-07 & NV-08: Next.js config & frontend Dockerfile hardening
# ---------------------------------------------------------------------------


def test_next_config_disables_image_optimizer_and_gates_api_proxy() -> None:
    content = NEXT_CONFIG.read_text(encoding="utf-8")

    assert re.search(r"images\s*:\s*\{\s*unoptimized\s*:\s*true", content) is not None
    assert 'process.env.ENABLE_NEXT_API_PROXY !== "false"' in content
    assert re.search(r"if\s*\(\s*!enableApiProxy\s*\)\s*\{\s*return\s*\[\s*\]\s*;", content) is not None
    assert 'source: "/api/:path*"' in content


def test_frontend_dockerfile_defaults_proxy_disabled_and_prepares_ro_cache() -> None:
    content = FRONTEND_DOCKERFILE.read_text(encoding="utf-8")

    # Never hardcode backend internal URL in frontend image stages.
    assert "http://backend:8000" not in content

    builder_idx = content.find("AS builder")
    runner_idx = content.find("AS runner")
    assert builder_idx != -1 and runner_idx != -1 and builder_idx < runner_idx

    builder_stage = content[builder_idx:runner_idx]
    runner_stage = content[runner_idx:]

    build_cmd_pos = builder_stage.find("RUN npm run build")
    arg_proxy_pos = builder_stage.find("ARG ENABLE_NEXT_API_PROXY=false")
    arg_backend_pos = builder_stage.find("ARG BACKEND_INTERNAL_URL=")
    env_proxy_pos = builder_stage.find("ENABLE_NEXT_API_PROXY=${ENABLE_NEXT_API_PROXY}")
    env_backend_pos = builder_stage.find("BACKEND_INTERNAL_URL=${BACKEND_INTERNAL_URL}")
    assert min(build_cmd_pos, arg_proxy_pos, arg_backend_pos, env_proxy_pos, env_backend_pos) != -1
    assert arg_proxy_pos < env_proxy_pos < build_cmd_pos
    assert arg_backend_pos < env_backend_pos < build_cmd_pos

    assert "BACKEND_INTERNAL_URL" not in runner_stage
    cache_mkdir_pos = runner_stage.find("mkdir -p /app/.next/cache")
    cache_chown_pos = runner_stage.find("chown -R nextjs:nodejs /app/.next/cache")
    user_nextjs_pos = runner_stage.find("USER nextjs")
    assert min(cache_mkdir_pos, cache_chown_pos, user_nextjs_pos) != -1
    assert cache_mkdir_pos < cache_chown_pos < user_nextjs_pos


# ---------------------------------------------------------------------------
# NV-13: Backend Dockerfile Uvicorn forwarded-header hardening
# ---------------------------------------------------------------------------


def test_backend_dockerfile_defaults_no_proxy_headers_and_drops_broad_cidrs() -> None:
    content = BACKEND_DOCKERFILE.read_text(encoding="utf-8")

    for broad_cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert broad_cidr not in content, f"Overbroad trusted proxy CIDR {broad_cidr} still present"

    assert 'UVICORN_FORWARDED_ALLOW_IPS=""' in content
    assert "--no-proxy-headers" in content
    assert "--proxy-headers" in content
    assert "--forwarded-allow-ips=${UVICORN_FORWARDED_ALLOW_IPS}" in content
    assert 'if [ -n \\"${UVICORN_FORWARDED_ALLOW_IPS:-}\\" ]; then' in content


# ---------------------------------------------------------------------------
# NV-07, NV-08, NV-11, NV-13: Compose dev & prod manifests + .env.prod.example
# ---------------------------------------------------------------------------


def test_dev_compose_binds_loopback_ports_and_forwards_security_envs() -> None:
    compose = _load_compose_yaml(DEV_COMPOSE)
    services = compose["services"]

    backend = services["backend"]
    frontend = services["frontend"]

    assert backend["ports"] == ["127.0.0.1:8000:8000"]
    assert frontend["ports"] == ["127.0.0.1:3000:3000"]

    backend_env = _env_list_to_map(backend["environment"])
    assert backend_env["CASE_TOKEN_SECRET"] == "${CASE_TOKEN_SECRET:-}"
    assert backend_env["ONNX_INTRA_THREADS"] == "${ONNX_INTRA_THREADS:-2}"
    assert backend_env["UVICORN_FORWARDED_ALLOW_IPS"] == "${UVICORN_FORWARDED_ALLOW_IPS:-}"

    fe_args = frontend["build"]["args"]
    assert str(fe_args["ENABLE_NEXT_API_PROXY"]).lower() == "true"
    assert fe_args["BACKEND_INTERNAL_URL"] == "http://backend:8000"


def test_prod_compose_backend_hardening_and_required_secrets() -> None:
    raw = PROD_COMPOSE.read_text(encoding="utf-8")
    compose = _load_compose_yaml(PROD_COMPOSE)
    backend = compose["services"]["backend"]

    assert "env_file: !override []" in raw
    assert backend["env_file"] == []
    assert backend["ports"] == []
    assert backend["read_only"] is True
    assert backend["tmpfs"] == ["/tmp:rw,noexec,nosuid,mode=1777,size=256m"]  # noqa: S108
    assert "no-new-privileges:true" in backend["security_opt"]
    assert "ALL" in backend["cap_drop"]
    assert backend["networks"] == ["proxy_backend"]

    env = _env_list_to_map(backend["environment"])
    assert env["ANALYST_PIN"].startswith("${ANALYST_PIN:?")
    assert env["IOC_HMAC_SECRET"].startswith("${IOC_HMAC_SECRET:?")
    assert env["CASE_TOKEN_SECRET"].startswith("${CASE_TOKEN_SECRET:?")
    assert env["ONNX_INTRA_THREADS"] == "${ONNX_INTRA_THREADS:-2}"
    assert (
        env["UVICORN_FORWARDED_ALLOW_IPS"]
        == "${UVICORN_FORWARDED_ALLOW_IPS:-${PROXY_BACKEND_SUBNET:-172.28.0.0/24}}"
    )
    assert env["HOME"] == "/tmp"  # noqa: S108
    assert env["TMPDIR"] == "/tmp"  # noqa: S108
    assert env["XDG_CACHE_HOME"] == "/tmp"  # noqa: S108
    assert env["XDG_CONFIG_HOME"] == "/tmp"  # noqa: S108

    # Residual tradeoff comment for Chromium sandbox under cap_drop: [ALL]
    assert "PLAYWRIGHT_CHROMIUM_SANDBOX=false" in raw
    assert "cap_drop" in raw


def test_prod_compose_frontend_proxy_disabled_ro_and_isolated() -> None:
    compose = _load_compose_yaml(PROD_COMPOSE)
    frontend = compose["services"]["frontend"]

    assert frontend["ports"] == []
    assert frontend["read_only"] is True
    assert frontend["networks"] == ["proxy_frontend"]
    assert "no-new-privileges:true" in frontend["security_opt"]
    assert "ALL" in frontend["cap_drop"]

    assert frontend["tmpfs"] == [
        "/tmp:rw,noexec,nosuid,mode=1777,size=64m",  # noqa: S108
        "/app/.next/cache:rw,noexec,nosuid,nodev,size=32m,uid=1001,gid=1001",
    ]

    build_args = frontend["build"]["args"]
    assert str(build_args["ENABLE_NEXT_API_PROXY"]).lower() == "false"
    assert build_args["BACKEND_INTERNAL_URL"] == ""
    assert build_args["NEXT_PUBLIC_APP_ENV"] == "${APP_ENV:-production}"

    env = _env_list_to_map(frontend["environment"])
    assert env["ENABLE_NEXT_API_PROXY"] == "false"
    assert env["BACKEND_INTERNAL_URL"] == ""


def test_prod_compose_network_segmentation_and_ipam_subnet() -> None:
    compose = _load_compose_yaml(PROD_COMPOSE)
    services = compose["services"]

    backend_nets = set(services["backend"]["networks"])
    frontend_nets = set(services["frontend"]["networks"])
    caddy_nets = set(services["caddy"]["networks"])

    assert backend_nets == {"proxy_backend"}
    assert frontend_nets == {"proxy_frontend"}
    assert backend_nets.isdisjoint(frontend_nets)
    assert caddy_nets == {"proxy_backend", "proxy_frontend"}

    networks = compose["networks"]
    assert networks["proxy_frontend"]["internal"] is True
    ipam_configs = networks["proxy_backend"]["ipam"]["config"]
    assert ipam_configs == [{"subnet": "${PROXY_BACKEND_SUBNET:-172.28.0.0/24}"}]


def test_env_prod_example_documents_mandatory_secrets_and_proxy_subnet() -> None:
    raw = ENV_PROD_EXAMPLE.read_text(encoding="utf-8")
    values: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()

    for secret_key in (
        "GEMINI_API_KEY",
        "GEMINI_BACKUP_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_WEBHOOK_SECRET",
        "ANALYST_PIN",
        "IOC_HMAC_SECRET",
        "CASE_TOKEN_SECRET",
    ):
        assert secret_key in values, f"Missing {secret_key} in deploy/.env.prod.example"
        assert values[secret_key] == "", f"Secret template {secret_key} must be blank!"

    assert values["PROXY_BACKEND_SUBNET"] == "172.28.0.0/24"
    assert values["UVICORN_FORWARDED_ALLOW_IPS"] == "172.28.0.0/24"

    assert ">= 16 chars" in raw
    assert ">= 32 chars" in raw
    assert ">= 24 chars" in raw
    assert "unless IOC_HMAC_SECRET is set" not in raw
