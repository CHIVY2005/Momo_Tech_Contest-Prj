"""Build verified clean source archive submission/dist/verishield-ai-source.zip (zero secrets/bloat)."""

from __future__ import annotations

import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_ZIP = REPO_ROOT / "submission" / "dist" / "verishield-ai-source.zip"

EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".superpowers",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".next",
        "out",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)

EXCLUDED_REL_PREFIXES: tuple[str, ...] = (
    "submission/dist/",
    "training/data/",
    "docs/the-le-cuoc-thi.pdf",
)

ALLOWED_DOTENV_TEMPLATES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.prod.example",
    }
)


def _should_exclude(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    if any(part in EXCLUDED_DIR_NAMES for part in parts[:-1]):
        return True
    if any(rel_posix == pfx.rstrip("/") or rel_posix.startswith(pfx) for pfx in EXCLUDED_REL_PREFIXES):
        return True

    filename = parts[-1]
    lower_name = filename.lower()

    if lower_name.startswith(".env") and lower_name not in ALLOWED_DOTENV_TEMPLATES:
        return True
    if lower_name.endswith(
        (".pyc", ".pyo", ".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".zip")
    ):
        return True
    return lower_name in ("thumbs.db", ".ds_store")


def build_clean_source_zip(out_path: Path = OUT_ZIP) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    added_count = 0
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for file_path in sorted(REPO_ROOT.rglob("*")):
            if not file_path.is_file():
                continue
            rel_posix = file_path.relative_to(REPO_ROOT).as_posix()
            if _should_exclude(rel_posix):
                continue
            zf.write(file_path, arcname=rel_posix)
            added_count += 1

    # Post-packaging security audit on archive table of contents
    with zipfile.ZipFile(out_path, "r") as check_zf:
        for member in check_zf.namelist():
            base = member.rsplit("/", maxsplit=1)[-1].lower()
            if base.startswith(".env") and base not in ALLOWED_DOTENV_TEMPLATES:
                out_path.unlink(missing_ok=True)
                raise RuntimeError(f"SECURITY ABORT: Secret dotenv file {member} detected in archive!")

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"==> Packaged {added_count} clean files into {out_path} ({size_mb:.2f} MB)")
    return out_path


if __name__ == "__main__":
    build_clean_source_zip()
