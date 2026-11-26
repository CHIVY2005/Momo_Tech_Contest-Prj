"""Build verified clean source archive submission/dist/verishield-ai-source.zip (zero secrets/bloat)."""

from __future__ import annotations

import shutil
import subprocess
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

SECRET_EXTENSIONS: tuple[str, ...] = (
    ".pyc",
    ".pyo",
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".sqlite3",
    ".zip",
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".kdbx",
)


def _is_forbidden_secret_filename(lower_name: str) -> bool:
    if lower_name.startswith(".env") and lower_name not in ALLOWED_DOTENV_TEMPLATES:
        return True
    if lower_name.startswith(("id_rsa", "id_ed25519")):
        return True
    if ("secret" in lower_name or "credential" in lower_name) and lower_name.endswith(".json"):
        return True
    return lower_name.endswith(SECRET_EXTENSIONS)


def _should_exclude(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    if any(part in EXCLUDED_DIR_NAMES for part in parts[:-1]):
        return True
    if any(rel_posix == pfx.rstrip("/") or rel_posix.startswith(pfx) for pfx in EXCLUDED_REL_PREFIXES):
        return True

    lower_name = parts[-1].lower()
    if _is_forbidden_secret_filename(lower_name):
        return True
    return lower_name in ("thumbs.db", ".ds_store")


def _list_candidate_files(repo_root: Path) -> list[Path]:
    git_bin = shutil.which("git")
    if git_bin and (repo_root / ".git").exists():
        proc = subprocess.run(  # noqa: S603
            [git_bin, "ls-files"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return [repo_root / rel for rel in proc.stdout.splitlines() if rel.strip()]

    return sorted(p for p in repo_root.rglob("*") if p.is_file() and not p.is_symlink())


def build_clean_source_zip(out_path: Path = OUT_ZIP) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    added_count = 0
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for file_path in _list_candidate_files(REPO_ROOT):
            if file_path.is_symlink() or not file_path.is_file():
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
            if _is_forbidden_secret_filename(base):
                out_path.unlink(missing_ok=True)
                raise RuntimeError(f"SECURITY ABORT: Secret or forbidden file {member} in archive!")

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"==> Packaged {added_count} clean tracked files into {out_path} ({size_mb:.2f} MB)")
    return out_path


if __name__ == "__main__":
    build_clean_source_zip()
