#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "==> [VeriShield Verify] Repo root: ${REPO_ROOT}"

cd "${REPO_ROOT}/backend"
if [ -x ".venv/bin/pytest" ]; then
  RUFF=".venv/bin/ruff"
  MYPY=".venv/bin/mypy"
  PYTEST=".venv/bin/pytest"
else
  RUFF="ruff"
  MYPY="mypy"
  PYTEST="pytest"
fi

echo "==> [1/3] Running Ruff linter..."
"${RUFF}" check app tests ../scripts ../evaluation ../submission ../training

echo "==> [2/3] Running Mypy strict typecheck..."
"${MYPY}" --config-file pyproject.toml app

echo "==> [3/3] Running Pytest suite..."
"${PYTEST}" -c pyproject.toml

if [ -f "${REPO_ROOT}/frontend/package.json" ]; then
  cd "${REPO_ROOT}/frontend"
  echo "==> [Frontend] Running TypeScript strict check, tests & build..."
  npx tsc --noEmit
  npm test
  npm run build
fi

echo "==> [VeriShield Verify] ALL CHECKS PASSED!"
