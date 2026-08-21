#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
export PYTHONDONTWRITEBYTECODE=1
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN=python
else
    printf 'No se encuentra Python 3.\n' >&2
    exit 1
fi

bash -n "$ROOT/tools/labnet.sh" "$ROOT/tools/runlib.sh" "$ROOT/tools/validate.sh" \
    "$ROOT/tools/smoke-all.sh"
for script in "$ROOT"/labs/*/run.sh; do
    bash -n "$script"
done
bash -n "$ROOT/tests/test_runlib.sh"
for manifest in "$ROOT"/labs/*/topology.conf; do
    bash "$ROOT/tools/labnet.sh" "$manifest" check
done

if grep -RInE '127\.|localhost|0\.0\.0\.0' --include='topology.conf' --include='run.sh' "$ROOT/labs"; then
    printf 'Se encontraron destinos de loopback o escuchas globales en lanzadores/manifiestos.\n' >&2
    exit 1
fi

"$PYTHON_BIN" - "$ROOT" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
for path in sorted(root.rglob("*.py")):
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY
"$PYTHON_BIN" -m unittest discover -s "$ROOT/tests" -p 'test_*.py'
bash "$ROOT/tests/test_runlib.sh"
printf 'Validación estática completada.\n'
