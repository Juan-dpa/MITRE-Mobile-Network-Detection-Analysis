#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
TEST_DIR=$(mktemp -d)
trap '[[ $TEST_DIR == /tmp/* ]] && rm -rf -- "$TEST_DIR"' EXIT

LAB_DIR=$ROOT/labs/gplayed
LABNET_KEY_DIR=$TEST_DIR
# shellcheck source=../tools/runlib.sh
source "$ROOT/tools/runlib.sh"

printf 'dynamic-secret\n' >"$TEST_DIR/dynamic.log"
LAB_KEY_FILES=(
    "static.pem|$ROOT/labs/notcompatible/source/keys/global_public.pem|material estático de prueba"
)
LAB_KEY_DYNAMIC_FILES=(
    "dynamic.log|material dinámico de prueba"
)
LAB_KEY_VALUES=(
    "literal.hex|001122|valor de prueba"
)
LAB_KEY_NOTE="inventario de prueba"

export_key_material

test -s "$TEST_DIR/static.pem"
test -s "$TEST_DIR/dynamic.log"
test -s "$TEST_DIR/literal.hex"
grep -Fq 'static.pem' "$TEST_DIR/key-material.txt"
grep -Fq 'dynamic.log' "$TEST_DIR/key-material.txt"
grep -Fq 'literal.hex' "$TEST_DIR/key-material.txt"

if (
    LAB_PYTHON_MODULES=(labnet_module_that_must_not_exist)
    runner_check_python_modules
) 2>"$TEST_DIR/missing-module.log"; then
    printf 'El preflight aceptó un módulo Python inexistente.\n' >&2
    exit 1
fi
grep -Fq 'labnet_module_that_must_not_exist' "$TEST_DIR/missing-module.log"
