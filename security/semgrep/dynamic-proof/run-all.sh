#!/usr/bin/env bash
# Compiles and runs every dynamic proof. Each proof is a standalone program
# that actually executes the vulnerable and guarded code paths and asserts on
# the observable difference -- exit code is non-zero if any assertion fails.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
rm -rf "$OUT"; mkdir -p "$OUT"

total_failed=0

for src in "$HERE"/*Proof.java; do
  name="$(basename "$src" .java)"
  printf '\n\033[1m########## %s ##########\033[0m\n' "$name"

  if ! javac -nowarn -proc:none -d "$OUT" "$src" 2> "$OUT/$name.compile.err"; then
    echo "COMPILE FAILED:"
    cat "$OUT/$name.compile.err"
    total_failed=$((total_failed + 1))
    continue
  fi

  if java -cp "$OUT" "$name"; then
    : # printed its own pass summary
  else
    echo "  (exited non-zero -- see FAIL lines above)"
    total_failed=$((total_failed + 1))
  fi
done

echo
if [ "$total_failed" -gt 0 ]; then
  echo "=========================================="
  echo " $total_failed proof(s) FAILED"
  echo "=========================================="
  exit 1
fi

echo "=========================================="
echo " All dynamic proofs passed."
echo "=========================================="
