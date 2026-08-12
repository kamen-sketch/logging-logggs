#!/usr/bin/env bash
# Verify the Semgrep ruleset.
#
# Runs `semgrep --test` when Semgrep is installed; otherwise falls back to the
# local checks in validate.py and says clearly what was NOT verified.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo "=== local checks (rule schema, annotations, javac) ==="
python3 validate.py || exit 1

echo
if command -v semgrep >/dev/null 2>&1; then
  echo "=== semgrep --test ==="
  semgrep --test --config . .
  exit $?
fi

cat <<'EOF'

=== semgrep --test: SKIPPED ===
Semgrep is not installed and could not be installed in this environment:
PyPI and npm both answer "Host not in allowlist" through the egress proxy.

The pattern-matching behaviour of these rules is therefore UNVERIFIED.
Where Semgrep is available, verify with:

    pip install semgrep
    ./run-tests.sh          # picks up semgrep automatically

`semgrep --test` reads the `// ruleid:` and `// ok:` annotations in the
fixtures and fails on any missed or spurious match.
EOF
exit 0
