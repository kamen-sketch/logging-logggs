#!/usr/bin/env bash
# Compile and run the smoke test against the javac-built Log4j.
# Usage: ./build.sh && ./run.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
DEMO="$HERE/demo"
CP="$OUT/api:$OUT/core"

if [ ! -d "$OUT/core" ]; then
  echo "No build output found -- run ./build.sh first." >&2
  exit 1
fi

rm -rf "$DEMO/classes" "$DEMO/logs"
mkdir -p "$DEMO/classes"

javac -proc:none -nowarn -cp "$CP" -d "$DEMO/classes" "$DEMO/SmokeTest.java"

# log4j2.xml is picked up from the working directory, so run from demo/.
cd "$DEMO"
exec java -cp "classes:.:$CP" SmokeTest
