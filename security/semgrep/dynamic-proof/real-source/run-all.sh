#!/usr/bin/env bash
# Compiles and runs every real-source proof against the actual compiled
# Log4j classes in nomaven-build/out -- not a hand-rolled stand-in for
# javax.naming.Context, java.sql.Connection, or javax.script.ScriptEngine.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
LOG4J_CP="$REPO_ROOT/nomaven-build/out/api:$REPO_ROOT/nomaven-build/out/core"
OUT="$HERE/out"

if [ ! -d "$REPO_ROOT/nomaven-build/out/core" ]; then
  echo "nomaven-build/out/core not found -- run $REPO_ROOT/nomaven-build/build.sh first." >&2
  exit 1
fi

rm -rf "$OUT"; mkdir -p "$OUT"
total_failed=0

run_proof() {
  local main_class="$1"; shift
  local sources=("$@")

  printf '\n\033[1m########## %s ##########\033[0m\n' "$main_class"
  if ! javac -nowarn -proc:none -cp "$LOG4J_CP" -d "$OUT" "${sources[@]}" 2> "$OUT/$main_class.compile.err"; then
    echo "COMPILE FAILED:"
    cat "$OUT/$main_class.compile.err"
    total_failed=$((total_failed + 1))
    return
  fi

  if java -cp "$OUT:$LOG4J_CP" "$main_class"; then
    :
  else
    echo "  (exited non-zero -- see FAIL lines above)"
    total_failed=$((total_failed + 1))
  fi
}

run_proof JndiRealSourceProof "$HERE/JndiRealSourceProof.java"
run_proof org.apache.logging.log4j.core.config.xml.XxeRealSourceProof \
  "$HERE/org/apache/logging/log4j/core/config/xml/XxeRealSourceProof.java"
run_proof org.apache.logging.log4j.core.config.xml.XIncludeRealSourceProof \
  "$HERE/org/apache/logging/log4j/core/config/xml/XIncludeRealSourceProof.java"
run_proof XIncludeExfilProof "$HERE/XIncludeExfilProof.java"
run_proof XIncludeRemoteConfigProof "$HERE/XIncludeRemoteConfigProof.java"
run_proof XIncludeClasspathShadowProof "$HERE/XIncludeClasspathShadowProof.java"
run_proof XIncludeWatcherTakeoverProof "$HERE/XIncludeWatcherTakeoverProof.java"
run_proof XIncludeJmxProof "$HERE/XIncludeJmxProof.java"
run_proof SqlRealSourceProof "$HERE/SqlRealSourceProof.java"

"$HERE/gen-ssl-certs.sh"
run_proof SslHostnameVerificationProof "$HERE/SslHostnameVerificationProof.java"

printf '\n\033[1m########## ScriptRealSourceProof ##########\033[0m\n'
if ! javac -nowarn -proc:none -cp "$LOG4J_CP" -d "$OUT" \
    "$HERE/TinyScriptEngine.java" "$HERE/ScriptRealSourceProof.java" 2> "$OUT/script.compile.err"; then
  echo "COMPILE FAILED:"; cat "$OUT/script.compile.err"
  total_failed=$((total_failed + 1))
else
  cp -r "$HERE/META-INF" "$OUT/"
  if java -cp "$OUT:$LOG4J_CP" ScriptRealSourceProof; then
    :
  else
    echo "  (exited non-zero -- see FAIL lines above)"
    total_failed=$((total_failed + 1))
  fi
fi

printf '\n\033[1m########## XIncludeSpringCloudWatchProof ##########\033[0m\n'
SCW="$HERE/springcloud-watch"
if ! javac -nowarn -proc:none -cp "$LOG4J_CP" -d "$OUT" \
    "$SCW/TestWatchEventService.java" "$SCW/XIncludeSpringCloudWatchProof.java" 2> "$OUT/springcloud.compile.err"; then
  echo "COMPILE FAILED:"; cat "$OUT/springcloud.compile.err"
  total_failed=$((total_failed + 1))
else
  cp -r "$SCW/META-INF" "$OUT/"
  if java -cp "$OUT:$LOG4J_CP" XIncludeSpringCloudWatchProof; then
    :
  else
    echo "  (exited non-zero -- see FAIL lines above)"
    total_failed=$((total_failed + 1))
  fi
fi

printf '\n\033[1m########## log4j-unsafe-deserialization ##########\033[0m\n'
echo "  No real-source proof -- the vulnerable component (TcpSocketServer/"
echo "  UdpSocketServer) was removed from this branch entirely, not merely"
echo "  patched. See DESERIALIZATION_FINDING.md for the investigation."

echo
if [ "$total_failed" -gt 0 ]; then
  echo "=========================================="
  echo " $total_failed proof(s) FAILED"
  echo "=========================================="
  exit 1
fi
echo "=========================================="
echo " All real-source proofs passed."
echo "=========================================="
