#!/usr/bin/env bash
# Scripted demo. Usage: ./scripts/demo.sh [secrets|sast|dockerfile|deps|image|gate|all]
# Each scenario scans BOTH apps with one scanner and checks the result. Keep http://<EC2-PUBLIC-IP>:8080/ open
# in a browser and refresh it between scenarios: the dashboard updates after every scan.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
dashboard_up || die "The dashboard is not running. Run ./scripts/up.sh first."

FAILURES=0
assert() { # LABEL COMMAND...
  local label="$1"; shift
  if "$@"; then ok "$label"; else fail "$label"; FAILURES=$((FAILURES + 1)); fi
}
finish() {
  if [ "$FAILURES" -eq 0 ]; then printf '\n\033[1;32mPASS\033[0m  %s\n\n' "$1"; else printf '\n\033[1;31mFAIL\033[0m  %s\n\n' "$1"; exit 1; fi
}
say()  { printf '    %s\n' "$*"; }
show() { python3 "$ROOT/scripts/devsec.py" show "$ROOT/reports/$1" "$2" "${3:-6}"; }       # show TARGET CHECK [N]
scan() { "$ROOT/scripts/scan.sh" "$1" "${@:2}" >/dev/null || { fail "scan of $1 failed. Run: ./scripts/scan.sh $1 ${*:2}"; exit 1; }; }
at_least() { [ "$(count "$1" "$2")" -ge "$3" ]; }
none()     { [ "$(count "$1" "$2")" = 0 ]; }
both() { scan vulnerable "$@"; scan fixed "$@"; }

scenario_secrets() {
  log "SCENARIO secrets: a forgotten .env.production file with cloud keys (gitleaks)"
  both secrets
  say "what gitleaks found in the vulnerable app:"; show vulnerable secrets
  assert "vulnerable: at least 1 leaked secret found"      at_least vulnerable secrets 1
  assert "fixed: no secrets"                               none fixed secrets
  finish secrets
}

scenario_sast() {
  log "SCENARIO sast: insecure code patterns (semgrep, rules in scan/semgrep-rules.yml)"
  both sast
  say "what semgrep found in the vulnerable app:"; show vulnerable sast 8
  assert "vulnerable: 6 or more ERROR findings"            at_least vulnerable sast 6
  assert "vulnerable: SQL injection is among them"         grep -q sql-injection "$ROOT/reports/vulnerable/semgrep.json"
  assert "fixed: no findings"                              none fixed sast
  finish sast
}

scenario_dockerfile() {
  log "SCENARIO dockerfile: build-file best practices (hadolint)"
  both dockerfile
  say "what hadolint found in the vulnerable Dockerfile:"; show vulnerable dockerfile 8
  assert "vulnerable: 3 or more warnings or errors"        at_least vulnerable dockerfile 3
  assert "fixed: clean"                                    none fixed dockerfile
  finish dockerfile
}

scenario_deps() {
  log "SCENARIO deps: known CVEs in pinned libraries (trivy)"
  both deps
  say "the worst findings in the vulnerable requirements.txt:"; show vulnerable deps 8
  assert "vulnerable: 3 or more fixable HIGH/CRITICAL CVEs" at_least vulnerable deps 3
  assert "fixed: none (newer versions)"                    none fixed deps
  finish deps
}

scenario_image() {
  log "SCENARIO image: scan the built container image, including secrets baked into it (trivy)"
  both image
  say "the worst findings in the vulnerable image:"; show vulnerable image 8
  assert "vulnerable: the image has blocking findings"     at_least vulnerable image 1
  assert "fixed: no fixable CRITICAL CVEs, no secrets"     none fixed image
  finish image
}

scenario_gate() {
  log "SCENARIO gate: the pipeline decides. Vulnerable is blocked, fixed is deployed"
  "$ROOT/scripts/pipeline.sh" vulnerable; local rc_bad=$?
  assert "the vulnerable build is BLOCKED (exit 1)"        test "$rc_bad" -eq 1
  "$ROOT/scripts/pipeline.sh" fixed; local rc_good=$?
  assert "the fixed build PASSES and is deployed (exit 0)" test "$rc_good" -eq 0
  local body
  assert "the deployed app is healthy"                     test "$(http_code "$APP_URL/healthz")" = 200
  body="$(curl -s -m 4 --get --data-urlencode "q=alice" "$APP_URL/search")"
  say "GET /search?q=alice            -> $body"
  assert "a normal search finds alice"                     test "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["count"])' "$body")" = 1
  body="$(curl -s -m 4 --get --data-urlencode "q=' OR '1'='1" "$APP_URL/search")"
  say "GET /search?q=' OR '1'='1      -> $body"
  assert "the SQL injection attempt finds nothing"         test "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["count"])' "$body")" = 0
  say "GET /calc?expr=__import__('os').system('id') -> HTTP $(http_code "$APP_URL/calc?expr=__import__('os').system('id')")"
  assert "code injection through /calc is refused (400)"   test "$(http_code "$APP_URL/calc?expr=__import__('os').system('id')")" = 400
  finish gate
}

case "${1:-all}" in
  secrets)     scenario_secrets ;;
  sast)        scenario_sast ;;
  dockerfile)  scenario_dockerfile ;;
  deps)        scenario_deps ;;
  image)       scenario_image ;;
  gate)        scenario_gate ;;
  all)         scenario_secrets; scenario_sast; scenario_dockerfile; scenario_deps; scenario_image; scenario_gate
               echo "All scenarios passed." ;;
  *)           die "usage: $0 [secrets|sast|dockerfile|deps|image|gate|all]" ;;
esac
