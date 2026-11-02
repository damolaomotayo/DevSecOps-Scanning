#!/usr/bin/env bash
# Health check of the running demo (run ./scripts/up.sh first). Ends with "All 14 checks passed."
set -uo pipefail
. "$(dirname "$0")/lib.sh"

TOTAL=0; BAD=0
check() { # LABEL COMMAND...
  local label="$1"; shift
  TOTAL=$((TOTAL + 1))
  if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; BAD=$((BAD + 1)); fi
}
code_is()  { [ "$(http_code "$1")" = "$2" ]; }
at_least() { [ "$(count "$1" "$2")" -ge "$3" ]; }          # at_least TARGET CHECK N
gate_rc()  { python3 "$ROOT/scripts/devsec.py" gate "$ROOT/reports/$1" >/dev/null 2>&1; echo $?; }
reports_valid() { [ "$(gate_rc vulnerable)" != 2 ] && [ "$(gate_rc fixed)" != 2 ]; }
vulnerable_blocked() { [ "$(gate_rc vulnerable)" = 1 ]; }
fixed_passes()       { [ "$(gate_rc fixed)" = 0 ]; }
dashboard_shows_both() { local page; page="$(curl -s -m 4 "$DASH_URL/")"; [[ "$page" == *"badge BLOCKED"* && "$page" == *"badge PASSED"* ]]; }
app_healthy()  { app_running && [ "$(http_code "$APP_URL/healthz")" = "200" ]; }
json_count()   { # URL-ENCODED-QUERY: the "count" field of /search
  local body; body="$(curl -s -m 4 --get --data-urlencode "q=$1" "$APP_URL/search")"
  python3 -c 'import json, sys; print(json.loads(sys.argv[1])["count"])' "$body"
}
search_works()    { [ "$(json_count alice)" = 1 ]; }
injection_fails() { [ "$(json_count "' OR '1'='1")" = 0 ]; }


check "Docker daemon reachable"                          $DOCKER info
check "the dashboard container is running"               dashboard_up
check "the dashboard answers on port 8080"               code_is "$DASH_URL/" 200
check "scan reports exist and are valid for both apps"   reports_valid
check "vulnerable: leaked secrets found"                 at_least vulnerable secrets 1
check "vulnerable: insecure code found (5+ issues)"      at_least vulnerable sast 5
check "vulnerable: Dockerfile problems found (3+)"       at_least vulnerable dockerfile 3
check "vulnerable: vulnerable dependencies found"        at_least vulnerable deps 3
check "vulnerable: the gate says BLOCKED"                vulnerable_blocked
check "fixed: the gate says PASSED"                      fixed_passes
check "the fixed app is deployed and healthy on 8081"    app_healthy
check "the deployed app answers a normal search"         search_works
check "the SQL injection attempt returns nothing"        injection_fails
check "the dashboard shows BLOCKED and PASSED"           dashboard_shows_both

echo
if [ "$BAD" -eq 0 ]; then echo "All $TOTAL checks passed."; exit 0; fi
echo "$BAD of $TOTAL checks failed." >&2
exit 1
