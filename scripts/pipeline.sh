#!/usr/bin/env bash
# A tiny CI/CD pipeline with a security gate: scan -> gate -> deploy only if the gate passes.
# Usage: ./scripts/pipeline.sh vulnerable|fixed       exit 0 = passed (and deployed), 1 = blocked, 2 = scanner problem
set -uo pipefail
. "$(dirname "$0")/lib.sh"

T="${1:-}"
case "$T" in vulnerable|fixed) ;; *) die "usage: $0 vulnerable|fixed" ;; esac

deploy() {
  log "[$T] DEPLOY: starting the container on port 8081"
  $DOCKER rm -f "$APP_CONTAINER" >/dev/null 2>&1
  $DOCKER run -d --name "$APP_CONTAINER" --restart unless-stopped -p 8081:8000 \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges "dso-app:$T" >/dev/null || return 1
  wait_http "the deployed app" "$APP_URL/healthz" 40
}

"$ROOT/scripts/scan.sh" "$T" || { echo "Pipeline stopped: a scanner did not run." >&2; exit 2; }

log "[$T] SECURITY GATE (policy.json)"
python3 "$ROOT/scripts/devsec.py" gate "$ROOT/reports/$T"
rc=$?
case "$rc" in
  0) deploy || { fail "deploy failed"; exit 2; }
     printf '\n\033[1;32mPASSED\033[0m  %s passed the gate and is deployed: %s/\n\n' "$T" "$APP_URL" ;;
  1) printf '\n\033[1;31mBLOCKED\033[0m  %s broke the policy. Nothing was deployed.\n\n' "$T" ;;
  *) printf '\n\033[1;33mERROR\033[0m  a report is missing or invalid, so the gate cannot decide.\n\n' ;;
esac
exit "$rc"
