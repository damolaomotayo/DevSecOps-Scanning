#!/usr/bin/env bash
# Run this BEFORE the demo. It pulls every image, downloads the vulnerability database once (so the demo
# works offline and fast), proves the scanners run on both apps, builds both app images and runs the tests.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

FAILS=0
check() { # LABEL COMMAND...
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; FAILS=$((FAILS + 1)); fi
}

pull_with_retry() { # IMAGE
  local i
  for i in 1 2 3; do
    $DOCKER pull "$1" >/dev/null 2>&1 && return 0
    sleep 3
  done
  return 1
}

# Docker Hub's /v2/ endpoint answers HTTP 401 (login required) when it is reachable.
# So 200 and 401 both mean "reachable". Do not add curl -f here.
hub_reachable() {
  local code
  code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' https://registry-1.docker.io/v2/ || true)"
  [ "$code" = "200" ] || [ "$code" = "401" ]
}
disk_ok()   { [ "$(df -BG --output=avail / | tail -n1 | tr -dc '0-9')" -ge 10 ]; }
mem_ok()    { [ "$(free -m | awk '/^Mem:/{print $2}')" -ge 3500 ]; }
port_free() { ! python3 -c 'import socket, sys; s = socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$1"; }
# The first trivy run downloads the vulnerability database into the cache volume (TRIVY_ONLINE lets it).
warm_db()   { local out; out="$(mktemp)"; TRIVY_ONLINE=1 run_trivy_deps fixed > "$out"; local rc=$?; rm -f "$out"; return $rc; }
quick_scans() {
  mkdir -p "$ROOT/reports/vulnerable" "$ROOT/reports/fixed"
  "$ROOT/scripts/scan.sh" vulnerable secrets sast dockerfile deps && "$ROOT/scripts/scan.sh" fixed secrets sast dockerfile deps
}
flags_the_vulnerable_app() { [ "$(count vulnerable secrets)" -ge 1 ] && [ "$(count vulnerable sast)" -ge 5 ] && [ "$(count vulnerable deps)" -ge 1 ]; }
leaves_the_fixed_app_alone() { [ "$(count fixed secrets)" = 0 ] && [ "$(count fixed sast)" = 0 ] && [ "$(count fixed dockerfile)" = 0 ] && [ "$(count fixed deps)" = 0 ]; }
build_both() { build_image vulnerable && build_image fixed; }
all_tests() { PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests; }

log "System checks"
check "Docker daemon reachable"                  $DOCKER info
check "Docker Compose v2 installed"              $DC version
check "At least 10 GB free disk"                 disk_ok
check "At least 3.5 GB RAM"                      mem_ok
if dashboard_up; then ok "Dashboard already running (port 8080 check skipped)"; else check "Port 8080 is free" port_free 8080; fi
if app_running; then ok "App already running (port 8081 check skipped)"; else check "Port 8081 is free" port_free 8081; fi
check "Docker Hub reachable (HTTP 200 or 401)"   hub_reachable

log "Pulling images (up to 3 tries each; the first pull takes a few minutes)"
for img in "$GITLEAKS_IMAGE" "$SEMGREP_IMAGE" "$HADOLINT_IMAGE" "$TRIVY_IMAGE" "$NGINX_IMAGE" python:3.8-slim python:3.12-slim; do
  check "Pull $img" pull_with_retry "$img"
done

log "Scanners"
check "Trivy vulnerability database downloaded"  warm_db
check "All scanners run on both apps"            quick_scans
check "The vulnerable app is flagged"            flags_the_vulnerable_app
check "The fixed app is clean"                   leaves_the_fixed_app_alone
check "Both app images build"                    build_both

log "Tests"
check "Unit tests, report tests and repo tests"  all_tests

echo
if [ "$FAILS" -eq 0 ]; then
  echo "Preflight passed. Safe to run ./scripts/up.sh"
  exit 0
fi
echo "Preflight found $FAILS problem(s). See the troubleshooting table in STEPS.md." >&2
echo "Pull failed? Run 'sudo docker login' with a free Docker Hub account. Wrong tag? Edit the image in .env." >&2
exit 1
