#!/usr/bin/env bash
# Removes everything this project created: the dashboard, the deployed app, both app images, the
# vulnerability database volume, the reports and the fake secrets file.
# Usage: ./scripts/destroy.sh [--keep-env] [--images]     (--images also deletes the scanner images)
set -uo pipefail
. "$(dirname "$0")/lib.sh"

KEEP_ENV=""; IMAGES=""
for a in "$@"; do case "$a" in --keep-env) KEEP_ENV=1 ;; --images) IMAGES=1 ;; *) die "usage: $0 [--keep-env] [--images]" ;; esac; done

log "Stopping the dashboard and the deployed app"
$DC down --remove-orphans
$DOCKER rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true

log "Removing the app images and the vulnerability database"
$DOCKER rmi -f dso-app:vulnerable dso-app:fixed >/dev/null 2>&1 || true
$DOCKER volume rm "$TRIVY_CACHE" >/dev/null 2>&1 || true

if [ -n "$IMAGES" ]; then
  log "Removing the scanner images"
  for img in "$GITLEAKS_IMAGE" "$SEMGREP_IMAGE" "$HADOLINT_IMAGE" "$TRIVY_IMAGE" python:3.8-slim python:3.12-slim; do
    $DOCKER rmi -f "$img" >/dev/null 2>&1 || true
  done
fi

rm -rf "$ROOT"/reports/*/ "$ROOT/reports/index.html" "$ROOT/apps/vulnerable/.env.production"
[ -n "$KEEP_ENV" ] || rm -f "$ROOT/.env"

echo
echo "Cleanup done. (Scanner images stay cached; add --images to delete them too.)"
echo "IMPORTANT: terminate the EC2 instance in the AWS console (EC2 > Instances >"
echo "Instance state > Terminate) so it stops costing money. Then delete the security group."
