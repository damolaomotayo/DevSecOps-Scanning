#!/usr/bin/env bash
# Starts the dashboard and runs the pipeline once for each app:
#   vulnerable -> scanned -> BLOCKED (not deployed)      fixed -> scanned -> PASSED -> deployed on 8081
set -uo pipefail
. "$(dirname "$0")/lib.sh"

python3 "$ROOT/scripts/devsec.py" report                     # a placeholder page, so the dashboard has something to show
log "Starting the dashboard (nginx on port 8080)"
$DC up -d || die "docker compose up failed"
wait_http "dashboard" "$DASH_URL/" 60 || die "The dashboard did not start. Run: $DOCKER logs dso-dashboard"

log "Pipeline run 1 of 2: the vulnerable app (it should be BLOCKED)"
"$ROOT/scripts/pipeline.sh" vulnerable; rc=$?
[ "$rc" -eq 1 ] || die "Expected the vulnerable app to be blocked (exit 1) but the pipeline returned $rc. See the messages above."

log "Pipeline run 2 of 2: the fixed app (it should PASS and be deployed)"
"$ROOT/scripts/pipeline.sh" fixed || die "The fixed app did not pass the gate. Open the dashboard on port 8080 for the findings, or run: python3 scripts/devsec.py gate reports/fixed"

IP="$(public_ip)"
cat <<EOF

Done. Open in your browser (from the laptop allowed by the security group):
  Dashboard : http://${IP}:8080/    <- both apps: BLOCKED and PASSED, with every finding
  Fixed app : http://${IP}:8081/    <- deployed only because it passed the gate

Next: ./scripts/smoke.sh   then   ./scripts/demo.sh all
EOF
