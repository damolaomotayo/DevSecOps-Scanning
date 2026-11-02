#!/usr/bin/env bash
# Shared helpers. Sourced by the other scripts, not run directly.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# Use plain docker if the current user may talk to the daemon, otherwise sudo.
if docker info >/dev/null 2>&1; then DOCKER="docker"; else DOCKER="sudo docker"; fi
DC="$DOCKER compose"

TARGETS="vulnerable fixed"
STAGES="secrets sast dockerfile deps image"
DASH_URL="${DASH_URL:-http://127.0.0.1:8080}"
APP_URL="${APP_URL:-http://127.0.0.1:8081}"
APP_CONTAINER="dso-app"
TRIVY_CACHE="dso-trivy-cache"                          # docker volume holding trivy's vulnerability database

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

ensure_env() {
  [ -f "$ROOT/.env" ] || cp "$ROOT/.env.example" "$ROOT/.env"
  set -a; . "$ROOT/.env"; set +a
  mkdir -p "$ROOT/reports"
}
ensure_env

public_ip() { # EC2 metadata (IMDSv2), then a public what-is-my-ip fallback
  local tok ip=""
  tok="$(curl -fsS -m 2 -X PUT http://169.254.169.254/latest/api/token \
         -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
  if [ -n "$tok" ]; then
    ip="$(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $tok" \
          http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)"
  fi
  if [ -z "$ip" ]; then
    ip="$(curl -fsS -m 4 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
  fi
  echo "${ip:-<EC2-PUBLIC-IP>}"
}

http_code() { curl -s -o /dev/null -m 4 -w '%{http_code}' "$1" 2>/dev/null || true; }   # 000 = no connection

wait_http() { # LABEL URL [SECONDS]  (any 2xx)
  local label="$1" url="$2" secs="${3:-60}" i
  for ((i = 0; i < secs; i++)); do
    if curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; then ok "$label is up"; return 0; fi
    sleep 1
  done
  fail "$label did not answer at $url within ${secs}s"
  return 1
}

# ---- the demo "leaked" secrets ----
# Created at run time (and git-ignored) so that the repository itself never contains something
# that looks like a real key. The values are fake. The key is built from pieces on purpose.
seed_secrets() {
  local f="$ROOT/apps/vulnerable/.env.production" a="AKIA" b="QYLPMN5HFIQR7XYZ" c="wJalrXUtnFEMI" d="/K7MDENG/bPxRfiCYzR3vQ8kLm2"
  [ -f "$f" ] && return 0
  {
    echo "# Production settings that somebody forgot to keep out of the repo (FAKE values made by seed_secrets)"
    echo "AWS_ACCESS_KEY_ID=${a}${b}"
    echo "AWS_SECRET_ACCESS_KEY=${c}${d}"
    echo "DATABASE_URL=postgres://admin:hunter2hunter2@db.internal:5432/prod"
  } > "$f"
}

# ---- the scanners (each one is a throw-away official container; results go to reports/<target>/) ----
run_gitleaks() { # TARGET: writes reports/TARGET/gitleaks.json
  $DOCKER run --rm --user "$(id -u):$(id -g)" --entrypoint gitleaks \
    -v "$ROOT/apps/$1:/src:ro" -v "$ROOT/reports/$1:/out" "$GITLEAKS_IMAGE" \
    detect --no-git --no-banner --source /src --report-format json --report-path /out/gitleaks.json --exit-code 0
}
run_semgrep() { # TARGET: JSON on stdout
  $DOCKER run --rm -e HOME=/tmp --entrypoint semgrep \
    -v "$ROOT/apps/$1:/src:ro" -v "$ROOT/scan:/rules:ro" "$SEMGREP_IMAGE" \
    scan --config /rules/semgrep-rules.yml --json --metrics=off --disable-version-check --quiet /src
}
run_hadolint() { # TARGET: JSON on stdout (the Dockerfile is sent on stdin)
  $DOCKER run --rm -i --entrypoint hadolint "$HADOLINT_IMAGE" -f json --no-fail - < "$ROOT/apps/$1/Dockerfile"
}
trivy_flags() { # offline by default (the database was downloaded by preflight); TRIVY_ONLINE=1 lets it update
  if [ -n "${TRIVY_ONLINE:-}" ]; then echo "--skip-version-check"; else echo "--skip-version-check --skip-db-update --skip-java-db-update"; fi
}
run_trivy_deps() { # TARGET: JSON on stdout
  # shellcheck disable=SC2046
  $DOCKER run --rm -v "$TRIVY_CACHE:/root/.cache" -v "$ROOT/apps/$1:/src:ro" --entrypoint trivy "$TRIVY_IMAGE" \
    fs --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --format json $(trivy_flags) /src
}
run_trivy_image() { # TARGET: JSON on stdout (scans the saved image file reports/TARGET/image.tar)
  # shellcheck disable=SC2046
  $DOCKER run --rm -v "$TRIVY_CACHE:/root/.cache" -v "$ROOT/reports/$1:/img:ro" --entrypoint trivy "$TRIVY_IMAGE" \
    image --quiet --scanners vuln,secret --severity HIGH,CRITICAL --ignore-unfixed --format json $(trivy_flags) --input /img/image.tar
}
build_image() { # TARGET: docker build with up to 3 tries
  local i
  for i in 1 2 3; do
    $DOCKER build -q -t "dso-app:$1" "$ROOT/apps/$1" >/dev/null && return 0
    sleep 3
  done
  return 1
}

# ---- looking at results ----
count() { python3 "$ROOT/scripts/devsec.py" count "$ROOT/reports/$1" "$2" "${3:-}"; }   # count TARGET CHECK [total]
dashboard_up() { [ "$($DOCKER ps -q --filter "name=^dso-dashboard\$" | wc -l)" -gt 0 ]; }
app_running() { [ "$($DOCKER ps -q --filter "name=^$APP_CONTAINER\$" | wc -l)" -gt 0 ]; }
