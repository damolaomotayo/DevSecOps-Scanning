#!/usr/bin/env bash
# Runs the scanners on one app and writes raw reports to reports/<target>/, then rebuilds the dashboard.
# Usage: ./scripts/scan.sh vulnerable|fixed [secrets sast dockerfile deps image ...]   (default: all five)
set -uo pipefail
. "$(dirname "$0")/lib.sh"

T="${1:-}"; shift || true
case "$T" in vulnerable|fixed) ;; *) die "usage: $0 vulnerable|fixed [stage ...]   (stages: $STAGES)" ;; esac
WANT="${*:-$STAGES}"
for s in $WANT; do case " $STAGES " in *" $s "*) ;; *) die "unknown stage '$s' (stages: $STAGES)" ;; esac; done

OUT="$ROOT/reports/$T"
mkdir -p "$OUT"
[ "$T" = "vulnerable" ] && seed_secrets
FAILED=0

stage() { # STAGE LABEL FILE COMMAND...   JSON goes to the file, and only if the command succeeded
  local key="$1" label="$2" file="$3"; shift 3
  case " $WANT " in *" $key "*) ;; *) return 0 ;; esac
  log "[$T] $label"
  rm -f "$OUT/$file"
  if "$@" > "$OUT/$file.tmp"; then mv "$OUT/$file.tmp" "$OUT/$file"; else rm -f "$OUT/$file.tmp"; fail "$label: the scanner container failed (see the messages above)"; FAILED=1; fi
}

secrets_stage() { # gitleaks writes its own file, and may write none when it finds nothing
  case " $WANT " in *" secrets "*) ;; *) return 0 ;; esac
  log "[$T] secrets (gitleaks)"
  rm -f "$OUT/gitleaks.json"
  if run_gitleaks "$T"; then [ -f "$OUT/gitleaks.json" ] || echo "[]" > "$OUT/gitleaks.json"; else fail "gitleaks failed (see the messages above)"; FAILED=1; fi
}

image_stage() {
  case " $WANT " in *" image "*) ;; *) return 0 ;; esac
  log "[$T] image: docker build, then trivy image"
  rm -f "$OUT/trivy-image.json" "$OUT/image.tar"
  if ! build_image "$T"; then fail "docker build failed. Run: $DOCKER build apps/$T"; FAILED=1; return 0; fi
  if ! $DOCKER save -o "$OUT/image.tar" "dso-app:$T"; then fail "docker save failed"; FAILED=1; return 0; fi
  if run_trivy_image "$T" > "$OUT/trivy-image.json.tmp"; then mv "$OUT/trivy-image.json.tmp" "$OUT/trivy-image.json"
  else rm -f "$OUT/trivy-image.json.tmp"; fail "trivy image failed (database missing? run ./scripts/preflight.sh)"; FAILED=1; fi
  rm -f "$OUT/image.tar"
}

secrets_stage
stage sast       "code patterns (semgrep)"           semgrep.json     run_semgrep "$T"
stage dockerfile "Dockerfile (hadolint)"             hadolint.json    run_hadolint "$T"
stage deps       "dependencies (trivy fs)"           trivy-deps.json  run_trivy_deps "$T"
image_stage

python3 "$ROOT/scripts/devsec.py" report
[ "$FAILED" -eq 0 ] || exit 1
