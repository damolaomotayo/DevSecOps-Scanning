# DevSecOps Scanning with a Security Gate

Five open-source scanners check two versions of one small web app, and a policy decides whether a build may be deployed. One EC2 instance, only Docker installed, no other AWS services.

```
apps/vulnerable  --\                         /-- BLOCKED: nothing is deployed
                    >-- gitleaks, semgrep, hadolint, trivy (deps), trivy (image) --> security gate (policy.json)
apps/fixed       --/                         \-- PASSED: deployed on :8081          dashboard on :8080
```

## What is in it

| Part | What it shows |
|---|---|
| `apps/vulnerable` | A deliberately insecure Flask app: hard-coded passwords, SQL injection, `eval`, unsafe YAML, shell injection, weak hash, debug mode, old libraries with known CVEs, a bad Dockerfile, and a forgotten `.env.production` with fake cloud keys (created at run time, git-ignored) |
| `apps/fixed` | The same app, fixed: parameterised SQL, no `eval`, safe YAML, no secrets, current libraries, non-root image with a health check |
| **gitleaks** | Leaked secrets in files |
| **semgrep** | Insecure code patterns, using our own rules in `scan/semgrep-rules.yml` (no internet needed for rules) |
| **hadolint** | Dockerfile best practices |
| **trivy** | Known CVEs in `requirements.txt` and in the built image, plus secrets baked into the image |
| `policy.json` | The rule book: what counts against the gate (limits are all 0) |
| `scripts/devsec.py` | Reads the reports, applies the policy, prints the gate table, builds the dashboard (standard library only) |
| `scripts/pipeline.sh` | scan, then gate, then deploy only if passed |
| `docker-compose.yml` | The dashboard (nginx, port 8080). Scanners are run on demand as throw-away containers |

## Quick start (on Ubuntu 24.04 with sudo)

```bash
chmod +x scripts/*.sh
./scripts/setup.sh        # installs Docker (once)
./scripts/preflight.sh    # pulls images, downloads the CVE database once, proves everything works
./scripts/up.sh           # scans both apps: vulnerable is BLOCKED, fixed is PASSED and deployed
./scripts/smoke.sh        # 14 checks, ends with "All 14 checks passed."
./scripts/demo.sh all     # six scenarios
./scripts/destroy.sh      # remove everything (after the demo)
```

Open `http://<EC2-PUBLIC-IP>:8080/` (dashboard) and `:8081/` (deployed app). See **STEPS.md** for the full walkthrough and **DEMO.md** for the one-page talk track.

## Notes

- Requirements: 2 vCPU, 4 GiB RAM or more, 10 GiB free disk. The scanner images are about 2 GiB in total.
- Preflight downloads trivy's vulnerability database into a Docker volume; after that the demo needs no internet for scanning. Do not run `destroy.sh` before the demo.
- CVE data changes daily. The fixed app is pinned to current versions and the gate ignores CVEs that have no fix yet, but a brand-new CVE could in theory make the fixed app fail the gate. Preflight tells you early. Change `policy.json` or the pins if that happens.
- All secrets in this repo's demo are fake and generated at run time.
