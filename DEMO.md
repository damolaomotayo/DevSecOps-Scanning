# Demo cheat sheet (1-minute read)

**What it does:** "DevSecOps" means finding security problems **before** code reaches production, automatically, on every build. Here five free scanners check two versions of the same small web app (one deliberately insecure, one fixed). A **security gate** blocks the bad build and only lets the good one be deployed. All on this one EC2 instance.

**How it works:**
1. **gitleaks** looks for leaked passwords and cloud keys in the files.
2. **semgrep** reads the code for dangerous patterns (SQL injection, `eval`, debug mode).
3. **hadolint** checks the Dockerfile; **trivy** checks the libraries and the built image for known CVEs.
4. `policy.json` is the rule book (zero blocking findings). The gate reads every report and says **PASSED** or **BLOCKED**.
5. Only a PASSED build is deployed (`http://<EC2-PUBLIC-IP>:8081/`). The dashboard (`:8080`) shows every finding.

**Example 1: the gate (`./scripts/demo.sh gate`)**
Keep `http://<PUBLIC-IP>:8080/` open. The vulnerable build is **BLOCKED** (red) and nothing is deployed. The fixed build is **PASSED** (green) and starts on port 8081. Try the SQL injection on it: it finds nothing.

**Example 2: secrets (`./scripts/demo.sh secrets`)**
A forgotten `.env.production` holds a cloud key. gitleaks finds it in the vulnerable app, nothing in the fixed one. Refresh the dashboard.

**Bonus:** `sast` (insecure code), `dockerfile` (build-file rules), `deps` (CVE list with the version that fixes each), `image` (the secret was even baked into the container image).

**If asked "why not scan only at the end?":** A fix costs minutes while the code is fresh and a breach costs far more. The gate makes the check automatic, so nobody has to remember.
