# STEPS: DevSecOps Scanning with a Security Gate

## Prerequisites (set these up BEFORE step 1)

| Need | Details |
|---|---|
| **AWS account** | Any account that can launch EC2. No IAM role, no other AWS service. Use one region for everything below. |
| **Instance type** | `m7i-flex.large` (2 vCPU, 8 GiB). This project needs about 2 GiB. |
| **OS image (AMI)** | Ubuntu Server 24.04 LTS (64-bit x86). 22.04 also works. |
| **Disk** | 20 GiB gp3. |
| **Key pair** | An RSA `.pem` key pair created in EC2 (step 0a). |
| **Security group** | Created in step 0b. **Inbound: exactly three rules: (1) SSH, TCP port 22; (2) Custom TCP, port 8080 (the dashboard); (3) Custom TCP, port 8081 (the deployed app). All with source My IP.** **Outbound: leave the default (All traffic, 0.0.0.0/0)**, because the instance must reach Docker Hub (the scanner images), the trivy database registries (ghcr.io and mirror.gcr.io), PyPI (the apps' libraries are installed while building the images) and Docker's apt repo. |
| **Code on the instance** | Option A: private GitHub repo plus a fine-grained token (Contents: Read) used as the password for `git clone`. Option B: copy the zip with `scp` (step 2). |
| **Accounts / tokens** | None. The demo's fake secrets are generated on the instance (git-ignored). |
| **On your laptop** | A terminal with `ssh`/`scp` and a web browser. **No SSH tunnel is needed:** open `http://<PUBLIC-IP>:8080/` and `:8081/` directly. |

**Time:** about 12 minutes of setup (the first run downloads about 2 GiB of images), 10 minutes for the full demo. **Cost:** about $0.10/hour at your quoted rate, plus pennies for the disk. Do step 12 when finished.

---

## Step 0: Create the key pair, security group and instance (AWS console)

**0a. Key pair.** EC2 > Network & Security > Key pairs > **Create key pair**. Name `devsec-lab-key`, type **RSA**, format **.pem**. The file downloads once; keep it safe. On your laptop, lock down its permissions:

```bash
# Linux / macOS
chmod 400 ~/Downloads/devsec-lab-key.pem
```
```powershell
# Windows PowerShell (OpenSSH)
icacls "$HOME\Downloads\devsec-lab-key.pem" /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

**0b. Security group.** EC2 > Network & Security > Security Groups > **Create security group**.
- Name: `devsec-lab-sg`, Description: `SSH, dashboard and app from my IP`, VPC: the default VPC.
- **Inbound rules > Add rule** (do it three times):
  1. Type `SSH`, Protocol `TCP`, Port range `22`, Source `My IP`
  2. Type `Custom TCP`, Protocol `TCP`, Port range `8080`, Source `My IP`
  3. Type `Custom TCP`, Protocol `TCP`, Port range `8081`, Source `My IP`
- **Outbound rules:** leave the default rule (Type `All traffic`, Destination `0.0.0.0/0`).
- Click **Create security group**.

> Showing the demo to someone on a different network? Their browser is blocked by "My IP". Either share your screen, or add their public IP followed by `/32` as the source of the 8080 and 8081 rules. Do not use `0.0.0.0/0`.

**0c. Launch the instance.** EC2 > Instances > **Launch instances**.
- Name: `devsec-lab-box`
- Application and OS Image: **Ubuntu**, choose **Ubuntu Server 24.04 LTS**, architecture **64-bit (x86)**
- Instance type: `m7i-flex.large`
- Key pair: `devsec-lab-key`
- Network settings > **Edit**: Auto-assign public IP **Enable**; Firewall: **Select existing security group** > `devsec-lab-sg`
- Configure storage: **20 GiB**, `gp3`
- Advanced details > IAM instance profile: leave as **No IAM role**
- Click **Launch instance**, wait until Instance state is `Running` and Status check is `2/2 passed`, then copy the **Public IPv4 address**. This is your `<PUBLIC-IP>` below.

> If your network changes later, SSH and the pages will time out because "My IP" no longer matches. Edit **all three** inbound rules of `devsec-lab-sg` and set Source to My IP again. Stopping and starting the instance also gives it a new public IP.

## Step 1: Connect to the instance (from your laptop)

```bash
ssh -i ~/Downloads/devsec-lab-key.pem ubuntu@<PUBLIC-IP>
```
Type `yes` at the fingerprint prompt. Every command from here to step 11 runs **on the instance**.

## Step 2: Update packages and get the code

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git unzip
```

**Option A (private GitHub repo):**
```bash
git clone https://github.com/<you>/devsecops-scanning.git
cd devsecops-scanning
```
When asked, username = your GitHub username, password = the fine-grained token.

**Option B (no GitHub), run from your laptop in the folder holding the zip, then continue on the instance:**
```bash
# on your laptop
scp -i ~/Downloads/devsec-lab-key.pem devsecops-scanning.zip ubuntu@<PUBLIC-IP>:~
# on the instance
unzip devsecops-scanning.zip
cd devsecops-scanning
```

## Step 3: Make the scripts executable (do not skip)

Files that were zipped, uploaded to GitHub or copied between systems often lose their "executable" flag. Without this you get `Permission denied`.

```bash
chmod +x scripts/*.sh
ls -l scripts/        # every .sh line should start with -rwxr-xr-x
```

## Step 4: Install Docker

```bash
./scripts/setup.sh
```
It runs `apt update`/`upgrade`, installs `ca-certificates curl git gnupg openssl python3 unzip`, installs Docker Engine and Compose v2 from Docker's official repo (falling back to Ubuntu's `docker.io` package if that repo is unreachable), starts Docker and prints the versions. Takes 3-5 minutes. It ends with `Setup complete.` The scanners are **not** installed on the instance: each one runs from its official container image.

## Step 5: Unit tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
Ends with `OK` (a few seconds). They test the gate logic and the dashboard with canned scanner output, the scan and pipeline scripts with a stand-in for Docker, and the repo layout. Tests that need the real `semgrep` or `trivy` on the host show as `skipped`; that is normal.

## Step 6: Preflight (run this well before the demo)

```bash
./scripts/preflight.sh
```
Checks Docker, disk (10 GB), memory (3.5 GB) and ports 8080 and 8081; checks that Docker Hub is reachable; pulls the five tool images and the two Python base images; **downloads trivy's vulnerability database once** into a Docker volume (so scans work offline afterwards); runs all scanners on both apps and checks that the vulnerable app is flagged and the fixed app is clean; builds both app images; runs the tests. Every line must say `ok`, and the last line is `Preflight passed. Safe to run ./scripts/up.sh`. First run takes 6-12 minutes.

## Step 7: Run the pipeline for both apps

```bash
./scripts/up.sh
```
Starts the dashboard, then runs the pipeline twice: the **vulnerable** app (scan, gate, `BLOCKED`, nothing deployed) and the **fixed** app (scan, gate, `PASSED`, deployed on port 8081). Takes 3-5 minutes. It prints:

```
Dashboard : http://<PUBLIC-IP>:8080/
Fixed app : http://<PUBLIC-IP>:8081/
```

## Step 8: Health check

```bash
./scripts/smoke.sh
```
Every line says `ok` and it ends with **`All 14 checks passed.`**

## Step 9: Open the pages in your browser (on your laptop)

- `http://<PUBLIC-IP>:8080/`: the dashboard. **vulnerable** shows a red `BLOCKED` badge with the findings of all five scanners; **fixed** shows a green `PASSED` badge. Click a "top findings" line to expand it.
- `http://<PUBLIC-IP>:8081/`: the deployed (fixed) app, answering `{"app":"devsec-demo","edition":"fixed"}`. Try `http://<PUBLIC-IP>:8081/search?q=alice`.

## Step 10: Run the demo (on the instance)

```bash
./scripts/demo.sh all           # all six scenarios, about 10 minutes
```
Or one at a time (each scans both apps and checks the result; refresh the dashboard after each):
```bash
./scripts/demo.sh secrets       # gitleaks: a forgotten .env.production with cloud keys
./scripts/demo.sh sast          # semgrep: SQL injection, eval, unsafe YAML, shell=True, debug mode, hard-coded passwords
./scripts/demo.sh dockerfile    # hadolint: ADD, running as root, unpinned packages, no cache flag
./scripts/demo.sh deps          # trivy: CVEs in the pinned libraries, with the fixed version for each
./scripts/demo.sh image         # trivy: the built image, including the secret baked into it
./scripts/demo.sh gate          # the whole pipeline: vulnerable BLOCKED, fixed PASSED and deployed, injection attempt fails
```
Each scenario ends with a green `PASS`.

## Step 11: Useful commands (a manual walkthrough you can do live)

```bash
./scripts/pipeline.sh vulnerable                              # scan + gate + (not) deploy; exit code 1 = blocked
./scripts/pipeline.sh fixed                                   # exit code 0 = passed and deployed
./scripts/scan.sh vulnerable secrets                          # run just one scanner
python3 scripts/devsec.py gate reports/vulnerable             # the gate table for an app
python3 scripts/devsec.py show reports/vulnerable deps 10     # the worst 10 findings of one scanner
cat policy.json                                               # the rule book (change "max" to loosen a rule)
cat scan/semgrep-rules.yml                                    # the code rules
cat apps/vulnerable/.env.production                           # the fake "forgotten" secrets
curl "http://localhost:8081/search?q=alice"                   # the deployed app: one result
curl --get --data-urlencode "q=' OR '1'='1" http://localhost:8081/search   # SQL injection attempt: zero results
```

## Step 12: Clean up, then terminate the instance

```bash
./scripts/destroy.sh
```
Then in the AWS console: EC2 > Instances > select `devsec-lab-box` > **Instance state > Terminate instance**. Optionally delete the `devsec-lab-sg` security group and `devsec-lab-key` key pair too.

---

## What you should see

| Step | Result |
|---|---|
| 5 | Tests end with `OK` |
| 6 | All `ok`, then `Preflight passed.` |
| 7 | `BLOCKED` for vulnerable, `PASSED` and deployed for fixed, then two URLs |
| 8 | `All 14 checks passed.` |
| 9 | Red `BLOCKED` and green `PASSED` badges; the app answers on 8081 |
| 10 | Six `PASS` lines, then `All scenarios passed.` |

## Risky dependencies and fallbacks

| Dependency | Risk | Fallback |
|---|---|---|
| Docker Hub (scanner images, `python`, `nginx`) | Rate limit or a withdrawn tag | `sudo docker login` with a free account, or change the tag in `.env` and re-run preflight |
| trivy's vulnerability database (`ghcr.io`, then `mirror.gcr.io`) | Unreachable, or rate-limited | Preflight downloads it once and keeps it in a Docker volume; later scans are offline. **Run preflight early.** Re-run it to retry |
| Image tags in `.env.example` (written from memory) | A tag is not found | Pick another tag of the same image on Docker Hub and put it in `.env` |
| PyPI (installs the apps' libraries while building the images) | Unreachable | The build is retried 3 times; once built the images are cached |
| New CVEs appear every day | The fixed app could one day fail the gate | Preflight shows it early. Bump the version in `apps/fixed/requirements.txt`, or relax `policy.json` |
| `python:3.8-slim` (old on purpose) | Tag removed from Docker Hub | Use any older Python tag in `apps/vulnerable/Dockerfile` and the preflight list |
| Do not run `destroy.sh` before the demo | It deletes the database volume and the built images | Re-run preflight afterwards |
| MinIO, LocalStack | **Not used** | none needed |

## If something goes wrong

| Symptom | Fix |
|---|---|
| SSH: `Connection timed out` | Your IP changed. Edit security group `devsec-lab-sg`, inbound rule SSH port 22, Source My IP. Also confirm the instance is Running and has a public IP. |
| Browser: the dashboard never loads at `http://<PUBLIC-IP>:8080/` | (1) Use `http://` not `https://`, and include `:8080`. (2) The inbound rule for 8080 must exist with Source My IP. (3) Check the IP is the instance's current public IP. (4) On the instance: `curl -I http://localhost:8080/` should return `200`. If it works, the problem is the security group; if not, run `./scripts/up.sh`. |
| `:8081` does not load | The fixed app is deployed only when it passes the gate. `sudo docker ps` should list `dso-app`. If not, run `./scripts/pipeline.sh fixed`. Also check the 8081 inbound rule. |
| Testing the public IP from the instance itself hangs | Expected: the security group only allows your laptop's IP. Use `localhost` on the instance. |
| SSH: `Permission denied (publickey)` | Use user `ubuntu` (not `ec2-user`), the right `.pem`, and `chmod 400` on it. |
| SSH: `UNPROTECTED PRIVATE KEY FILE` | `chmod 400 devsec-lab-key.pem` |
| `./scripts/x.sh: Permission denied` | `chmod +x scripts/*.sh` (step 3). Or run with `bash scripts/x.sh`. |
| `bad interpreter: /usr/bin/env bash^M` | Windows line endings. Run `sed -i 's/\r$//' scripts/*.sh` |
| `permission denied` on the Docker socket in your own commands | The scripts use `sudo` for you. For manual commands use `sudo docker ...`, or log out and back in once. |
| Preflight: `Docker Hub reachable` or a `Pull ...` line fails | Check the outbound rule is All traffic; `sudo docker login` with a free account; if the tag is not found, edit the image in `.env`. |
| Preflight: `Trivy vulnerability database downloaded` fails | `TRIVY_ONLINE=1 ./scripts/scan.sh fixed deps` shows trivy's error. It needs to reach `ghcr.io` or `mirror.gcr.io`; wait a minute and retry (these registries rate-limit). |
| Preflight: `All scanners run on both apps` fails | Run the stage by hand to see the message, e.g. `./scripts/scan.sh vulnerable secrets`. A scanner container that exits with an error is reported by name. |
| Preflight: `The fixed app is clean` fails | `python3 scripts/devsec.py gate reports/fixed` shows which check. A new CVE: raise the version in `apps/fixed/requirements.txt`. |
| Preflight: `Both app images build` fails | `sudo docker build apps/vulnerable` (or `apps/fixed`) shows the failing step; usually a PyPI network blip, run preflight again. |
| Preflight: `Port 8080 is free` (or 8081) fails | `sudo ss -ltnp \| grep -E ':808[01] '`, stop what uses it, or `./scripts/destroy.sh` if it is an old run of this project. |
| `up.sh`: `Expected the vulnerable app to be blocked` | A scanner did not run or found nothing. Read the messages above it; `python3 scripts/devsec.py gate reports/vulnerable` shows the table. |
| Gate says `ERROR` (yellow) | A report is missing or invalid: a scanner failed. Run the failing stage alone with `./scripts/scan.sh <app> <stage>`. |
| `demo.sh`: `The dashboard is not running` | `./scripts/up.sh` |
| `demo.sh`: `scan of ... failed` | Run the command it prints and read the scanner's message. |
| Disk full | `sudo docker system prune -af` (this removes cached images and the CVE database; preflight downloads them again) |
