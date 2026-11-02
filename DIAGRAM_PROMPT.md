# Diagram prompt (copy everything below into an image-generation model)

Create a clean, professional cloud infrastructure diagram, 16:9 landscape, white background, flat vector style, large readable labels, thin dark-grey lines, soft pastel fills. Title at the top: "DevSecOps Scanning: a security gate on one EC2 instance".

LAYOUT, left to right.

LEFT: a "Browser (your laptop)" box with two items: "http://<EC2-PUBLIC-IP>:8080/ (scan dashboard)" and "http://<EC2-PUBLIC-IP>:8081/ (deployed app)". Solid arrows labeled "HTTP 8080" and "HTTP 8081" go to the right. Below it a small "Terminal (SSH port 22)" box with a dashed arrow to the right.

MIDDLE: a thin firewall icon labeled "Security group: inbound SSH 22, TCP 8080 and TCP 8081, all from my IP only; outbound all".

RIGHT: a large AWS-orange-bordered box labeled "AWS Region > Default VPC > EC2 instance m7i-flex.large (Ubuntu 24.04, 2 vCPU, 8 GiB)". Inside it, one big blue rounded box labeled "Docker Engine". Inside the Docker box, a pipeline drawn left to right as connected stages:
1. A box "Source: apps/vulnerable and apps/fixed (Flask app, requirements.txt, Dockerfile)".
2. A column of five small scanner boxes, each a throw-away container: "gitleaks: secrets", "semgrep: code patterns", "hadolint: Dockerfile", "trivy: dependencies (CVEs)", "trivy: built image".
3. A document stack labeled "JSON reports" feeding a diamond labeled "Security gate (policy.json: zero blocking findings)".
4. From the diamond, a red arrow labeled "BLOCKED: nothing is deployed" ending at a stop sign, and a green arrow labeled "PASSED" to a box "Deployed app container (read-only, no extra privileges) :8081".
5. Below the diamond, a box "Dashboard (nginx) :8080 shows every finding" fed by the reports.
6. A small cylinder labeled "trivy vulnerability database (Docker volume, downloaded once, then offline)" connected to the two trivy boxes.

Numbered arrows, each with a short label:
1. Terminal to the pipeline: "./scripts/up.sh".
2. Source to each of the five scanners: "scan".
3. Scanners to JSON reports: "findings".
4. Reports to the gate: "apply policy".
5. Gate to the dashboard: "verdict and findings".
6. Vulnerable app: a red path ending at BLOCKED; fixed app: a green path ending at the deployed container.
7. Browser to dashboard and to the deployed app.

Add a small legend: blue = public entry point, green = passed and deployed, red = blocked. Add a footer note: "All scanners run as containers on this one instance. No other AWS services are used."

Do not add any AWS services (no Inspector, GuardDuty, ECR, IAM, CodePipeline). Use generic icons, with a simple Docker whale as the only logo. Make sure all text is spelled exactly as written above.
