"""Tests the shell scripts (scan.sh, pipeline.sh, lib.sh) with a stub `docker`: no Docker, no network.
The stub answers like the real scanners would for the "vulnerable" and "fixed" apps."""
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import HTTPServer, SimpleHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from test_devsec import BAD, GOOD  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

STUB = r'''#!/usr/bin/env python3
import json, os, re, sys
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(" ".join(args) + "\n")
fixtures = json.load(open(os.environ["STUB_FIXTURES"]))
def target():
    m = re.search(r"/apps/(vulnerable|fixed)", " ".join(args)) or re.search(r"/reports/(vulnerable|fixed)", " ".join(args))
    return m.group(1) if m else "fixed"
cmd = args[0] if args else ""
if cmd == "ps":
    print("abc123" if "dso-dashboard" in " ".join(args) and os.environ.get("STUB_DASH") else "")
elif cmd == "save":
    open(args[args.index("-o") + 1], "w").write("tar")
elif cmd == "run":
    if os.environ.get("STUB_FAIL_TOOL") and ("--entrypoint " + os.environ["STUB_FAIL_TOOL"]) in " ".join(args):
        sys.exit(3)
    ep = args[args.index("--entrypoint") + 1] if "--entrypoint" in args else ""
    t = target()
    fx = fixtures[t]
    if ep == "gitleaks":
        out = [a for a in args if a.endswith(":/out")][0].split(":")[0]
        if fx["gitleaks.json"]:
            json.dump(fx["gitleaks.json"], open(os.path.join(out, "gitleaks.json"), "w"))
    elif ep == "semgrep":
        print(json.dumps(fx["semgrep.json"]))
    elif ep == "hadolint":
        sys.stdin.read()
        print(json.dumps(fx["hadolint.json"]))
    elif ep == "trivy":
        print(json.dumps(fx["trivy-image.json"] if "image" in args else fx["trivy-deps.json"]))
    elif "-d" in args:
        print("container-id")
sys.exit(0)
'''


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dso-scripts-")
        for d in ("scripts", "scan", "apps"):
            shutil.copytree(os.path.join(ROOT, d), os.path.join(self.tmp, d))
        for f in (".env.example", "policy.json"):
            shutil.copy(os.path.join(ROOT, f), self.tmp)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        stub = os.path.join(self.bin, "docker")
        with open(stub, "w") as fh:
            fh.write(STUB)
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)
        self.log = os.path.join(self.tmp, "docker.log")
        self.fix = os.path.join(self.tmp, "fixtures.json")
        with open(self.fix, "w") as fh:
            json.dump({"vulnerable": BAD, "fixed": GOOD}, fh)
        # a tiny web server that plays "the deployed app" (answers /healthz)
        web = os.path.join(self.tmp, "web")
        os.makedirs(web)
        with open(os.path.join(web, "healthz"), "w") as fh:
            fh.write("ok\n")
        handler = lambda *a, **k: QuietHandler(*a, directory=web, **k)  # noqa: E731
        self.server = HTTPServer(("127.0.0.1", free_port()), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.app_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, *cmd, **env):
        full = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], STUB_LOG=self.log, STUB_FIXTURES=self.fix,
                    APP_URL=self.app_url, **env)
        return subprocess.run(["bash", *cmd], cwd=self.tmp, env=full, capture_output=True, text=True, timeout=120)

    def logged(self):
        with open(self.log) as fh:
            return fh.read()

    def gate(self, target):
        return subprocess.run([sys.executable, os.path.join(self.tmp, "scripts", "devsec.py"), "gate", os.path.join(self.tmp, "reports", target)],
                              capture_output=True, text=True).returncode

    # ---- scan.sh ----
    def test_scan_writes_all_five_reports_and_the_dashboard(self):
        res = self.run_script("scripts/scan.sh", "vulnerable")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        files = set(os.listdir(os.path.join(self.tmp, "reports", "vulnerable")))
        self.assertEqual(files, {"gitleaks.json", "semgrep.json", "hadolint.json", "trivy-deps.json", "trivy-image.json"})
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "reports", "index.html")))
        self.assertEqual(self.gate("vulnerable"), 1)

    def test_clean_app_with_no_gitleaks_file_still_gets_an_empty_report(self):
        res = self.run_script("scripts/scan.sh", "fixed")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        with open(os.path.join(self.tmp, "reports", "fixed", "gitleaks.json")) as fh:
            self.assertEqual(json.load(fh), [])
        self.assertEqual(self.gate("fixed"), 0)

    def test_scan_can_run_selected_stages_only(self):
        self.run_script("scripts/scan.sh", "fixed", "sast", "deps")
        self.assertEqual(sorted(os.listdir(os.path.join(self.tmp, "reports", "fixed"))), ["semgrep.json", "trivy-deps.json"])
        self.assertNotEqual(self.run_script("scripts/scan.sh", "fixed", "bogus").returncode, 0)
        self.assertNotEqual(self.run_script("scripts/scan.sh", "other").returncode, 0)

    def test_a_failing_scanner_fails_the_scan_and_leaves_no_report(self):
        res = self.run_script("scripts/scan.sh", "fixed", "sast", STUB_FAIL_TOOL="semgrep")
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "reports", "fixed", "semgrep.json")))
        self.assertNotIn("semgrep.json.tmp", os.listdir(os.path.join(self.tmp, "reports", "fixed")))

    def test_scanner_command_lines(self):
        self.run_script("scripts/scan.sh", "vulnerable")
        log = self.logged()
        self.assertRegex(log, r"run --rm --user \d+:\d+ --entrypoint gitleaks .*zricethezav/gitleaks:v[\d.]+ detect --no-git")
        self.assertRegex(log, r"--entrypoint semgrep .*scan --config /rules/semgrep-rules.yml --json --metrics=off")
        self.assertRegex(log, r"--entrypoint hadolint .* -f json --no-fail -")
        self.assertRegex(log, r"--entrypoint trivy .*fs --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --format json .*--skip-db-update")
        self.assertRegex(log, r"--entrypoint trivy .*image --quiet --scanners vuln,secret .*--input /img/image\.tar")
        self.assertIn("build -q -t dso-app:vulnerable", log)
        self.assertIn(":/src:ro", log)                                       # sources are mounted read-only
        self.assertIn("dso-trivy-cache:/root/.cache", log)

    def test_trivy_updates_its_database_only_when_asked(self):
        self.run_script("scripts/scan.sh", "fixed", "deps", TRIVY_ONLINE="1")
        line = [x for x in self.logged().splitlines() if "--entrypoint trivy" in x][0]
        self.assertNotIn("--skip-db-update", line)

    def test_image_tar_is_removed_after_the_scan(self):
        self.run_script("scripts/scan.sh", "fixed", "image")
        self.assertNotIn("image.tar", os.listdir(os.path.join(self.tmp, "reports", "fixed")))

    # ---- the demo secrets ----
    def test_seed_secrets_creates_a_key_shaped_fake_and_never_overwrites(self):
        self.run_script("scripts/scan.sh", "vulnerable", "secrets")
        path = os.path.join(self.tmp, "apps", "vulnerable", ".env.production")
        with open(path) as fh:
            text = fh.read()
        self.assertRegex(text, r"AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}\n")
        with open(path, "w") as fh:
            fh.write("custom\n")
        self.run_script("scripts/scan.sh", "vulnerable", "secrets")
        with open(path) as fh:
            self.assertEqual(fh.read(), "custom\n")

    # ---- pipeline.sh ----
    def test_pipeline_blocks_the_vulnerable_app_and_does_not_deploy(self):
        res = self.run_script("scripts/pipeline.sh", "vulnerable")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("BLOCKED", res.stdout)
        self.assertNotIn("run -d", self.logged())

    def test_pipeline_deploys_the_fixed_app(self):
        res = self.run_script("scripts/pipeline.sh", "fixed")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("PASSED", res.stdout)
        deploy = [x for x in self.logged().splitlines() if x.startswith("run -d")][0]
        for flag in ("--name dso-app", "-p 8081:8000", "--read-only", "--cap-drop ALL", "no-new-privileges", "dso-app:fixed"):
            self.assertIn(flag, deploy)

    def test_pipeline_reports_a_scanner_problem_as_exit_2(self):
        res = self.run_script("scripts/pipeline.sh", "fixed", STUB_FAIL_TOOL="hadolint")
        self.assertEqual(res.returncode, 2)
        self.assertNotIn("run -d", self.logged())

    def test_pipeline_rejects_unknown_targets(self):
        self.assertNotEqual(self.run_script("scripts/pipeline.sh", "nope").returncode, 0)


class EnvTests(unittest.TestCase):
    def test_env_example_images_are_pinned_official_ones(self):
        with open(os.path.join(ROOT, ".env.example")) as fh:
            env = dict(re.findall(r"^(\w+)=(.*)$", fh.read(), re.M))
        self.assertEqual(sorted(env), ["GITLEAKS_IMAGE", "HADOLINT_IMAGE", "NGINX_IMAGE", "SEMGREP_IMAGE", "TRIVY_IMAGE"])
        for k, v in env.items():
            self.assertRegex(v, r":[v]?\d+\.\d+", k)                         # a version tag, never :latest


if __name__ == "__main__":
    unittest.main()
