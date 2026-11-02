"""Tests scripts/devsec.py (parsing, policy, gate exit codes, dashboard) with canned scanner output, and
runs the real semgrep / trivy secret scanner against the demo apps when they are installed."""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import devsec  # noqa: E402

BAD = {
    "gitleaks.json": [{"RuleID": "aws-access-token", "File": "/src/.env.production", "StartLine": 2, "Description": "AWS key"}],
    "semgrep.json": {"results": [
        {"check_id": "scan.sql-injection-string-built-query", "path": "/src/app.py", "start": {"line": 33},
         "extra": {"severity": "ERROR", "message": "built from\n   a string <script>alert(1)</script>"}},
        {"check_id": "scan.weak-hash", "path": "/src/app.py", "start": {"line": 57}, "extra": {"severity": "WARNING", "message": "md5"}}],
        "errors": []},
    "hadolint.json": [{"code": "DL3020", "level": "error", "line": 3, "message": "Use COPY"},
                      {"code": "DL3042", "level": "warning", "line": 6, "message": "no-cache-dir"},
                      {"code": "DL3015", "level": "info", "line": 5, "message": "no-install-recommends"}],
    "trivy-deps.json": {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-30861", "PkgName": "Flask", "InstalledVersion": "1.1.2", "FixedVersion": "2.2.5", "Severity": "HIGH", "Title": "cookie"},
        {"VulnerabilityID": "CVE-2022-22817", "PkgName": "Pillow", "InstalledVersion": "9.0.0", "FixedVersion": "9.0.1", "Severity": "CRITICAL", "Title": "eval"}]}]},
    "trivy-image.json": {"Results": [{"Target": "app/.env.production", "Class": "secret", "Secrets": [
        {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "AWS Access Key ID", "StartLine": 2}]}]},
}
GOOD = {"gitleaks.json": [], "semgrep.json": {"results": [], "errors": []}, "hadolint.json": [],
        "trivy-deps.json": {"Results": None}, "trivy-image.json": {"SchemaVersion": 2}}


def write_reports(root, target, files):
    d = os.path.join(root, "reports", target)
    os.makedirs(d, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(d, name), "w") as fh:
            json.dump(data, fh)
    return d


class ParseAndGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="devsec-")
        self.bad = write_reports(self.tmp, "vulnerable", BAD)
        self.good = write_reports(self.tmp, "fixed", GOOD)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rows(self, d):
        return {r["key"]: r for r in devsec.evaluate(d)}

    def test_bad_reports_fail_every_check(self):
        rows = self.rows(self.bad)
        self.assertEqual({k: r["status"] for k, r in rows.items()}, {k: "FAIL" for k in devsec.ORDER})
        self.assertEqual(devsec.verdict(list(rows.values())), "BLOCKED")

    def test_counts_only_what_the_policy_blocks(self):
        rows = self.rows(self.bad)
        self.assertEqual((rows["sast"]["count"], rows["sast"]["total"]), (1, 2))          # the WARNING does not block
        self.assertEqual((rows["dockerfile"]["count"], rows["dockerfile"]["total"]), (2, 3))  # info does not block
        self.assertEqual(rows["deps"]["count"], 2)
        self.assertEqual(rows["image"]["count"], 1)                                        # the baked-in secret

    def test_good_reports_pass(self):
        rows = self.rows(self.good)
        self.assertTrue(all(r["status"] == "PASS" for r in rows.values()))
        self.assertEqual(devsec.verdict(list(rows.values())), "PASSED")

    def test_image_ignores_high_but_blocks_critical(self):
        data = copy.deepcopy(GOOD)
        data["trivy-image.json"] = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "libc", "InstalledVersion": "1", "Severity": "HIGH"}]}]}
        d = write_reports(self.tmp, "img1", data)
        self.assertEqual(self.rows(d)["image"]["status"], "PASS")
        data["trivy-image.json"]["Results"][0]["Vulnerabilities"][0]["Severity"] = "CRITICAL"
        d = write_reports(self.tmp, "img2", data)
        self.assertEqual(self.rows(d)["image"]["status"], "FAIL")

    def test_missing_or_invalid_report_is_an_error_not_a_pass(self):
        os.remove(os.path.join(self.good, "semgrep.json"))
        with open(os.path.join(self.good, "hadolint.json"), "w") as fh:
            fh.write("not json")
        rows = self.rows(self.good)
        self.assertEqual(rows["sast"]["status"], "ERROR")
        self.assertEqual(rows["dockerfile"]["status"], "ERROR")
        self.assertEqual(devsec.verdict(list(rows.values())), "ERROR")

    def test_a_looser_policy_lets_things_through(self):
        policy = devsec.load_policy()
        policy["deps"]["max"] = 5
        self.assertEqual({r["key"]: r for r in devsec.evaluate(self.bad, policy)}["deps"]["status"], "PASS")

    def test_gitleaks_null_report_means_no_findings(self):
        data = dict(GOOD)
        data["gitleaks.json"] = None
        d = write_reports(self.tmp, "nullcase", data)
        self.assertEqual(self.rows(d)["secrets"]["status"], "PASS")

    def test_policy_has_all_checks_with_zero_limits(self):
        policy = devsec.load_policy()
        self.assertEqual(sorted(policy), sorted(devsec.ORDER))
        self.assertTrue(all(p["max"] == 0 for p in policy.values()))


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="devsec-cli-")
        self.bad = write_reports(self.tmp, "vulnerable", BAD)
        self.good = write_reports(self.tmp, "fixed", GOOD)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "devsec.py"), *args], capture_output=True, text=True)

    def test_gate_exit_codes(self):
        self.assertEqual(self.run_cli("gate", self.good).returncode, 0)
        res = self.run_cli("gate", self.bad)
        self.assertEqual(res.returncode, 1)
        self.assertIn("Verdict: BLOCKED", res.stdout)
        os.remove(os.path.join(self.good, "gitleaks.json"))
        self.assertEqual(self.run_cli("gate", self.good).returncode, 2)

    def test_count_and_show(self):
        self.assertEqual(self.run_cli("count", self.bad, "deps").stdout.strip(), "2")
        self.assertEqual(self.run_cli("count", self.bad, "sast", "total").stdout.strip(), "2")
        self.assertEqual(self.run_cli("count", self.good, "secrets").stdout.strip(), "0")
        shown = self.run_cli("show", self.bad, "deps", "1").stdout
        self.assertIn("CVE-2022-22817", shown)                      # CRITICAL first
        self.assertNotIn("CVE-2023-30861", shown)

    def test_unknown_command(self):
        self.assertNotEqual(self.run_cli("nonsense").returncode, 0)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="devsec-dash-")
        shutil.copy(os.path.join(ROOT, "policy.json"), self.tmp)
        write_reports(self.tmp, "vulnerable", BAD)
        write_reports(self.tmp, "fixed", GOOD)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def page(self):
        devsec.build_dashboard(self.tmp)
        with open(os.path.join(self.tmp, "reports", "index.html"), encoding="utf-8") as fh:
            return fh.read()

    def test_shows_both_verdicts_and_findings(self):
        page = self.page()
        self.assertIn("badge BLOCKED", page)
        self.assertIn("badge PASSED", page)
        for needle in ("CVE-2022-22817", "sql-injection-string-built-query", "aws-access-token", "DL3020"):
            self.assertIn(needle, page)

    def test_scanner_text_is_html_escaped(self):
        page = self.page()
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_placeholder_without_any_scan(self):
        shutil.rmtree(os.path.join(self.tmp, "reports"))
        self.assertIn("No scan has been run yet", self.page())

    def test_a_broken_report_shows_error_not_passed(self):
        os.remove(os.path.join(self.tmp, "reports", "fixed", "trivy-deps.json"))
        page = self.page()
        self.assertIn("badge ERROR", page)


def find_tool(name):
    found = shutil.which(name)
    if found:
        return found
    sibling = os.path.join(os.path.dirname(sys.executable), name)
    return sibling if os.path.exists(sibling) else None


class RealScannerTests(unittest.TestCase):
    @unittest.skipUnless(find_tool("semgrep"), "semgrep not installed")
    def test_semgrep_rules_flag_the_vulnerable_app_and_not_the_fixed_one(self):
        def run(target):
            res = subprocess.run([find_tool("semgrep"), "scan", "--config", os.path.join(ROOT, "scan", "semgrep-rules.yml"), "--json",
                                  "--metrics=off", "--disable-version-check", "--quiet", os.path.join(ROOT, "apps", target)],
                                 capture_output=True, text=True, timeout=300)
            self.assertEqual(res.returncode, 0, res.stderr[-500:])
            return json.loads(res.stdout)
        bad = devsec.parse_sast(run("vulnerable"))
        ids = {f["id"] for f in bad}
        self.assertEqual(ids, {"hardcoded-credential", "sql-injection-string-built-query", "eval-or-exec", "yaml-unsafe-load",
                               "subprocess-shell-true", "weak-hash", "flask-debug-enabled"})
        self.assertGreaterEqual(sum(1 for f in bad if f["severity"] == "ERROR"), 6)
        self.assertEqual(devsec.parse_sast(run("fixed")), [])

    @unittest.skipUnless(shutil.which("trivy") or find_tool("trivy"), "trivy not installed")
    def test_trivy_secret_scanner_finds_the_seeded_key(self):
        tmp = tempfile.mkdtemp(prefix="seed-")
        try:
            os.makedirs(os.path.join(tmp, "scripts"))
            os.makedirs(os.path.join(tmp, "apps", "vulnerable"))
            shutil.copy(os.path.join(ROOT, "scripts", "lib.sh"), os.path.join(tmp, "scripts"))
            shutil.copy(os.path.join(ROOT, ".env.example"), tmp)
            subprocess.run(["bash", "-c", f'. "{tmp}/scripts/lib.sh"; seed_secrets'], check=True, capture_output=True,
                           env=dict(os.environ, PATH="/nonexistent-docker:" + os.environ["PATH"]))
            res = subprocess.run([shutil.which("trivy") or find_tool("trivy"), "fs", "--quiet", "--scanners", "secret", "--format", "json",
                                  "--skip-version-check", os.path.join(tmp, "apps", "vulnerable")], capture_output=True, text=True, timeout=120)
            self.assertEqual(res.returncode, 0, res.stderr[-500:])
            found = devsec.parse_trivy(json.loads(res.stdout))
            self.assertIn("aws-access-key-id", {f["id"] for f in found})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
