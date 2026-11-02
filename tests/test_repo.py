"""Sanity tests for the repo itself (layout, safety, config, docs). Stdlib only. Run from the repo root:
    python3 -m unittest discover -s tests -v
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

REQUIRED_FILES = [
    "README.md", "STEPS.md", "DEMO.md", "DIAGRAM_PROMPT.md", ".gitignore", ".gitattributes", ".env.example",
    "docker-compose.yml", "policy.json", "scan/semgrep-rules.yml", "reports/.gitkeep",
    "apps/vulnerable/app.py", "apps/vulnerable/requirements.txt", "apps/vulnerable/Dockerfile",
    "apps/fixed/app.py", "apps/fixed/requirements.txt", "apps/fixed/Dockerfile", "apps/fixed/.dockerignore",
    "scripts/lib.sh", "scripts/setup.sh", "scripts/preflight.sh", "scripts/up.sh", "scripts/scan.sh",
    "scripts/pipeline.sh", "scripts/smoke.sh", "scripts/demo.sh", "scripts/destroy.sh", "scripts/devsec.py",
    "tests/test_devsec.py", "tests/test_scripts.py",
]
SCRIPTS = [f for f in REQUIRED_FILES if f.endswith(".sh")]


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class LayoutTests(unittest.TestCase):
    def test_required_files_exist(self):
        for rel in REQUIRED_FILES:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, rel)), f"missing {rel}")

    def test_scripts_have_shebang(self):
        for rel in SCRIPTS:
            self.assertTrue(read(rel).startswith("#!/usr/bin/env bash"), rel)

    def test_no_crlf_line_endings(self):
        for rel in SCRIPTS + ["scripts/devsec.py", "docker-compose.yml"]:
            with open(os.path.join(ROOT, rel), "rb") as fh:
                self.assertNotIn(b"\r\n", fh.read(), rel)

    def test_generated_files_are_not_shipped_and_are_ignored(self):
        self.assertFalse(os.path.exists(os.path.join(ROOT, ".env")))
        self.assertFalse(os.path.exists(os.path.join(ROOT, "apps", "vulnerable", ".env.production")))
        ignore = read(".gitignore")
        for needle in (".env", "apps/vulnerable/.env.production", "reports/*"):
            self.assertIn(needle, ignore)


class SafetyTests(unittest.TestCase):
    def test_no_real_looking_secret_is_committed(self):
        """The demo's fake key is assembled at run time. Nothing key-shaped may sit in the repo (GitHub would block the push)."""
        patterns = [r"AKIA[A-Z2-7]{16}", r"ghp_[A-Za-z0-9]{36}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"wJalrXUtnFEMI" + r"/K7MDENG"]
        for dirpath, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for name in files:
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT)
                with open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
                for p in patterns:
                    self.assertIsNone(re.search(p, text), f"{rel} contains something matching {p}")

    def test_only_the_dashboard_and_the_app_are_published(self):
        ports = re.findall(r'-\s*"([^"]+)"', read("docker-compose.yml"))
        self.assertEqual([p for p in ports if re.match(r"^(\d+\.\d+\.\d+\.\d+:)?\d+:\d+$", p)], ["8080:80"])
        published = re.findall(r"-p\s+(\S+)", read("scripts/pipeline.sh"))
        self.assertEqual(published, ["8081:8000"])

    def test_scanners_never_get_the_docker_socket_or_write_access_to_the_sources(self):
        lib = read("scripts/lib.sh")
        self.assertNotIn("docker.sock", lib)
        self.assertNotIn("--privileged", lib)
        for line in lib.splitlines():
            if re.search(r'-v "[^"]*:/src', line):
                self.assertIn(":/src:ro", line)

    def test_deployed_container_is_locked_down(self):
        text = read("scripts/pipeline.sh")
        for flag in ("--read-only", "--cap-drop ALL", "no-new-privileges"):
            self.assertIn(flag, text)

    def test_fixed_app_is_clean_by_construction(self):
        app, docker = read("apps/fixed/app.py"), read("apps/fixed/Dockerfile")
        for bad in ("exec(", "shell=True", "yaml.load(", "md5", "debug=True", "% q", ".format("):
            self.assertNotIn(bad, app)
        self.assertNotRegex(app, r"(?<!literal_)eval\(")
        self.assertIn("USER appuser", docker)
        self.assertNotRegex(docker, r"(?m)^ADD ")
        self.assertIn("HEALTHCHECK", docker)
        self.assertRegex(read("apps/fixed/requirements.txt"), r"(?m)^Flask==")

    def test_vulnerable_app_really_contains_the_flaws_the_demo_talks_about(self):
        app, docker = read("apps/vulnerable/app.py"), read("apps/vulnerable/Dockerfile")
        for flaw in ("eval(", "shell=True", "yaml.load(", "hashlib.md5", "debug=True", "DB_PASSWORD"):
            self.assertIn(flaw, app)
        self.assertIn("ADD . /app", docker)
        self.assertIn("USER root", docker)
        for pin in ("Flask==1.1.2", "requests==2.19.1", "Pillow==9.0.0"):
            self.assertIn(pin, read("apps/vulnerable/requirements.txt"))

    def test_all_requirements_are_pinned(self):
        for app in ("vulnerable", "fixed"):
            for line in read(f"apps/{app}/requirements.txt").split():
                self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[\w.]+$", f"{app}: {line}")


class ScriptRuleTests(unittest.TestCase):
    def test_no_curl_f_against_docker_hub(self):
        for rel in SCRIPTS:
            for line in read(rel).splitlines():
                if "registry-1.docker.io" in line and "curl" in line:
                    self.assertNotRegex(line, r"curl\s+-\w*f", f"{rel}: {line}")

    def test_preflight_accepts_http_200_and_401_for_docker_hub(self):
        text = read("scripts/preflight.sh")
        self.assertIn('"$code" = "200"', text)
        self.assertIn('"$code" = "401"', text)

    def test_no_pipe_into_grep_q(self):
        for rel in SCRIPTS:
            for n, line in enumerate(read(rel).splitlines(), 1):
                if not line.strip().startswith("#"):
                    self.assertNotRegex(line, r"\|\s*grep\s+-\w*q", f"{rel}:{n}: {line}")

    def test_demo_has_all_scenarios_and_smoke_has_14_checks(self):
        demo = read("scripts/demo.sh")
        for name in ("secrets", "sast", "dockerfile", "deps", "image", "gate"):
            self.assertIn(f"scenario_{name}()", demo)
        smoke = read("scripts/smoke.sh")
        self.assertEqual(len(re.findall(r"^check ", smoke, re.M)), 14)
        self.assertIn('All $TOTAL checks passed.', smoke)

    def test_demo_does_not_exit_on_the_first_failed_check(self):
        self.assertNotRegex(read("scripts/demo.sh"), r"^set -\w*e")

    def test_every_scanner_image_is_set_from_env_and_pulled_by_preflight(self):
        pre = read("scripts/preflight.sh")
        for var in ("GITLEAKS_IMAGE", "SEMGREP_IMAGE", "HADOLINT_IMAGE", "TRIVY_IMAGE", "NGINX_IMAGE"):
            self.assertIn(f"${var}", pre)
        self.assertIn("python:3.8-slim", pre)
        self.assertIn("python:3.12-slim", pre)
        self.assertIn("python:3.8-slim", read("apps/vulnerable/Dockerfile"))
        self.assertIn("python:3.12-slim", read("apps/fixed/Dockerfile"))


class DocsTests(unittest.TestCase):
    def test_steps_has_prerequisites_first_and_the_key_items(self):
        text = read("STEPS.md")
        self.assertLess(text.index("## Prerequisites"), text.index("## Step 0"))
        for needle in ("8080", "8081", "chmod +x scripts/*.sh", "chmod 400", "All 14 checks passed.", "sudo apt update",
                       "Terminate", "My IP", "m7i-flex.large", "preflight.sh"):
            self.assertIn(needle, text)

    def test_every_script_is_documented_in_steps(self):
        steps = read("STEPS.md")
        for name in ("setup.sh", "preflight.sh", "up.sh", "smoke.sh", "demo.sh", "destroy.sh", "scan.sh", "pipeline.sh"):
            self.assertIn(name, steps)

    def test_demo_md_is_very_short(self):
        text = read("DEMO.md")
        self.assertLess(len(text.split()), 450)
        self.assertLess(len(text.splitlines()), 40)

    def test_diagram_prompt_mentions_the_main_parts(self):
        text = read("DIAGRAM_PROMPT.md")
        for needle in ("gitleaks", "semgrep", "hadolint", "trivy", "8080", "8081", "gate", "BLOCKED"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
