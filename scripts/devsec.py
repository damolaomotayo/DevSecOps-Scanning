#!/usr/bin/env python3
"""Reads the raw scanner reports in reports/<target>/, applies policy.json and prints/builds the results.
Standard library only.

  devsec.py gate   reports/vulnerable     table of checks; exit 0 = pass, 1 = blocked, 2 = a report is missing/invalid
  devsec.py count  reports/vulnerable deps    print the number of findings for one check
  devsec.py show   reports/vulnerable deps [N]   the worst N findings, one per line
  devsec.py report                        rebuild reports/index.html (the dashboard)
"""
import html
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FILES = {"secrets": "gitleaks.json", "sast": "semgrep.json", "dockerfile": "hadolint.json",
         "deps": "trivy-deps.json", "image": "trivy-image.json"}
ORDER = ["secrets", "sast", "dockerfile", "deps", "image"]
TARGETS = ["vulnerable", "fixed"]


# ---------- reading the raw reports ----------
def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise ValueError("report missing")
    except json.JSONDecodeError:
        raise ValueError("report is not valid JSON")


def clean_path(p):
    p = p or ""
    return p[len("/src/"):] if p.startswith("/src/") else p


def parse_secrets(data):          # gitleaks: a list (or null) of findings
    if data is not None and not isinstance(data, list):
        raise ValueError("unexpected gitleaks format")
    return [{"severity": "CRITICAL", "id": f.get("RuleID", "?"), "where": f"{clean_path(f.get('File'))}:{f.get('StartLine', '?')}",
             "text": f.get("Description", "")} for f in (data or [])]


def parse_sast(data):             # semgrep: {"results": [...]}
    if not isinstance(data, dict) or "results" not in data:
        raise ValueError("unexpected semgrep format")
    out = []
    for r in data["results"]:
        extra = r.get("extra", {})
        out.append({"severity": extra.get("severity", "INFO"), "id": r.get("check_id", "?").split(".")[-1],
                    "where": f"{clean_path(r.get('path'))}:{r.get('start', {}).get('line', '?')}",
                    "text": " ".join(extra.get("message", "").split())})
    return out


def parse_dockerfile(data):       # hadolint: a list of {code, level, line, message}
    if not isinstance(data, list):
        raise ValueError("unexpected hadolint format")
    return [{"severity": f.get("level", "info").upper(), "id": f.get("code", "?"), "where": f"Dockerfile:{f.get('line', '?')}",
             "text": f.get("message", "")} for f in data]


def parse_trivy(data):            # trivy: {"Results": [{"Vulnerabilities": [...], "Secrets": [...]}]}
    if not isinstance(data, dict):
        raise ValueError("unexpected trivy format")
    out = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion")
            out.append({"severity": v.get("Severity", "UNKNOWN"), "id": v.get("VulnerabilityID", "?"), "kind": "vuln",
                        "where": f"{v.get('PkgName', '?')} {v.get('InstalledVersion', '')}".strip(),
                        "text": (f"fix: upgrade to {fixed}. " if fixed else "") + (v.get("Title") or "")})
        for s in res.get("Secrets") or []:
            out.append({"severity": s.get("Severity", "HIGH"), "id": s.get("RuleID", "?"), "kind": "secret",
                        "where": f"{res.get('Target', '?')}:{s.get('StartLine', '?')}", "text": s.get("Title", "secret")})
    return out


PARSERS = {"secrets": parse_secrets, "sast": parse_sast, "dockerfile": parse_dockerfile,
           "deps": parse_trivy, "image": parse_trivy}


def load_policy(root=ROOT):
    with open(os.path.join(root, "policy.json"), encoding="utf-8") as fh:
        return json.load(fh)


# ---------- what counts against the gate ----------
def blocking(key, f):
    sev = f["severity"]
    if key == "secrets":
        return True
    if key == "sast":
        return sev == "ERROR"
    if key == "dockerfile":
        return sev in ("ERROR", "WARNING")
    if key == "deps":
        return sev in ("HIGH", "CRITICAL")
    if key == "image":
        return f.get("kind") == "secret" or sev == "CRITICAL"
    return False


def evaluate(report_dir, policy=None):
    """One row per check: key, title, rule, status (PASS/FAIL/ERROR), count (blocking), total, findings."""
    policy = policy or load_policy()
    rows = []
    for key in ORDER:
        row = {"key": key, "title": policy[key]["title"], "rule": policy[key]["rule"], "limit": policy[key]["max"],
               "count": 0, "total": 0, "findings": [], "status": "PASS", "detail": ""}
        try:
            findings = PARSERS[key](read_json(os.path.join(report_dir, FILES[key])))
        except ValueError as exc:
            row.update(status="ERROR", detail=str(exc))
            rows.append(row)
            continue
        row["findings"] = findings
        row["total"] = len(findings)
        row["count"] = sum(1 for f in findings if blocking(key, f))
        row["status"] = "PASS" if row["count"] <= row["limit"] else "FAIL"
        rows.append(row)
    return rows


def verdict(rows):
    if any(r["status"] == "ERROR" for r in rows):
        return "ERROR"
    return "BLOCKED" if any(r["status"] == "FAIL" for r in rows) else "PASSED"


# ---------- the dashboard ----------
CSS = """body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f4f6f8;color:#1b2430}
main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px}.sub{color:#5b6775;margin:0 0 24px}
section{background:#fff;border-radius:10px;padding:18px 20px;margin:0 0 22px;box-shadow:0 1px 3px #0002}
h2{margin:0 0 4px;display:flex;align-items:center;gap:12px}.badge{font-size:13px;padding:2px 12px;border-radius:99px;color:#fff}
.PASSED,.PASS{background:#1a7f37}.BLOCKED,.FAIL{background:#c62828}.ERROR{background:#8a6d00}
table{border-collapse:collapse;width:100%;margin:10px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e3e8ee;vertical-align:top}
th{font-size:13px;color:#5b6775}code{background:#eef1f5;padding:1px 5px;border-radius:4px}details{margin:6px 0}summary{cursor:pointer}
.sev{font-weight:600}.CRITICAL,.HIGH,.ERROR_{color:#c62828}.WARNING,.MEDIUM{color:#b26a00}"""


def esc(x):
    return html.escape(str(x), quote=True)


def render_target(name, rows):
    v = verdict(rows)
    msg = {"PASSED": "Every check is within policy. It may be deployed.",
           "BLOCKED": "The security gate stops this build. It is NOT deployed.",
           "ERROR": "A scanner did not produce a valid report, so the gate cannot decide."}[v]
    out = [f"<section><h2>{esc(name)} <span class='badge {v}'>{v}</span></h2><p class='sub'>{esc(msg)}</p>",
           "<table><tr><th>Check</th><th>Policy</th><th>Blocking findings</th><th>All findings</th><th>Result</th></tr>"]
    for r in rows:
        out.append(f"<tr><td>{esc(r['title'])}</td><td>{esc(r['rule'])}</td><td>{r['count']}</td>"
                   f"<td>{r['total']}</td><td><span class='badge {r['status']}'>{r['status']}</span> {esc(r['detail'])}</td></tr>")
    out.append("</table>")
    for r in rows:
        if not r["findings"]:
            continue
        shown = sorted(r["findings"], key=lambda f: ["CRITICAL", "HIGH", "ERROR", "WARNING", "MEDIUM", "LOW", "INFO"].index(f["severity"])
                       if f["severity"] in ("CRITICAL", "HIGH", "ERROR", "WARNING", "MEDIUM", "LOW", "INFO") else 9)[:12]
        out.append(f"<details><summary>{esc(r['title'])}: top {len(shown)} of {r['total']}</summary><table>"
                   "<tr><th>Severity</th><th>Rule / CVE</th><th>Where</th><th>What</th></tr>")
        for f in shown:
            out.append(f"<tr><td class='sev {esc(f['severity'])}'>{esc(f['severity'])}</td><td><code>{esc(f['id'])}</code></td>"
                       f"<td>{esc(f['where'])}</td><td>{esc(f['text'])}</td></tr>")
        out.append("</table></details>")
    out.append("</section>")
    return "\n".join(out)


def build_dashboard(root=ROOT):
    parts = []
    policy = load_policy(root)
    for t in TARGETS:
        d = os.path.join(root, "reports", t)
        if os.path.isdir(d):
            parts.append(render_target(t, evaluate(d, policy)))
    body = "\n".join(parts) or "<section><p>No scan has been run yet. Run <code>./scripts/up.sh</code>.</p></section>"
    page = ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>DevSecOps scan results</title><style>{CSS}</style></head><body><main><h1>DevSecOps scan results</h1>"
            "<p class='sub'>Five scanners, one policy (policy.json). A build that breaks the policy is blocked.</p>"
            f"{body}</main></body></html>\n")
    os.makedirs(os.path.join(root, "reports"), exist_ok=True)
    with open(os.path.join(root, "reports", "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)


# ---------- command line ----------
def main(argv):
    if len(argv) >= 3 and argv[1] == "gate":
        rows = evaluate(argv[2])
        for r in rows:
            mark = {"PASS": "ok  ", "FAIL": "FAIL", "ERROR": "ERR "}[r["status"]]
            extra = f"  ({r['detail']})" if r["detail"] else ""
            print(f"  {mark} {r['title']}: {r['count']} blocking (limit {r['limit']}), {r['total']} total{extra}")
        v = verdict(rows)
        print(f"  Verdict: {v}")
        return {"PASSED": 0, "BLOCKED": 1, "ERROR": 2}[v]
    if len(argv) >= 4 and argv[1] == "count":
        rows = {r["key"]: r for r in evaluate(argv[2])}
        r = rows[argv[3]]
        if r["status"] == "ERROR":
            print(-1)
            return 2
        print(r["count"] if len(argv) < 5 or argv[4] != "total" else r["total"])
        return 0
    if len(argv) >= 4 and argv[1] == "show":                      # show DIR KEY [N]: the worst findings, one per line
        r = {x["key"]: x for x in evaluate(argv[2])}[argv[3]]
        order = ["CRITICAL", "HIGH", "ERROR", "WARNING", "MEDIUM", "LOW", "INFO"]
        top = sorted(r["findings"], key=lambda f: order.index(f["severity"]) if f["severity"] in order else 9)
        for f in top[: int(argv[4]) if len(argv) > 4 else 8]:
            print(f"      {f['severity']:<8} {f['id']:<36} {f['where']}")
        return 0
    if len(argv) >= 2 and argv[1] == "report":
        build_dashboard()
        return 0
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
