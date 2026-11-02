"""A deliberately INSECURE demo app. Every flaw below is on purpose, so the scanners have something to find.
Never run this anywhere real."""
import hashlib
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PASSWORD = "Sup3rS3cret!2024"            # flaw: hard-coded credential
API_TOKEN = "internal-api-token-9f8e7d"     # flaw: hard-coded credential

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (name TEXT, role TEXT)")
db.executemany("INSERT INTO users VALUES (?, ?)", [("alice", "admin"), ("bob", "user"), ("carol", "user")])


@app.route("/")
def index():
    return jsonify(app="devsec-demo", edition="vulnerable")


@app.route("/healthz")
def healthz():
    return "ok\n"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db.execute("SELECT name, role FROM users WHERE name = '%s'" % q).fetchall()   # flaw: SQL injection
    return jsonify(query=q, count=len(rows), rows=rows)


@app.route("/calc")
def calc():
    return jsonify(result=eval(request.args.get("expr", "0")))                            # flaw: eval on user input


@app.route("/config", methods=["POST"])
def config():
    data = yaml.load(request.get_data(as_text=True))                                      # flaw: unsafe YAML load
    return jsonify(keys=sorted(data) if isinstance(data, dict) else [])


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)                        # flaw: shell injection
    return out


@app.route("/hash")
def hash_password():
    return hashlib.md5(request.args.get("pw", "").encode()).hexdigest()                   # flaw: weak hash


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)                                        # flaw: debug mode
