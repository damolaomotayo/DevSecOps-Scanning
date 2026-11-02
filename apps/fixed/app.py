"""The same demo app, fixed: parameterised SQL, no eval, safe YAML, no shell, no secrets in code."""
import ast
import os
import sqlite3

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (name TEXT, role TEXT)")
db.executemany("INSERT INTO users VALUES (?, ?)", [("alice", "admin"), ("bob", "user"), ("carol", "user")])


@app.route("/")
def index():
    return jsonify(app="devsec-demo", edition="fixed")


@app.route("/healthz")
def healthz():
    return "ok\n"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db.execute("SELECT name, role FROM users WHERE name = ?", (q,)).fetchall()
    return jsonify(query=q, count=len(rows), rows=rows)


@app.route("/calc")
def calc():
    try:
        return jsonify(result=ast.literal_eval(request.args.get("expr", "0")))   # literals only, never code
    except (ValueError, SyntaxError):
        return jsonify(error="only plain numbers and lists are accepted"), 400


@app.route("/config", methods=["POST"])
def config():
    data = yaml.safe_load(request.get_data(as_text=True))
    return jsonify(keys=sorted(data) if isinstance(data, dict) else [])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
