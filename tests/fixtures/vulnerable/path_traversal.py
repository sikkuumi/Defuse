# FIXTURE: path traversal (CWE-22) in Python.
import os
import shutil
import sys

from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/read")
def read():
    name = request.args.get("name")
    # EXPECT-FLOW path-traversal
    with open("reports/" + name) as f:
        return f.read()


@app.route("/download")
def download():
    # os.path.join keeps every `..` the user sent.
    target = os.path.join("/srv/files", request.args["f"])
    # EXPECT-FLOW path-traversal
    return send_file(target)


@app.route("/purge", methods=["POST"])
def purge():
    # EXPECT-FLOW path-traversal
    shutil.rmtree("/tmp/jobs/" + request.form["job"])
    return "ok"


@app.route("/remove", methods=["POST"])
def remove():
    # EXPECT-FLOW path-traversal
    os.remove(request.form["path"])
    return "ok"


@app.route("/checked")
def checked():
    # BenchmarkPython's shape: a `../` blocklist first. Not proven, not cleared.
    name = request.args["name"]
    if "../" in name:
        return "no"
    # EXPECT-SIGNATURE path-traversal
    with open(f"/srv/files/{name}") as f:
        return f.read()


def cli():
    # A script run by hand: its caller chooses the file and could read it anyway.
    # EXPECT-SIGNATURE path-traversal
    with open(sys.argv[1]) as f:
        return f.read()
