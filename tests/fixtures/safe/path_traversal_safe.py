# FIXTURE: the fixes for path traversal, which must stay quiet.
import os

from flask import Flask, request, send_from_directory
from PIL import Image
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    name = secure_filename(request.form["name"])
    # EXPECT-CLEAN path-traversal
    with open(os.path.join("/srv/uploads", name), "w") as f:
        f.write(request.form["body"])
    return "ok"


@app.route("/read")
def read():
    name = os.path.basename(request.args["name"])
    # EXPECT-CLEAN path-traversal
    with open("reports/" + name) as f:
        return f.read()


# send_from_directory refuses a path that climbs out of its folder.
@app.route("/static/<path:name>")
def static_file(name):
    return send_from_directory("/srv/static", request.args.get("f", name))


# Image.open shares only the name with the builtin.
@app.route("/thumb")
def thumb():
    return str(Image.open(request.files["img"]).size)
