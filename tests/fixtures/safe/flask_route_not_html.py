# EXPECT-NONE
#
# The fence around the Flask-route return sink in vulnerable/flask-return.py:
# each of these returns attacker text WITHOUT it becoming an HTML page.
from fastapi import FastAPI
from flask import Flask, request

app = Flask(__name__)
api = FastAPI()


@app.route("/data")
def as_dict():
    # Flask turns a dict into JSON (application/json): not a page.
    out = {}
    out["x"] = request.args.get("x")
    return out


@app.route("/maybe")
def maybe_dict(flag):
    # Not a str by construction: one branch holds a dict.
    body = ""
    if flag:
        body = {"x": request.args.get("x")}
    return body


@api.get("/fast")
def fastapi_str(x: str):
    # FastAPI JSON-encodes a returned str.
    return f"bar is {x}"


def not_a_route():
    # No route decorator and no markup: a str some other code uses.
    return f"bar is {request.args.get('x')}"
