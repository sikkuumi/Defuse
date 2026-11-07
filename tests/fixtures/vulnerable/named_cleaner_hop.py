# A function we do not model is assumed to pass its value through. When its
# own name says it escapes or cleans, that assumption may not be called proof:
# BenchmarkPython's 60 "proven" XSS all ran through its own HTML escaper.
import base64
import pickle

from flask import Flask, request
from helpers.utils import escape_for_html, helper

app = Flask(__name__)


@app.route("/escaped")
def escaped():
    bar = request.args.get("bar")
    # EXPECT-SIGNATURE xss
    return f"value: {escape_for_html(bar)}"


@app.route("/roundtrip")
def roundtrip():
    # b64decode(b64encode(x)) is x: an encode undone later cleaned nothing.
    param = request.args.get("p")
    tmp = base64.b64encode(param.encode("utf-8"))
    bar = base64.b64decode(tmp).decode("utf-8")
    # EXPECT-FLOW code-injection
    eval(bar)


@app.route("/html-before-pickle")
def html_before_pickle():
    # An HTML escaper is no defence for pickle: base64 survives it untouched.
    bar = escape_for_html(request.args.get("p"))
    # EXPECT-FLOW unsafe-deserialization
    pickle.loads(base64.urlsafe_b64decode(bar))
    return "ok"


def global_name_is_not_local():
    # `global` makes `code` the module's, and helper() can rewrite it before
    # eval runs: the literal write alone proves nothing.
    global code
    code = "1 + 1"
    helper()
    # EXPECT-SIGNATURE code-injection
    eval(code)
