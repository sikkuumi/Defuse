# A Flask view returns the response body directly - there is no res.send() for a
# call-sink to match on. Without this modelled, the most ordinary reflected XSS
# in Python produced NOTHING, and the escaped version in safe/ "passed" only
# because no sink existed for html.escape to be credited against.
from flask import request


def greet():
    name = request.args.get("name")
    # EXPECT-FLOW xss
    return f"<h1>Hello, {name}!</h1>"


def greet_concat():
    who = request.args.get("who")
    # EXPECT-FLOW xss
    return "<div class='greeting'>" + who + "</div>"


# A Flask ROUTE needs no markup in the string: Flask sends a returned str as
# text/html, so `<script>` in the value runs. BenchmarkPython's 31 real XSS
# cases are this shape, and every one was silent.
from flask import Flask

app = Flask(__name__)


@app.route("/echo", methods=["POST"])
def echo():
    bar = request.form.get("bar")
    # EXPECT-FLOW xss
    return f"bar is '{bar}'"


@app.route("/accumulate")
def accumulate():
    RESPONSE = ""
    bar = request.args.get("bar")
    RESPONSE += f"Parameter value: {bar}"
    # EXPECT-FLOW xss
    return RESPONSE
