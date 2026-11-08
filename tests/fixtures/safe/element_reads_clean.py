# FIXTURE: element reads that certainly return a clean value. In safe/, any
# finding is a failure.
from flask import Flask, request

app = Flask(__name__)


@app.route("/other-key", methods=["POST"])
def other_key_is_a_literal():
    # One dirty element used to make every read of the dict a proof.
    m = {}
    m['keyA'] = 'a-Value'
    m['keyB'] = request.form.get("x")
    bar = m['keyA']
    return f"bar is '{bar}'"


def escape_char_by_char(s):
    # BenchmarkPython's helpers.utils.escape_for_html, in short.
    ret = ''
    for c in s:
        if c.isalnum():
            ret += c
        else:
            ret += f'&#x{hex(ord(c))[2:]};'
    return ret


@app.route("/escaped", methods=["POST"])
def escaped():
    bar = escape_char_by_char(request.form.get("x"))
    # EXPECT-CLEAN xss
    return f"bar is '{bar}'"
