# FIXTURE: an element write adds to a container; it never replaces it.
# `m['k'] = v` used to be applied as `m = v`, so a later clean key wiped the dirt.
# A Flask return has no shape rule, so silence on the guesses below would be a
# real regression, not one rule covering for another.
from flask import Flask, request

app = Flask(__name__)


@app.route("/later-clean-key", methods=["POST"])
def later_clean_key():
    # BenchmarkPython 00189: a constant written to ANOTHER key after the input.
    param = request.form.get("x")
    m = {}
    m['keyA'] = 'a-Value'
    m['keyB'] = param
    m['keyC'] = 'another-Value'
    bar = m['keyB']
    # EXPECT-FLOW xss
    return f"bar is '{bar}'"


@app.route("/branch", methods=["POST"])
def key_under_a_branch():
    # With no "c", m['k'] holds the literal: which value comes back is a guess.
    m = {}
    m['k'] = 'safe'
    if request.form.get("c"):
        m['k'] = request.form.get("x")
    m['j'] = 'other'
    # EXPECT-SIGNATURE xss
    return f"bar is '{m['k']}'"


@app.route("/rebound", methods=["POST"])
def rebound_between():
    # param changes after it is stored: the dict holds the old value, so the
    # read is not traced as `param` - it falls back to the whole-dict guess.
    param = request.form.get("x")
    m = {}
    m['k'] = param
    m['j'] = 'other'
    param = 'reset'
    # EXPECT-SIGNATURE xss
    return f"bar is '{m['k']}'"
