# EXPECT-NONE
#
# The partner to vulnerable/flask-return.py. This one escapes first, so the
# tracer must RETRACT rather than report - and, crucially, it must do so because
# it saw the sink and credited the escaping, not because it never looked.
import html
from flask import request


def greet_safe():
    name = request.args.get("name")
    return f"<h1>Hello, {html.escape(name)}!</h1>"


def greet_safe_var():
    name = html.escape(request.args.get("name"))
    return "<div>" + name + "</div>"
