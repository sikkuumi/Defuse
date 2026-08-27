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
