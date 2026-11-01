# FIXTURE: the same rule in Python - a fixed address with a path after it.
from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/user")
def user():
    # EXPECT-SIGNATURE ssrf
    return requests.get(f"https://api.example.com/users/{request.args['id']}").text


@app.route("/proxy")
def proxy():
    # EXPECT-FLOW ssrf
    return requests.get(request.args["url"]).text
