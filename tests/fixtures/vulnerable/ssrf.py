import requests, urllib.request
from flask import request

def fetch_profile():
    # EXPECT-FLOW ssrf
    return requests.get(request.args["url"]).text

def fetch_raw():
    # EXPECT-FLOW ssrf
    return urllib.request.urlopen(request.form["endpoint"]).read()

def fetch_fixed():
    return requests.get("https://api.example.com/status").text       # SAFE
