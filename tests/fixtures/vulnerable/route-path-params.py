# FIXTURE: path parameters bound by a route decorator are sources.
#
# Flask and FastAPI hand a view its URL segments as plain arguments. By the
# time the body runs, `name` is a str and nothing in the body says where it
# came from - the only evidence is the placeholder in the decorator's path.
# Before this was read, every one of these was traced from nothing.
import os
from flask import Flask
from fastapi import FastAPI

app = Flask(__name__)
api = FastAPI()


@app.route("/user/<name>")
def flask_plain(name):
    # EXPECT-FLOW command-injection
    os.system("id " + name)


@app.get("/file/<path:target>")
def flask_converter(target):
    # EXPECT-FLOW command-injection
    os.system("cat " + target)


@api.get("/items/{item_id}")
def fastapi_braces(item_id: str):
    # EXPECT-FLOW command-injection
    os.system("lookup " + item_id)


# The fence. A decorator whose string holds a placeholder, but is not a
# route, binds nothing. Neither does a route parameter the path does not
# name - `limit` below comes from a default, not the URL.
@cache.memoize("<name>")
def not_a_route(name):
    # EXPECT-SIGNATURE command-injection
    os.system("id " + name)


@app.route("/list/<kind>")
def unnamed_param(kind, limit="10"):
    # EXPECT-SIGNATURE command-injection
    os.system("ls -n " + limit)
