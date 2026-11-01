# FIXTURE: allow-list checks in Python - see safe/allow-list-guards.php for
# why each shape is here. Every sink must be CLEARED, not merely quiet.
# The fence is vulnerable/allow_list_fence.py.
import os
import re

from flask import request


def page():
    p = request.args.get("page")
    if not p.isdigit():
        return "bad", 400
    # EXPECT-CLEAN command-injection
    os.system("sed -n " + p + "p app.log")
    return "ok"


def lang():
    code = request.args.get("lang")
    if re.fullmatch(r"[a-z]{2}", code):
        # EXPECT-CLEAN xss
        return '<html lang="' + code + '">'
    return ""


def sort(cursor):
    s = request.args.get("sort")
    if s in ("name", "price", "date"):
        # EXPECT-CLEAN sql-injection
        cursor.execute("SELECT * FROM products ORDER BY " + s)


def mode():
    m = request.args.get("m")
    if m == "full" or m == "brief":
        # EXPECT-CLEAN xss
        return f"<p>{m}</p>"
    return ""


def by_id(cursor):
    i = request.args.get("id")
    if re.match(r"\d+\Z", i) is not None:
        # EXPECT-CLEAN sql-injection
        cursor.execute("SELECT * FROM t WHERE id = " + i)
