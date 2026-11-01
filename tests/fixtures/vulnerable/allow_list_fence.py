# FIXTURE: the fence around safe/allow_list_guards.py. Each check looks like an
# allow-list and is not one here, so every line must still be reported.
import os
import re

from flask import request


def match_has_no_end():
    # re.match pins the start only: "1; id" starts with a digit.
    h = request.args.get("h")
    if re.match(r"\d+", h):
        # EXPECT-FLOW command-injection
        os.system("ping " + h)


def multi_line_flag():
    h = request.args.get("h")
    if re.match(r"\d+$", h, re.M):
        # EXPECT-FLOW command-injection
        os.system("ping " + h)


def not_in_the_list(cursor):
    s = request.args.get("sort")
    if s not in ("name", "price"):
        # EXPECT-FLOW sql-injection
        cursor.execute("SELECT * FROM products ORDER BY " + s)


def either_check():
    h = request.args.get("h")
    if h.isdigit() or request.args.get("force"):
        # EXPECT-FLOW command-injection
        os.system("ping " + h)
