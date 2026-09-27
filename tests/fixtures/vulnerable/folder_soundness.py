# The Python half of FolderSoundness.java.
#
#   param_once   a parameter holds the caller's value before any `=`, and the
#                one `=` here sits inside an if that might not run
#
# Python has no block-scoped declarations, so a single write only decides a
# name when it is at the TOP of the function body - never inside an if, a
# loop or a try - and the name is not a parameter.

import sqlite3
from flask import request


def param_once(conn, num):
    param = request.args.get("p")
    if param == "":
        num = 500
    bar = "safe" if num > 200 else param
    # EXPECT-FLOW sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")
