# FIXTURE (cross-file): the source lives here; the sink is in xfile_db.py.
from flask import request
from xfile_db import run_query


def handler(cursor):
    run_query(cursor, "SELECT * FROM users WHERE id = " + request.args["id"])
