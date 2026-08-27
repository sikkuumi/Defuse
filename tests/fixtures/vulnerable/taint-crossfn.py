# FIXTURE: flows that cross a function boundary, Python.
from flask import request


def run_query(cursor, sql_text):
    # EXPECT-FLOW sql-injection
    cursor.execute(sql_text)


def handler_forward(cursor):
    run_query(cursor, "SELECT * FROM users WHERE id = " + request.args["id"])


def read_name():
    return request.args["name"]


def handler_return(cursor):
    name = read_name()
    # EXPECT-FLOW sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
