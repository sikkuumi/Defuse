# FIXTURE: flows the taint engine must VERIFY, Python.
import subprocess
from flask import request


def through_a_variable(cursor):
    user_id = request.args["id"]
    sql = "SELECT * FROM users WHERE id = " + user_id
    # EXPECT-FLOW sql-injection
    cursor.execute(sql)


def through_an_fstring(cursor):
    # EXPECT-FLOW sql-injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{request.args['name']}'")


def into_a_shell():
    # EXPECT-FLOW command-injection
    subprocess.run("ping -c 1 " + request.args["host"], shell=True)
