# EXPECT-NONE
#
# SQL assembled by interpolation, where every spliced-in value is a literal
# written a line above. The shape is "dynamic"; the content is not. A tester
# handed us exactly this expecting silence, and got a HIGH.
#
# The sibling function below matters as much as this one: it binds the SAME
# name to a request value. The first version of this check searched the whole
# module for bindings, walked into the sibling, and concluded `table` was
# tainted here - so it kept quiet in a one-function test file and did nothing
# at all in a realistic one.
import sqlite3


def admin_table(conn):
    table = "admin_users"
    return conn.execute(f"SELECT * FROM {table}")


def report_table(conn):
    table = "reports"
    order = "created_at"
    return conn.execute(f"SELECT * FROM {table} ORDER BY {order}")
