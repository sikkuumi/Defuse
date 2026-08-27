# The constant-folding check must never swallow a real one. Three ways a name
# that LOOKS locally constant is not: reassigned from a request, arriving as a
# parameter, or bound somewhere we cannot see.
import sqlite3


def reassigned(conn, request):
    table = "admin_users"
    table = request.args.get("t")
    # EXPECT sql-injection
    return conn.execute(f"SELECT * FROM {table}")


def from_parameter(conn, table):
    # EXPECT sql-injection
    return conn.execute(f"SELECT * FROM {table}")


def no_visible_binding(conn):
    # EXPECT sql-injection
    return conn.execute(f"SELECT * FROM {MYSTERY_TABLE}")
