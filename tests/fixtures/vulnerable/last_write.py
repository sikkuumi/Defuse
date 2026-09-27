# The Python half of last-write.js: the write that certainly runs last before
# the read decides the value, and a write that might not run does not.

from flask import request


def overwritten(conn):
    bar = request.args.get("p")
    bar = "safe"
    # EXPECT-CLEAN sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def last_write_in_if(conn):
    bar = request.args.get("p")
    if len(bar) > 3:
        bar = "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


# A write inside a try that may throw first, and a while-else whose else is
# skipped by the break: neither last write is certain.
def try_last(conn):
    bar = request.args.get("p")
    try:
        bar = "safe"
        risky()
    except Exception:
        pass
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def while_else(conn):
    bar = request.args.get("p")
    while cond():
        break
    else:
        bar = "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")
