# The other side of outer_write_fence.py: a module global that no function
# writes. In safe/, any finding is a failure.

TABLE = "users"


def list_rows(conn):
    return conn.execute("SELECT * FROM " + TABLE)
