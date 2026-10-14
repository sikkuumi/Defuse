# The Python half of joined-constant.js: literals joined with `+` are fixed.
# In safe/, any finding is a failure.


def archived(conn):
    base = "users"
    table = base + "_archive"
    return conn.execute("SELECT * FROM " + table)
