# The Python half of OuterWriteFence.java: a module global rewritten by a
# function that declares it `global`. `read_setting` is defined nowhere, so the
# tracer has no source to follow and only the pattern rule can speak.
#
# Python cannot write a module global from a function WITHOUT that statement -
# a plain assignment makes a new local - and the constant proof already counted
# `global` as a write it cannot follow. So this fence held before the Java one
# existed. It is here so the Python side of the rule is on the record.

TABLE = "users"


def set_table(key):
    global TABLE
    TABLE = read_setting(key)


def list_rows(conn):
    # EXPECT sql-injection
    return conn.execute("SELECT * FROM " + TABLE)
