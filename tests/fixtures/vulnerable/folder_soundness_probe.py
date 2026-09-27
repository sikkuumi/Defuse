# The Python half of FolderSoundnessProbe.java - an adversarial probe's programs,
# each a real injection the constant folder hid before this was fixed.
import sqlite3
from flask import request


def tuple_assign(conn):
    param = request.args.get("p")
    n = 0
    n, m = len(param), 0
    bar = param if n > 5 else "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def list_pattern(conn):
    param = request.args.get("p")
    n = 0
    [n] = [len(param)]
    bar = param if n > 5 else "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def paren_assign(conn):
    param = request.args.get("p")
    n = 0
    (n) = len(param)
    bar = param if n > 5 else "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def true_division(conn):
    param = request.args.get("p")
    half = 7 / 2
    bar = param if half > 3 else "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def floor_modulo(conn):
    param = request.args.get("p")
    r = -7 % 3
    bar = param if r > 0 else "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def match_capture(conn):
    param = request.args.get("p")
    n = 0
    match len(param):
        case 0:
            pass
        case n:
            pass
    bar = param if n > 5 else "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")


def star_assign(conn):
    param = request.args.get("p")
    n = 0
    n, *rest = [len(param)]
    bar = param if n > 5 else "safe"
    # EXPECT sql-injection
    conn.execute("SELECT * FROM t WHERE x = '" + bar + "'")
