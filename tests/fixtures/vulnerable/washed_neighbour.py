# FIXTURE: a washed value beside an unwashed one in one f-string - see
# vulnerable/washed-neighbour.php.
import os
import shlex

from flask import request


def log_access(cursor):
    a = int(request.args.get("a"))
    note = request.args.get("note")
    # EXPECT-FLOW sql-injection
    cursor.execute(f"INSERT INTO log VALUES ({a}, '{note}')")


# A list literal had the same habit - see washed-neighbour.js.
def list_both():
    args = [shlex.quote(request.args.get("a")), request.args.get("b")]
    # EXPECT-FLOW command-injection
    os.system("ls " + " ".join(args))
