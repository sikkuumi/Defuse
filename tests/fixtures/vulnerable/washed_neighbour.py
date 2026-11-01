# FIXTURE: a washed value beside an unwashed one in one f-string - see
# vulnerable/washed-neighbour.php.
from flask import request


def log_access(cursor):
    a = int(request.args.get("a"))
    note = request.args.get("note")
    # EXPECT-FLOW sql-injection
    cursor.execute(f"INSERT INTO log VALUES ({a}, '{note}')")
