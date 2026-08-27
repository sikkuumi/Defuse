# A traced path whose middle hop goes through a function we have never heard of.
# The taint is carried (treating unknowns as clean produced zero verified flows
# across 2,766 Java files), but "no sanitiser on the path" is then an ASSUMPTION,
# not an observation - so the finding has to name it as a field, not only say it
# in prose that a --json consumer will never read.
import sqlite3
from vendor.mystery import launder      # deliberately outside the scan


def through_unknown(request, conn):
    raw = request.args.get("id")
    value = launder(raw)
    # EXPECT-FLOW sql-injection
    return conn.execute("SELECT * FROM t WHERE id = " + value)
