# FIXTURE (cross-file): the sink lives here; the source is in xfile_handler.py.


def run_query(cursor, sql_text):
    # EXPECT-FLOW sql-injection
    cursor.execute(sql_text)
