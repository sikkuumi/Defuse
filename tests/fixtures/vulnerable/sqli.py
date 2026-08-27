# FIXTURE: SQL injection, Python.
import sqlite3

def get_user_concat(cursor, user_id):
    # EXPECT sql-injection
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)

def get_user_fstring(cursor, name):
    # EXPECT sql-injection
    cursor.execute(f"SELECT id, email FROM users WHERE name = '{name}'")

def get_user_percent(cursor, email):
    # EXPECT sql-injection
    cursor.execute("SELECT * FROM users WHERE email = '%s'" % email)
