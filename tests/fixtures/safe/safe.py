# FIXTURE: the SAFE versions, Python.
# EXPECT-NONE
import hashlib
import os
import subprocess


def get_user(cursor, user_id):
    return cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


DB_PASSWORD = os.environ["DB_PASSWORD"]


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def list_dir(directory):
    return subprocess.run(["ls", "-la", directory], check=True)
