# FIXTURE: broken hash algorithms, Python.
import hashlib

def hash_password(password):
    # EXPECT weak-hash
    return hashlib.md5(password.encode()).hexdigest()

def fingerprint(data):
    # EXPECT weak-hash
    return hashlib.sha1(data).hexdigest()
