# FIXTURE: Python's own marker for a hash that is not used for security.
#
# Since Python 3.9, hashlib constructors take `usedforsecurity=False`: the
# programmer stating, in the call, that the digest is a cache key, an ETag or a
# checksum. Django passes it on eight of its twelve MD5/SHA-1 calls. The rule
# cannot see purpose - this is the one place the code says it out loud - so the
# guess is withdrawn, with a receipt naming what it relied on.
import hashlib
from hashlib import md5


def cache_key(url):
    # EXPECT-CLEAN weak-hash
    return md5(url.encode(), usedforsecurity=False).hexdigest()


def etag(body):
    # EXPECT-CLEAN weak-hash
    return hashlib.sha1(body, usedforsecurity=False).hexdigest()


def by_name(data):
    # EXPECT-CLEAN weak-hash
    return hashlib.new("md5", data, usedforsecurity=False).hexdigest()


# ---- fences: each must stay reported ----

def says_it_is_for_security(password):
    # EXPECT weak-hash
    return hashlib.md5(password.encode(), usedforsecurity=True).hexdigest()


def flag_from_a_variable(data, flag):
    # Not a literal: the value at run time is unknown.
    # EXPECT weak-hash
    return hashlib.md5(data, usedforsecurity=flag).hexdigest()


def flag_only_in_a_comment(data):
    # EXPECT weak-hash
    return hashlib.md5(data).hexdigest()  # usedforsecurity=False


def flag_in_a_string(data):
    # EXPECT weak-hash
    return hashlib.md5(b"usedforsecurity=False" + data).hexdigest()
