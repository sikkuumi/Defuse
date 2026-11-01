# FIXTURE: a key handed straight to the function that uses it, in Python.
import hashlib
import hmac

import jwt


def sign(message):
    # EXPECT-SIGNATURE hardcoded-secret
    return hmac.new(b"super-secret-signing-key", message, hashlib.sha256).hexdigest()


def issue(payload):
    # EXPECT-SIGNATURE hardcoded-secret
    return jwt.encode(payload, "jwt-secret-in-the-code", algorithm="HS256")
