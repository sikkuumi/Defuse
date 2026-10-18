# FIXTURE: credential-shaped NAMES holding values that are not credentials.
# EXPECT-NONE
#
# From Django's own code, where each was reported as a HIGH hardcoded secret:
# a prefix the code checks keys FOR, the place a token is read FROM, an SQL
# statement with the password as a placeholder, and the name of a session key.
# tests/fixtures/vulnerable/secret-near-misses.py holds the fences.

SECRET_KEY_INSECURE_PREFIX = "django-insecure-"
API_TOKEN_SUFFIX = "-tok"
token_source = "POST"

set_password = 'ALTER USER %(user)s IDENTIFIED BY "%(password)s"'
reset_password = "UPDATE auth_user SET password = %s WHERE id = %s"

INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"
session_token = "remember_session_key"
