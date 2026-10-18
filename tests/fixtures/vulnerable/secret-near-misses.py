# FIXTURE: hardcoded credentials that sit next to the shapes
# tests/fixtures/safe/secret-shaped-names.py lets through. Each must report.

# A secret key's VALUE - the prefix is only excused under a name saying prefix.
# EXPECT hardcoded-secret
SECRET_KEY = "django-insecure-8f2k!x9q@zr4m#1p"

# Not every name ending is an excuse: `value` is not `source`.
# EXPECT hardcoded-secret
token_value = "POST-abcd"

# Snake_case, but no word in it names a key slot ("pass" is not "password").
# EXPECT hardcoded-secret
DB_PASSWORD = "admin_pass"

# A key-slot word, but digits too - generated values carry them.
# EXPECT hardcoded-secret
auth_token = "orange_session_7731"

# A passphrase has spaces and is still a secret.
# EXPECT hardcoded-secret
password = "correct horse battery staple"

# The word "select" does not make it a statement.
# EXPECT hardcoded-secret
password2 = "Select1234!"

# A brace in a Spring-style password is an algorithm id, not a template.
# EXPECT hardcoded-secret
admin_password = "{noop}hunter22"
