# EXPECT-NONE
#
# A LEXER'S TOKEN IS NOT AN AUTH TOKEN.
#
# Django's template engine (django/template/smartif.py) builds operator tokens
# for {% if %} tags, and Defuse reported both as hardcoded credentials, because
# the variable is called `token`:
#
#     token = "is not"
#     token = "not in"
#
# Every word in the value is a programming-language keyword. No credential is
# spelled that way, and the name has no other credential word in it.

def combine(first, second):
    if first == "is" and second == "not":
        token = "is not"
    elif first == "not" and second == "in":
        token = "not in"
    else:
        token = first
    return token


OPERATOR_TOKEN = "=="
