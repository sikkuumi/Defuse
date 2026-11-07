# FIXTURE: the fence around safe/quoted_literal_guards.py. Each looks like the
# safe shape and is missing the piece that made it safe.
from flask import request


def no_inner_check():
    # 'x' + __import__('os').system('id') + 'y' starts and ends with a quote.
    bar = request.args.get("x")
    if not bar.startswith('\'') or not bar.endswith('\''):
        return "no"
    # EXPECT-FLOW code-injection
    return eval(bar)


def different_quotes():
    bar = request.args.get("x")
    if not bar.startswith('\'') or not bar.endswith('"') or '\'' in bar[1:-1]:
        return "no"
    # EXPECT-FLOW code-injection
    return eval(bar)


def fence_does_not_cover_sql(cursor):
    # A quoted literal is still SQL: 'a' OR ''=''... has no inner ' only if crafted,
    # and the fence never claimed SQL.
    bar = request.args.get("x")
    if not bar.startswith('\'') or not bar.endswith('\'') or '\'' in bar[1:-1]:
        return "no"
    # EXPECT-FLOW sql-injection
    cursor.execute("SELECT * FROM t WHERE name = " + bar)


def list_read_hits_the_input():
    param = request.args.get("x")
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    # EXPECT-FLOW code-injection
    exec(lst[1])


def list_write_under_a_branch(c):
    param = request.args.get("x")
    lst = []
    lst.append('safe')
    if c:
        lst.append(param)
    lst.append('moresafe')
    # EXPECT-FLOW code-injection
    exec(lst[1])


def global_lets_exec_write(c):
    global num
    param = request.args.get("x")
    num = 86
    # EXPECT-SIGNATURE code-injection
    exec(c)
    if 7 * 42 - num > 200:
        bar = 'fixed'
    else:
        bar = param
    # EXPECT-FLOW code-injection
    exec(bar)


# Safe in fact, but only the TRACE can show it: the signature rule still sees
# exec() of a variable. These must stay a guess - never a proof - so a false
# "proven" (what the held-out run found here) fails the suite.

def list_replayed():
    # append, append, append, pop(0): lst[1] is 'moresafe'.
    param = request.args.get("x")
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    lst.pop(0)
    bar = lst[1]
    # EXPECT-SIGNATURE code-injection
    exec(bar)


def constant_condition_with_exec_in_function():
    # exec() in a FUNCTION cannot rebind num, so 7*42 - 86 > 200 is decided.
    param = request.args.get("x")
    num = 86
    if 7 * 42 - num > 200:
        bar = 'This_should_always_happen'
    else:
        bar = param
    # EXPECT-SIGNATURE code-injection
    exec(bar)
