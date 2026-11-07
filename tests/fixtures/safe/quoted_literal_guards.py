# FIXTURE: shapes from OWASP BenchmarkPython, held out from tuning - the first
# held-out run "proved" 10 of its safe cases vulnerable. These are the three
# causes. The fence is vulnerable/quoted_literal_fence.py.
from flask import request


def quoted_literal_only():
    # Past the check, bar is one '-quoted literal with no ' inside:
    # eval can only build a str from it.
    bar = request.args.get("x")
    if not bar.startswith('\'') or not bar.endswith('\'') or '\'' in bar[1:-1]:
        return "Eval argument must be a plain string literal."
    # EXPECT-CLEAN code-injection
    return eval(bar)


def quoted_literal_and_form():
    bar = request.args.get("x")
    if bar.startswith('"') and bar.endswith('"') and '"' not in bar[1:-1]:
        # EXPECT-CLEAN code-injection
        exec(bar)
