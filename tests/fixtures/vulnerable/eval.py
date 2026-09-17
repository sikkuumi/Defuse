from flask import request

def calc():
    # EXPECT-FLOW code-injection
    return eval(request.args["expr"])

def run():
    # EXPECT-FLOW code-injection
    exec(request.form["code"])

def compiled():
    # EXPECT-FLOW code-injection
    return compile(request.args["src"], "<s>", "exec")

def safe():
    return eval("1 + 1")                        # SAFE: constant
