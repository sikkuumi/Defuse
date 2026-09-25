# WHEN THE TRACER STOPS FOLLOWING A CALL, THE VALUE IS NOT CLEAN.
#
# The tracer follows a value into functions it can read, with two safety stops:
# a call chain deeper than four, and a call to a function it is already inside.
# Stopping is right - the second one is what keeps recursion from looping. What
# it did AT the stop was wrong: it returned "no taint", which is the answer
# "this value is clean", and nothing in the report said a flow had been cut.
#
# The comment above those two lines said stops are "recorded as misses, never
# as invented answers". Clean IS an invented answer, and the dangerous one.
#
# It was found through BenchmarkJava, where all 38 missed vulnerabilities had one
# shape: a helper named doSomething() calling thing.doSomething() on a different
# object. Calls are resolved by name, so the tracer took that for a call to
# itself, stopped, and declared the value clean. But the shape is not a Java
# quirk - it is DELEGATION, and it is everywhere:
#
#     def run(self, data):
#         return self.engine.run(data)
#
# The fix routes both stops to the branch the tracer already has for a function
# it cannot read: keep the value, and write into the path where the trace
# stopped and why, so the assumption is visible rather than silent.


import os
import shlex
import sys


# ---------------------------------------------------------------- DELEGATION

class Wrapper:
    def run(self, data):
        return self.engine.run(data)


def delegation():
    w = Wrapper()
    # EXPECT-FLOW command-injection
    os.system(w.run(sys.argv[1]))


# ---------------------------------------------------------------- DEPTH

def h1(x): return h2(x)
def h2(x): return h3(x)
def h3(x): return h4(x)
def h4(x): return h5(x)
def h5(x): return h6(x)
def h6(x): return x


def deep_chain():
    # EXPECT-FLOW command-injection
    os.system(h1(sys.argv[1]))


# ---------------------------------------------------------------- THE FENCE
#
# The same six-deep chain, with the value quoted on the FIRST hop - long before
# the stop. Carrying the value past the stop must carry its history too: the
# quote was applied, the sink is a shell, and this line is clean.
#
# The assertion is EXPECT-CLEAN, not silence, on purpose. Before the fix this was
# ALSO silent - because the value was thrown away at the stop, not because the
# quote was seen. Silence cannot tell those apart; a sanitiser receipt can.

def q1(x): return q2(shlex.quote(x))
def q2(x): return q3(x)
def q3(x): return q4(x)
def q4(x): return q5(x)
def q5(x): return q6(x)
def q6(x): return x


def deep_but_quoted():
    # EXPECT-CLEAN command-injection
    os.system(q1(sys.argv[1]))
