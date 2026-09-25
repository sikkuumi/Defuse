# BUILD THE COMMAND ON ONE LINE, RUN IT ON THE NEXT - AND NOTHING WAS REPORTED.
#
# The command-injection signature rule analysed the shell call's own argument
# and nothing else. A bare variable there was skipped on purpose - "you passed
# a variable to os.system" tells nobody anything - but the rule never asked the
# obvious follow-up: where was that variable built?
#
#     os.system("ls " + name)      reported
#     cmd = "ls " + name
#     os.system(cmd)               silent
#
# Same code, same risk, one line break apart. It was found while diagnosing C,
# which turned out to be the language where this is TOTAL rather than partial
# (see build-then-run.c) - and only because the C gap was checked against the
# other languages before being called a C problem.
#
# `name` is a plain parameter, not a recognised source, so only the signature
# pass can speak. That is deliberate: this file is about the shape, not a flow.
import os
import subprocess


def concat_then_run(name):
    cmd = "ls " + name
    # EXPECT-SIGNATURE command-injection
    os.system(cmd)


def fstring_then_run(name):
    cmd = f"ls -l {name}"
    # EXPECT-SIGNATURE command-injection
    os.popen(cmd)


def extended_then_run(term):
    cmd = "grep -r "
    cmd += term
    # EXPECT-SIGNATURE command-injection
    os.system(cmd)


def shell_true(host):
    cmd = "ping -c 1 " + host
    # EXPECT-SIGNATURE command-injection
    subprocess.run(cmd, shell=True)


# ---------------------------------------------------------------- FENCES

def fixed():
    cmd = "uptime"
    os.system(cmd)


def overwritten(name):
    cmd = "ls " + name
    cmd = "ls -l"
    os.system(cmd)


def given(cmd):
    os.system(cmd)


# A list, not a shell: the arguments are never parsed, so nothing to splice into.
def argument_vector(name):
    args = ["ls", "-l", name]
    subprocess.run(args)
