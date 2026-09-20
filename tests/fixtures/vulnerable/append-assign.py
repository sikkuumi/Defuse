# `+=` EXTENDS A VALUE. FOR A LONG TIME IT REPLACED IT.
#
# See append-assign.js for the full story. Python is one of the seven languages
# that lost the value, and it spells the compound assignment as its own node
# type - augmented_assignment - where Java and Go reuse the plain assignment
# node with a different operator. The fix reads the operator rather than the
# node type, so all of them are covered by one line; these fixtures are what
# says so out loud.
import os
import sys


def trailing_constant():
    cmd = "ls "
    cmd += sys.argv[1]
    cmd += " -l"
    # EXPECT-FLOW command-injection
    os.system(cmd)


def leading_constant():
    cmd = "grep "
    cmd += "-F "
    cmd += sys.argv[1]
    # EXPECT-FLOW command-injection
    os.system(cmd)


# The over-fix guard. A real overwrite must still clear the value. Reported
# here means clean assignment stopped working, which would be far worse than
# the bug this fixture exists for.
def real_reassignment_still_clears():
    cmd = "ls "
    cmd += sys.argv[1]
    cmd = "ls -l"
    os.system(cmd)
