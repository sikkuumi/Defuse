# FIXTURE: a path that depends on a branch is reported, but never PROVEN.
#
# Django, contrib/admin/options.py. A tainted `msg` is assigned inside an
# `except` block; a clean literal `msg` is assigned inside an `elif` forty lines
# later; the sink is reachable only through the second:
#
#     except (LookupError, ValueError):
#         msg = _('The app "%s" could not be found.') % source_model_name   # 1601
#         self.message_user(request, msg, messages.ERROR)                   # not the sink
#     ...
#     elif "_continue" in request.POST:
#         msg = _("The {name} was added successfully.")                     # 1643, clean
#         self.message_user(request, format_html(msg, **msg_dict), ...)     # 1646, the sink
#
# The engine reported it flow-verified: seven correct-looking hops across two
# files, proving a flow that cannot run.
#
# WHY IT HAPPENED, AND WHY THE RULE BEHIND IT IS RIGHT. The tracer keeps taint
# through a clean write it cannot prove happens - "a conditional write cannot
# prove a value clean". That is deliberately cautious and it is the correct
# default: it errs toward reporting a value that might be clean rather than
# staying silent about one that might be dirty.
#
# What it may not do is hand that assumption to flowVerifiedFinding(), which
# prints "this is not a pattern guess - the data flow was followed". Nothing was
# followed there. An assumption was made.
#
# THE FIRST FIX WAS WRONG AND THE BENCHMARK SAID SO IN ABOUT A MINUTE. Dropping
# the finding took recall from 89.3% to 75.5% - 89 real vulnerabilities in
# BenchmarkJava sit behind exactly this shape, and the signature rules did not
# cover those lines. Going silent about a real bug is the one failure this
# scanner cannot detect in itself.
#
# So the finding survives, with the label it has earned: reported, path printed
# so a reader can check the branch themselves, and never called proof.
from django.utils.safestring import mark_safe


def mutually_exclusive_branches(request):
    if request.GET.get("a"):
        msg = "tainted %s" % request.GET.get("q")
        record(msg)
    elif request.GET.get("b"):
        msg = "a clean literal"
        # EXPECT-SIGNATURE xss
        return mark_safe(msg)
    return ""


def record(x):
    return x
