# EXPECT-NONE
#
# THE FALSIFIABLE HALF of vulnerable/higher-order-escape.py.
#
# The functions in that file all take *args, so nothing in it was ever a SOURCE
# and nothing was ever going to be flow-verified - which meant its
# EXPECT-SIGNATURE assertions passed whether the higher-order rule worked or
# not. A fixture that cannot fail is decoration, and that one was, until this
# file was split out of it.
#
# Here the attacker's value really arrives, really is escaped through map(), and
# really does reach mark_safe(). Three outcomes are possible and only one is
# right:
#
#   flow-verified   a FALSE PROOF - what Django's own format_html drew out of
#                   this scanner, and the reason for the fix
#   signature-based a fair guess, but weaker than the evidence supports
#   nothing         correct: the tracer followed the value, saw map() apply
#                   `escape` to every element, and RETRACTED its own guess
#
# It reports nothing, which is the retraction machinery doing the job it was
# built for - `signaturesRetracted` in every scan summary counts these. Silence
# here is not the absence of an answer; it is the answer.
from django.utils.safestring import mark_safe
from django.utils.html import escape


def view_escaping_through_map(request):
    escaped = map(escape, request.GET.getlist("q"))
    return mark_safe("<ul>" + "".join(escaped) + "</ul>")


def view_escaping_through_a_dict_comprehension(request):
    parts = {k: escape(v) for (k, v) in request.GET.items()}
    return mark_safe("".join(parts.values()))
