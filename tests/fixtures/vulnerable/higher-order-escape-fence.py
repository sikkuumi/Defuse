# FIXTURE: the fence around safe/higher-order-escape.py.
#
# That change teaches the tracer that a sanitiser applied through map() or a
# comprehension still sanitises. The risk is the usual one for a retraction
# rule: it silences, and a silencing rule that fires too widely is invisible.
#
# So the shapes it must NOT touch are written down. In every one of these the
# value reaches mark_safe() with nothing having escaped it.
from django.utils.safestring import mark_safe
from django.utils.html import escape


def map_of_something_else(request):
    # `str` is not an escaper. Mapping it changes the type and nothing else.
    values = map(str, request.GET.getlist("q"))
    # EXPECT xss
    return mark_safe("".join(values))


def comprehension_without_an_escaper(request):
    # The element expression is the bare item.
    values = [item for item in request.GET.getlist("q")]
    # EXPECT xss
    return mark_safe("".join(values))


def comprehension_with_an_unknown_call(request):
    # `transform` is not in any sanitiser list, so it proves nothing.
    values = [transform(item) for item in request.GET.getlist("q")]
    # EXPECT xss
    return mark_safe("".join(values))


def escaper_covers_a_different_value(request):
    # The Jenkins lesson again: one value escaped, its neighbour not.
    safe_parts = map(escape, request.GET.getlist("a"))
    raw = request.GET.get("b")
    # EXPECT xss
    return mark_safe("".join(safe_parts) + raw)


def transform(x):
    return x
