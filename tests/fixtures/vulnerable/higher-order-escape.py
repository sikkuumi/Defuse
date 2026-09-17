# PUNISHING THE FIX, EIGHTH TIME - AND ON THE MOST PROMINENT SAFE API IN THE
# FRAMEWORK.
#
# Scanning Django (2,974 files) produced ten flow-verified findings. Two were
# not in test code, and both trace to one function - django/utils/html.py:
#
#     def format_html(format_string, *args, **kwargs):
#         """... pass all arguments through conditional_escape(), and call
#         mark_safe() on the result. This function should be used instead of
#         str.format or % interpolation to build up small HTML fragments."""
#         args_safe = map(conditional_escape, args)
#         kwargs_safe = {k: conditional_escape(v) for (k, v) in kwargs.items()}
#         # EXPECT-SIGNATURE xss
    return mark_safe(format_string.format(*args_safe, **kwargs_safe))
#
# That is Django's RECOMMENDED way to build HTML safely, and its own docstring
# says so. This scanner called it cross-site scripting, with a proof.
#
# WHY. `mark_safe()` is an XSS escape hatch and belongs in the sink list -
# mark_safe(user_input) really is dangerous. `conditional_escape` was already in
# the sanitiser list. What the tracer could not see is that the escaping happened
# through `map()`: the sanitiser was never CALLED at a place the tracer watches,
# it was PASSED AS A VALUE to a higher-order function that applied it.
#
# A sanitiser recognised only when it appears as `escape(x)` is a sanitiser that
# stops working the moment somebody writes idiomatic Python. Both idioms appear
# in this one Django function - map() on one line and a dict comprehension on
# the next.
#
# The second finding, admin/options.py:1646, is a CALLER of format_html. One
# unmodelled shape at the bottom of a framework propagates outward into every
# place that uses it, which is what makes this class expensive rather than
# merely wrong.
#
# WHY THESE ARE EXPECT-SIGNATURE AND NOT EXPECT-NONE.
#
# `mark_safe()` IS Django's cross-site-scripting escape hatch - it exists to
# turn escaping off - so a pattern matcher that sees `mark_safe(<something
# computed>)` and says "unverified, look at this" is telling the truth. That is
# what the signature label is for.
#
# What it may not do is call it PROVEN. The escaping is real, it happened
# through map(), and a proof that walks past it is a false statement rather
# than a noisy guess. That distinction is the whole product, and it is the
# assertion this file makes.
from django.utils.html import conditional_escape, escape
from django.utils.safestring import mark_safe


def django_format_html(format_string, *args, **kwargs):
    # The exact Django shape, both halves.
    args_safe = map(conditional_escape, args)
    kwargs_safe = {k: conditional_escape(v) for (k, v) in kwargs.items()}
    # EXPECT-SIGNATURE xss
    return mark_safe(format_string.format(*args_safe, **kwargs_safe))


def list_comprehension(items):
    escaped = [escape(item) for item in items]
    # EXPECT-SIGNATURE xss
    return mark_safe("<ul>" + "".join(escaped) + "</ul>")


def generator_expression(items):
    # EXPECT-SIGNATURE xss
    return mark_safe("".join(escape(item) for item in items))


def set_comprehension(items):
    escaped = {escape(item) for item in items}
    # EXPECT-SIGNATURE xss
    return mark_safe("".join(sorted(escaped)))
