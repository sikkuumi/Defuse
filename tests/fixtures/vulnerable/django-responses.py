# FIXTURE: Django responses that DO put request data into an HTML page.
#
# The safe twin is tests/fixtures/safe/django-not-html.py. Every line here is
# a fence for a rule written there: a response that is still HTML, a content
# type that still runs script, and request.META keys that still come from the
# client must all stay reported.
from django.http import HttpResponse


def default_is_html(request):
    # HttpResponse's default content type is text/html.
    # EXPECT-FLOW xss
    return HttpResponse(request.body)


def explicit_html(request):
    # EXPECT-FLOW xss
    return HttpResponse(request.GET["q"], content_type="text/html; charset=utf-8")


def svg_runs_script(request):
    # An SVG served inline can carry <script>: not on the safe list.
    # EXPECT-FLOW xss
    return HttpResponse(request.GET["q"], content_type="image/svg+xml")


def header_from_client(request):
    # HTTP_* keys are request headers, written by the client.
    # EXPECT-FLOW xss
    return HttpResponse("X-Arg: %s" % request.META.get("HTTP_X_ARG", "none"))


def query_string_from_client(request):
    # EXPECT-FLOW xss
    return HttpResponse(request.META["QUERY_STRING"])


def unknown_meta_key(request):
    # Only keys known to be set by the server are excluded; anything else in
    # META is treated as the client's, which is the safe direction.
    # EXPECT-FLOW xss
    return HttpResponse(request.META["CSRF_COOKIE_EXTRA"])


def server_key_plus_client_value(request):
    # EXPECT-FLOW xss
    return HttpResponse(request.META["CSRF_COOKIE"] + request.GET["q"])


def meta_default_from_client(request):
    # The fallback value is the client's, even though the key is the server's.
    # EXPECT-FLOW xss
    return HttpResponse(request.META.get("CSRF_COOKIE", request.GET["q"]))


def content_type_from_client(request):
    # A content type that is not a literal is not read - and here it is the
    # attacker's to choose.
    # EXPECT-FLOW xss
    return HttpResponse(request.GET["q"], content_type=request.GET["t"])


def markup_in_a_page(request, name):
    # Built markup in an HTML response, with no traced source: a guess, kept.
    # EXPECT-SIGNATURE xss
    return HttpResponse("<b>%s</b>" % name)
