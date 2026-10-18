# FIXTURE: Django responses that put request data somewhere that is NOT an
# HTML page, or that read a request.META key the server sets itself.
# EXPECT-NONE
#
# Both shapes came from scanning Django (tests/test_client_regress/views.py and
# tests/csrf_tests/views.py), where each was reported flow-verified: the one
# label that is supposed to mean "proven". A browser does not run text/plain or
# JSON as a page, and request.META["CSRF_COOKIE"] is written by Django's CSRF
# middleware after it has checked the cookie is letters and digits only.
import json

from django.http import HttpResponse


def echo_plain(request):
    return HttpResponse(request.body, content_type="text/plain")


def echo_plain_with_charset(request, charset):
    return HttpResponse(
        request.body, status=200, content_type="text/plain; charset=%s" % charset
    )


def echo_json(request):
    return HttpResponse(json.dumps({"q": request.GET["q"]}), content_type="application/json")


def echo_csv(request):
    return HttpResponse(request.GET["rows"], content_type="text/csv")


def csrf_token(request):
    return HttpResponse(request.META["CSRF_COOKIE"])


def csrf_token_get(request):
    return HttpResponse(request.META.get("CSRF_COOKIE", ""))


def _secret(request):
    return request.META["CSRF_COOKIE"]


def csrf_token_through_helper(request):
    return HttpResponse(_secret(request))


def markup_shaped_text(request):
    # Looks like HTML, but the response says text/plain: shown, never parsed.
    return HttpResponse("<b>%s</b>" % request.GET["q"], content_type="text/plain")
