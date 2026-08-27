# FIXTURE: properly sanitised flows, Python.
# EXPECT-NONE
import html
from django.utils.safestring import mark_safe
from flask import request


def escaped_for_html():
    return mark_safe("<div class='bio'>" + html.escape(request.args["bio"]) + "</div>")


def numeric_id(cursor):
    uid = int(request.args["id"])
    cursor.execute("SELECT * FROM users WHERE id = " + str(uid))
