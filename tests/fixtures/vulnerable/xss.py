# FIXTURE: Cross-site scripting, Python (Django/Flask escape hatches).
from django.utils.safestring import mark_safe

def render_bio(user_input):
    # EXPECT xss
    return mark_safe("<div class='bio'>" + user_input + "</div>")
