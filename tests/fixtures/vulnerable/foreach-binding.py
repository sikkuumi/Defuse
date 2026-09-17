# FIXTURE: the same for-each gap, in Python - because it is not a Java problem.
#
# See vulnerable/foreach-binding.java for how this was found. The point of
# repeating it here is that binding a loop variable is a TRACER fact, not a
# dictionary one, so a fix that only taught Java would be an instance fix
# wearing a class fix's clothes.
from flask import request, Flask

app = Flask(__name__)


@app.route("/one")
def iterate_a_list():
    for value in request.args.getlist("q"):
        # EXPECT-FLOW xss
        return "<p>" + value + "</p>"
    return ""


@app.route("/two")
def iterate_a_variable():
    values = request.args.getlist("q")
    for value in values:
        # EXPECT-FLOW xss
        return "<p>" + value + "</p>"
    return ""
