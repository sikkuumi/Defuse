# p01-py-format-template-skipped: The template itself is the parameter - `template.format(name)` - and it was never judged.
# p01: in template.format(name) only the argument is judged; the template (a parameter) is never looked at.
import os

def run(template):
    name = "docs" if 1 > 0 else "src"
    # EXPECT command-injection
    os.system(template.format(name))
