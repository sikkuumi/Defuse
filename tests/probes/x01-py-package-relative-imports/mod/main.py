# x01-py-package-relative-imports: `from . import runner` and a package folder
# (shell/__init__.py) both used to resolve to nothing, so no call crossed into
# them and both injections below went unreported. Found scanning a 23-file
# Python mod: 31 local imports, 0 resolved.
import sys
from . import runner
from .shell import run_in_shell

runner.run(sys.argv[1])
run_in_shell(sys.argv[2])
