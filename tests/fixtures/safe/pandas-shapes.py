# EXPECT-NONE
#
# FOUR SHAPES FROM SCANNING PANDAS, EACH A DIFFERENT KIND OF MISTAKE.
#
# A scan of pandas (1,421 files) reported 79 findings, 65 of them critical. That
# number is wrong in an interesting way: pandas genuinely does ship an evaluator
# and a pickle reader, so the rules were pointed at the right library and still
# got most of the individual lines wrong. The four shapes below are the reasons.

import pickle

from pandas.core.computation.eval import eval


class Engine:
    def eval(self, expr, engine=None, parser=None):
        return expr

    def run(self, expr, engine, parser):
        # 1. `self` IS THE GLOBAL OBJECT IN A BROWSER AND AN INSTANCE IN PYTHON.
        #
        # Seventeen findings, all `self.eval(...)`. The code-injection rule keeps
        # an allowlist of receivers that really are evaluators - `window.eval`,
        # `globalThis.eval`, `mathjs.eval` - and `self` was on it because in a
        # web worker `self` is the global scope, so `self.eval()` is the real
        # thing. In Python `self` is the instance, and `DataFrame.eval` is a
        # public pandas API that parses a restricted expression grammar and is
        # not Python's evaluator at all.
        #
        # The allowlist was right and applying it to every language was wrong.
        # It is now scoped to the languages where those names mean what it
        # thought they meant.
        return self.eval(expr, engine=engine, parser=parser)


def evaluate(term, env, engine, parser):
    # 2. A BUILTIN THAT HAS BEEN IMPORTED OVER IS NOT THE BUILTIN.
    #
    # pandas/core/computation/ops.py does exactly this, with the import on the
    # line above the call. `eval`, `exec` and `compile` are only dangerous
    # because of what the interpreter binds those names to - and an explicit
    # `from ... import eval` rebinds them. The scanner reads the file that
    # contains the import; not checking it was reporting a name rather than a
    # function.
    return eval(term, local_dict=env, engine=engine, parser=parser)


def roundtrip(obj):
    # 3. UNPICKLING WHAT YOU JUST PICKLED IS A ROUND TRIP, NOT AN INPUT.
    #
    # Six findings, all `pickle.loads(pickle.dumps(x))` in tests. Deserialisation
    # is dangerous because the BYTES come from somewhere else; here the bytes are
    # produced two characters to the right, by this process, from a value this
    # process already holds. There is no attacker position anywhere in the
    # expression. `pickle.load(some_file)` still reports, because a file is a
    # somewhere else.
    return pickle.loads(pickle.dumps(obj))


def messages(obj, left, right, key, count):
    # 4. "VALUES" AND "AND" ARE ENGLISH WORDS.
    #
    # Four findings, every one an assertion message. The SQL detector matches
    # query FRAGMENTS as well as whole statements, because a lot of real
    # injection is `" WHERE id = " + user_id` appended to a query built
    # elsewhere - and a fragment is recognised by opening with a clause keyword.
    #
    # An f-string's literal parts are fragments in exactly that sense. The text
    # after `{obj}` is " values are different (", which opens with VALUES; the
    # text after `{left}` is " and ", which opens with AND. Both matched, and
    # neither continues into anything a database could parse. SQL's VALUES is
    # always followed by a parenthesis, and its AND is always followed by a
    # comparison - so the fragment rule now asks for the rest of the clause
    # instead of stopping at the keyword.
    msg = f"{obj} values are different ({count} %)"
    msg2 = f"{left} and {right} were approximately equal when they shouldn't have been"
    msg3 = f"{key} values must not have NaT"
    return msg, msg2, msg3
