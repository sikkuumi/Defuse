# Testing and the instruments

The install checks, the identity check, and the three test suites in full. Back to the [README](../README.md).

## Install checks

Two instruments prove this rather than assuming it, because installing from a
registry and installing from a repository fail in different ways:

- **`npm run install-check`** packs the tarball and installs it. Catches a file
  missing from `files`, a `bin` path that does not survive compilation, grammars
  that resolve relative to the repo instead of `node_modules`.
- **`npm run git-install-check`** commits the tree to a throwaway repository and
  installs *that*, which runs `prepare` and compiles on the spot. Catches a
  `.gitignore` that excludes something the build needs, or a build that only
  works on the author's machine — the failure modes `npm pack` cannot see,
  because `npm pack` ships something already built.

Both scan a multi-language sample through the installed binary and through the
local build, and **fail unless the findings are identical** — same rules, same
lines, same confidence labels. A packaged scanner that reports differently from
the developer's copy is worse than one that fails to start, because it fails
quietly.

---

## Identity check

`npm run identity` is the one to run before and after anything that is *meant*
to change nothing. It scans twelve fixed targets and hashes the findings, the
proof steps and the diagnostic counters underneath them, because the accuracy
figures are averages and two findings moving in opposite directions cancel out
in an average. `--record` captures the current behaviour as the baseline — only
ever from a tree whose other instruments you have just run and believed.

---

## Test suites


That number is itself one of the checks. It had been wrong — this line said 112
while the suite ran 198 — which made it the fifth place in this project where a
figure went stale because it was written down instead of derived. The last check
in the run now reads this sentence and fails if it disagrees with the count.

**`npm run metamorphic` — 175 generated programs.** This one goes the other way.
Rather than hunting for code whose answer is known, it *generates* code whose
answer is known **by construction**:

```
source -> N propagation steps -> sink,  with a guard that is
          absent / matching / wrong-kind / universal
```

Four relations follow from the engine's own contract: no guard must be
flow-verified; a matching guard must be **retracted into `verifiedClean`**, not
merely silent (silence is also what a missing sink looks like); a *wrong-kind*
guard must still be flow-verified, because an HTML escaper does not make a value
safe for SQL; and a chain past the documented depth cap must not be verified.

It earned its keep on the first run. The four guard relations came back 42/42,
and the depth relation came back **4/7** — with depths 2, 3 and 4 failing while
1 and 5+ passed. The real interprocedural reach was **one level, not four**: the
descend cache was keyed by call site alone, so the top-level walk evaluated
`return s2(x)` inside `s1` with `x` unbound, cached `null` against that node, and
every later descent with a *tainted* `x` was handed the stale answer. The
outermost call is never poisoned that way, which is why it looked convincingly
like a depth limit doing its job. Keying the cache by taint shape fixed it, and
the capability text claiming four levels became true instead of needing a
correction.

**Hand-written adversarial fixtures.** Neither suite above finds a *design*
flaw. A person noticing that an escaped f-string was "passing" only because no
sink existed for the escaping to be credited against — that does not come from
scale.



```bash
npm test
```

The fixtures carry their own expectations as comments, so there is no separate
list of expected results to drift out of sync:

```js
// EXPECT sql-injection
return db.query("SELECT * FROM users WHERE id = " + userId);
```

`tests/fixtures/safe/` contains the *correct* version of every vulnerable
pattern — parameterised queries, `textContent`, `os.environ`, SHA-256, argument
lists instead of shell strings. **A finding in a safe file is a test failure**,
exactly like a missed detection. A scanner that flags correct code teaches people
to ignore it.

Reading the output:

| symbol | meaning |
|---|---|
| `✓ detected` | expected finding, present |
| `✗ MISSED` | expected finding, absent — the rule is broken |
| `✗ FALSE POSITIVE` | a safe file produced a finding — the rule is too eager |
| `! unexpected` | an extra, unannotated finding in a vulnerable file (reported, not a failure) |

The suite also asserts the honesty contract directly: no finding may be labelled
anything other than `signature-based`, and every finding must carry reasoning
and limitations.
