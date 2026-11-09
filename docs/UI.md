# The browser UI

How the browser shell runs the same engine as the CLI, and what each part of the analysis deck means. Back to the [README](../README.md).

## One engine, two shells

The browser UI does **not** reimplement the scanner. It imports the same
compiled modules the CLI does:

```
              src/core/analyze.ts          <- all the analysis, no platform
                 /            \
   src/engine/scan.ts       ui/worker.js
   walks a directory,       receives dropped files,
   reads bytes off disk     runs in a Web Worker
        (the CLI)              (the browser)
```

Getting there meant taking `node:fs`, `node:path` and `process` out of every
module on the analysis path - the last one was `node:path` inside the import
resolver, replaced by `src/core/paths.ts`. Grammar loading is the *only*
remaining difference between the platforms, and it is one function:

```ts
configureParsing({ loadGrammar: (g) => `/grammars/tree-sitter-${g}.wasm` });   // browser
configureParsing({ loadGrammar: (g) => join(GRAMMAR_DIR, ...) });             // Node
```

**This is checked, not asserted.** `npm test` refuses to pass if any module in
the browser bundle imports Node, and the same three-file sample produces
byte-identical findings in both:

| | CLI | browser |
|---|---|---|
| `db.js:4` sql-injection | flow-verified | flow-verified |
| `report.py:7` sql-injection | flow-verified | flow-verified |
| `report.py:12` command-injection | flow-verified | flow-verified |
| `report.py:15` hardcoded-secret | signature-based | signature-based |
| sanitised flows retracted | 2 | 2 |

Nothing is uploaded: the parser, the rules and the taint tracer all run inside
the tab. `npm run ui` compiles, copies the engine and the WASM grammars into
`ui/`, and serves it on :4173. There is no bundler and no new dependency - the
build step is one file rewrite, because browsers cannot resolve the bare
specifier `web-tree-sitter` and import maps do not reach inside module workers.

## Three gauges, never merged

Most scanners show one risk bar. This project's own `finding.ts` says why that
is a lie, and it said so before there were any gauges:

> Severity = "how bad is this if it turns out to be real?" Deliberately separate
> from confidence, which is "how sure are we it's real?" **Conflating those two
> numbers is the single most common lie in SAST tooling: a tool shows one "risk"
> bar and you cannot tell whether it means "probably harmless but catastrophic
> if not" or "definitely real but minor".**

So the dial is split along the line the engine already draws:

| gauge | scale | what moves it |
|---|---|---|
| **Verified exposure** | 0–500 | severity weight of findings whose path to the sink was *traced*. Every point is backed by a printed receipt. |
| **Unverified surface** | 0–500 | the same weights over pattern-only matches. Same scale on purpose, so you can see the shape of what is proven against the shape of what is suspected. |
| **Analysis coverage** | 0–100% | how much of the analysis actually completed. Not a security score — it is how much weight the other two can carry. |

They are never added together, and `npm test` fails if anyone tries: the suite
greps `score.ts` for an exported `overall*` / `combined*` / `*risk*` and fails on
a match. A structural rule that lives only in a comment is a rule until the first
hurried afternoon.

**A half circle, and a composition strip.** The dials started as a 260° sweep,
which looked untidy for a reason worth writing down: measured across the corpus,
the two severity readings occupy **0%–24%** of their scale, so a stub arc in the
corner is the *normal* case. It read as broken rather than as low. A semicircle
puts the number in a natural well, and printing the two ends of the scale turns
"a tiny arc" into "near the bottom of 500" — which is the fact.

The bigger fix is underneath: a strip showing what the total is **made of**.

```
MADE OF
▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
■ 19 critical   ■ 13 high   ■ 5 medium
```

A needle throws that away, and on real code the needle is a stub — so it throws
away nearly everything. `75` cannot tell you whether it is three criticals or
twenty-five lows, and those are different afternoons. The strip is engine data
(`segments` on each reading), and a test fails if it does not sum to the dial it
sits under.

**Every reading shows its arithmetic.** `3 critical × 25 = 75`. The severity
weights are a judgement, not a measurement, and the header of `score.ts` says so
in those words — what makes them usable is that they are fixed, published, and
applied identically to both severity dials, so the absolute number is arbitrary
but every *comparison* made with it is real. A score you cannot recompute by hand
is a vibe with a decimal point on it.

**Calibration.** Measured across the corpus, the verified dial stays at zero for
ordinary libraries and only moves for code that really does carry attacker data
into a sink:

| target | verified | unverified | coverage |
|---|---|---|---|
| axios | 0 | 86 | 94% |
| express | 0 | 18 | 96% |
| flask | 0 | 121 | 96% |
| NodeGoat | 0 | 88 | 96% |
| dvna | **50** | 30 | 87% |
| Vulnerable-Flask-App | **25** | 213 | 94% |

A dial past 500 is **pinned and says so** (`pinned — real total 2360`), because a
needle that quietly stops counting is a lie by omission.

### Where this scan stopped early

Beside the gauges is a row of blind spots — and these are counted, not
disclaimed. "Call chains deeper than four functions are not followed" was always
in the capability block; now the tracer counts how many times it actually
happened *in your code*:

```
WHERE THIS SCAN STOPPED EARLY
  38 call chains cut at the depth limit
   3 hops through functions we do not model
   1 cross-file call declined as ambiguous
```

A comment in `tracer.ts` used to claim these were "recorded as misses". They were
not — they returned `null` and vanished. Now the claim is true.

**That last sentence was only half true, and is left here rather than deleted.**
The stops were now *counted*, but at the stop the tracer still answered "no
taint" — which is the answer "this value is clean". All 38 vulnerabilities
Defuse missed on BenchmarkJava came from that one answer: a helper named
`doSomething()` calling `thing.doSomething()` on a different object. Calls are
resolved by name, so the tracer took it for recursion, stopped, and declared the
value clean. A stop now carries the value on as a named assumption instead
(`stopped-trace.py`, `SameNameDelegate.java`), and recall on BenchmarkJava went
from 94.1% to 100% with no new false positives.

## Readable and operable

The deck was audited against a UI/UX rubric and measured rather than eyeballed.
Four things it found, none of them visible by looking:

**The most important word on the page failed contrast.** `--crimson #e6274a`
measures **3.16:1** against the panel. That clears the 3.0 bar for a *graphical*
element and misses the 4.5 bar for *text* — and it was the colour of the word
`CRITICAL`. It now does graphics only (arcs, rules, gutter marks); text uses
`--crimson-ink` at 4.62:1, same hue, only lightness lifted. `--faint` was worse
at **2.72:1**, and `--brand` at **2.34:1** missed even the large-text bar.

**Tab did nothing.** The file tree, the finding rows and every flow hop were
`<div>`s with click handlers — no `tabindex`, no key handling, and not one
`:focus-visible` rule in the stylesheet. For a tool whose whole value is letting
someone *walk a data-flow path*, that is not a rough edge. They are real
`<button>`s now, so keyboard operation, focus handling and the correct
screen-reader role arrive for free and cannot be forgotten. Arrow keys walk the
tree, and a live region announces the file and line you land on after a hop.

**The tree badges depended on hue alone.** Red `1`, amber `1` and green `2`
rendered as identical numerals. They now carry the same glyphs as the gutter
(`●` `◆` `✓`) plus a screen-reader sentence — the finding/on-path/clean
distinction is the whole point of the tree, so it has to survive without colour.

**Small print and small targets.** 22 selectors sat under 12px, one at 9px; the
floor is 11px now. Tree rows were 22px tall against a 44px guideline — 34px on a
desktop pointer, the full 44 under `@media (pointer: coarse)`.

All four are now checks in `npm test`, which recomputes WCAG contrast from the
CSS tokens on every run:

```
Page accessibility
  ✓ every text colour clears WCAG AA on every background
  ✓ no text below the 11px floor
  ✓ deck is keyboard-operable (9 handlers, all on real buttons)
```

## The analysis deck

A findings list tells you *that* something is wrong. Triage needs *where*, and
"where" for a cross-file flow is four lines in two files. So the browser view is
three panes that stay in sync:

```
  FILES              sample/handler.js                 FINDINGS (4)
  ----               -----------------                 ------------
  db.js       1      1  const { runQuery } =           CRITICAL db.js:4 [FLOW] [2 FILES]
  handler.js  2      ...                               Attacker-controlled data from
  report.py   3      6  return runQuery("SELECT        `req.query.id` reaches a database
                     11 v el.innerHTML = escape        query
                     ...                                 |- handler.js:6   SOURCE
                     17 v return db.query("SELE          |  handler.js:6   PROPAGATION
                                                         |  handler.js:6   PROPAGATION
                                                         '- db.js:4        SINK
```

Three things in that picture are the point:

**The gutter has four states, not two.**

| mark | means | backed by |
|---|---|---|
| red `●` | a finding is reported on this line | `findings` |
| amber `◆` | attacker data passes through this line toward a finding filed in **another file** | `fileRoles[].pathLines` |
| green `✓` | the tracer reached this line and proved a sanitiser covers it | `verifiedClean` |
| nothing | read, nothing to say | — |

The amber state exists because of a bug this view exposed. Findings are filed at
the **sink**, which is right — that is where the untrusted value gets executed.
But in a cross-file flow the sink is often innocent plumbing:

```
handler.js:6   runQuery("SELECT ... " + req.query.id)    <- the line to fix
db.js:4        conn.query(sqlText)                       <- the finding is filed here
```

`db.js` gets the finding; `handler.js` gets none. And because `handler.js` also
happens to contain two sanitised lines, the first version of this tree drew it
**green** — the file you have to edit, marked safe. `fileRoles` is computed in
the engine so both shells can say the third thing: *not a finding here, but not
clean either*. A file that failed to parse gets an amber `!` and a banner over
the code, for the same reason: "we could not read this" and "this is fine" are
never drawn the same way.

**Every hop is a link.** Clicking `db.js:4` in the flow opens `db.js` at line 4.
A path that crosses files is the case a plain list handles worst, and it is
exactly the case the tracer exists to find.

**The panes never invent anything.** `ui/app.js` contains no rule, no severity
decision and no heuristic — every mark it draws came out of `analyze()`. If the
page ever starts deciding things, the browser and the terminal have begun to
disagree, and the "one engine" claim above stops being true.
