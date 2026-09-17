# NS-1 SecureScan

A static application security testing (SAST) tool that refuses to sound more
certain than it is.

Every finding is labelled **`signature-based`** or **`flow-verified`**, and the
two mean precise, different things:

| label | claim | evidence |
|---|---|---|
| `signature-based` | "this code has the *shape* of a bug" | a pattern matched in the syntax tree |
| `flow-verified` | "attacker data actually *reaches* here" | the full source→sink path, printed hop by hop |

A `flow-verified` finding prints its own receipt: every line the value passed
through, so you can check the claim instead of trusting it — including the hops
where our knowledge runs out, which are labelled as such rather than quietly
smoothed over.

The tool also prints, on every run, a list of what it did **not** check. That is
the product. The rules are table stakes; the labelling is the difference.

<!-- derived:counts -->
**10 rules** across **8 languages** (JavaScript, TypeScript, Python, Java, PHP, Go, C, C++).
<!-- /derived -->

---

## Quick start

**Run it without installing anything:**

```bash
npx github:<your-github-user>/ns1-securescan scan ./src
```

> Not on the npm registry yet, so the install is straight from the repository —
> substitute the account it lives under. This is stated rather than a
> `npx ns1-securescan` line that does not resolve: a README whose very first
> command fails is a worse first impression than one extra clause.

That is the whole setup. The WASM grammars ship inside the package and are
resolved from `node_modules`, so there is no toolchain to install, no compiler,
and nothing to configure — two runtime dependencies and a Node 18+ runtime.

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

**Working on the engine itself:**

```bash
npm install
npm run build

node dist/src/cli.js doctor                    # self-check: grammars + queries
node dist/src/cli.js scan tests/fixtures       # scan the sample vulnerable code
npm test                                       # verify every rule fires correctly

npm run ui                                     # the browser UI on :4173
npm run install-check                          # is the published package the same program?
npm run git-install-check                      # does a clone of this repo build and behave?
npm run memory                                 # what does a scan cost per byte of source?
npm run identity                               # did a refactor move any answer?
```

`npm run identity` is the one to run before and after anything that is *meant*
to change nothing. It scans twelve fixed targets and hashes the findings, the
proof steps and the diagnostic counters underneath them, because the accuracy
figures are averages and two findings moving in opposite directions cancel out
in an average. `--record` captures the current behaviour as the baseline — only
ever from a tree whose other instruments you have just run and believed.

> **Windows / PowerShell note.** In this README and in `--help`, `<path>` and
> `<file>` are *placeholders* — replace them with a real path. Do not type the
> angle brackets: PowerShell treats `<` as a reserved redirection operator and
> will refuse with *"The '<' operator is reserved for future use."* Also paste
> one command per line, without the trailing `# comment`.
>
> ```powershell
> node dist/src/cli.js scan .\tests\fixtures
> node dist/src/cli.js ast .\tests\fixtures\vulnerable\sqli.js
> ```

Installed globally (`npm i -g github:<your-github-user>/ns1-securescan`), the command is `securescan`
(`secureScan` also works — both names are declared, because a camelCase binary
resolves on macOS and not on the Linux box your CI runs on):

```bash
securescan scan ./src
securescan scan ./src --json > findings.json
securescan scan ./src --sarif > results.sarif   # for GitHub code scanning
securescan ast ./src/app.js                    # see the syntax tree
securescan rules --explain sql-injection       # read the write-up for a rule
```

---

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

## What it does, in order

```
  your files
      │
      ▼
┌───────────────┐   file extension or #! line decides the language
│  parse/       │   tree-sitter turns text into a syntax tree (AST)
└───────────────┘
      │
      ├──────────────────────────────┐
      ▼                              ▼
┌───────────────┐            ┌────────────────┐
│  engine/      │  shapes    │  taint/        │  follows values
│  shapes.ts    │  CallSite  │  tracer.ts     │  source → sink,
│  rules/*.ts   │  Assignment│  project.ts    │  across functions
└───────────────┘            └────────────────┘  AND across files
      │                              │
      ▼                              ▼
 signature-based                flow-verified
  (a pattern)                    (a proof, with the path)
      │                              │
      └──────────────┬───────────────┘
                     ▼
        the verified one SUPERSEDES the guess
        at the same line; everything unconfirmed
        stays signature-based and stays visible
                     │
                     ▼
          terminal report  or  --json
```

### Why an AST instead of regular expressions

These three lines contain identical characters:

```js
db.query("SELECT * FROM users WHERE id = " + userId)     // a real problem
// db.query("SELECT * FROM users WHERE id = " + userId)  // a comment
log("db.query is unsafe when you write \" + userId\"")   // a string
```

Text search cannot tell them apart. A parser already has: one is a
`call_expression`, one is a `comment`, one is a `string`. Using the syntax tree
means we inherit that accuracy for free.

Run `secureScan ast <file>` on anything to see the tree for yourself.

### Why a shape layer

`db.query(...)` in JavaScript, `cursor.execute(...)` in Python,
`stmt.executeQuery(...)` in Java and `db.Query(...)` in Go are the same idea
expressed in four grammars with four different node names. `engine/shapes.ts`
holds one tree-sitter query per language that reduces all of them to a single
`CallSite` object.

The consequence: **a rule is written once and works in every language**, and
adding the next one means adding two query strings — not editing every rule.

---

## The honesty contract

`src/core/finding.ts` is the file to read first. Three mechanisms enforce the
project's central claim:

**1. The type system makes overclaiming impossible.**
`Finding` is a union of two shapes, and `FlowVerifiedFinding` *requires* a
`flowPath`. Before the tracer existed no code could build one, so the label was
unreachable by construction rather than by discipline.

The tracer activated that second constructor without softening the requirement.
`flowVerifiedFinding()` throws unless the path has at least two steps, **begins
at a source**, **ends at a sink**, and contains **no sanitiser**. The type system
stops a rule from lying; that function stops the *engine* from lying, including
a future version of it written in a hurry.

**2. Rules cannot set their own confidence.**
A rule returns a `RuleHit` — a node, a message, a reason. The engine converts it
to a `Finding`. The confidence field is not in the rule's vocabulary.

**3. Every finding must state its limitations.**
`reasoning` and `limitations` are required fields, not optional ones.
`validateRegistry()` runs before every scan and refuses to start if a rule ships
with an empty limitations string or declares partial language support without
saying what is missing. The scan aborts rather than emit a finding that cannot
explain itself.

Every report ends with **"What this scan did NOT check"** — engine limits,
partial rules, rule/language combinations that do not exist, and file types
present in the tree that were never opened.

---

## The data-flow engine

Four words carry the whole design — **source**, **propagation**, **sanitiser**,
**sink**. `src/taint/types.ts` explains each one from scratch.

The part most tools get wrong is that **soap is job-specific**. `escapeHtml(x)`
makes a value safe for a web page and does nothing whatsoever for a SQL query.
A scanner that keeps one boolean "is it clean?" silently accepts HTML escaping
in front of a database call. NS-1 tracks *which kinds* of sink a value has been
washed for, so this is correctly reported as a real vulnerability:

```js
const cleanedForHtml = escapeHtml(req.query.id);
db.query("SELECT * FROM users WHERE id = " + cleanedForHtml);   // still injectable
```

...while this one is correctly *retracted* — the signature pass flags it, the
tracer proves a sanitiser runs, and the guess is withdrawn:

```js
const id = parseInt(req.query.id, 10);
db.query("SELECT * FROM users WHERE id = " + id);               // a number cannot inject
```

Language coverage is reported separately from rule coverage, because the two are
genuinely different depths of analysis:

| | JS | TS | PY | JAVA | GO |
|---|:--:|:--:|:--:|:--:|:--:|
| signature rules | ● | ● | ● | ● | ◐ |
| **data-flow verification** | ● | ● | ● | ● | ● |

### Following a value into another function

The first tracer stopped at the call. `helper(req.query.id)` was the end of the
trace, because guessing what `helper` does would have been the exact kind of
confident wrong answer this project refuses to give. Interprocedural tracing
doesn't guess — it goes and looks. Every function defined in the file is indexed by name; when a tainted
value is passed to one, it is bound to the parameter name and the body is
analysed with the taint already in place. Return values come back out:

```js
function readName(req) { return req.query.name; }   // fetches the source
const name = readName(req);
db.query("SELECT * FROM users WHERE name = '" + name + "'");   // flow-verified
```

Three guards keep it terminating and honest: a depth limit of four calls, a
cycle guard so recursion cannot loop, and a per-call-site cache. Imports are
*not* resolved at this level — a helper in another module still ends the trace.
That is what the import graph in the next section is for.

### Following a value into another file

Applications put their database access in `db.js`, their escaping in
`util/html.py`, their command runners in `Shell.java`. Until now every one of
those was a wall. `src/taint/project.ts` builds an import graph so the tracer
can walk through it, and a finding's path can name two files:

```
handler.js:3   source       `req.query.id` is HTTP request parameters
handler.js:3   propagation  concatenated into a larger string with +
handler.js:3   propagation  passed into `runQuery()` as parameter `sqlText`
db.js:3        sink         reaches a database query via `conn.query()`
```

Imports are resolved from the syntax tree, not a text search: `require('./db')`
inside a comment is not an import. JS/TS relative specifiers (including the
TypeScript `./x.js` → `x.ts` convention), Python module paths, Java `import`
plus same-package visibility, and Go's same-directory packages.

**The rule it plays by: answer only when the answer is unambiguous.** If two
imported modules both define `sanitize`, the index says nothing and records
that it declined — scanning five real libraries, it followed 7,446 cross-file
calls and **declined 4,248** as ambiguous. Picking one at random would let the
tool print a step-by-step "proof" through a function that never runs, which is
worse than printing nothing because it looks like evidence. Both counts are in
every report.

### Prepared statements are not injection

```go
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
stmt.QueryRow(r.FormValue("id"))     // NOT a finding
```

After `Prepare`, the arguments are bound parameters — the database keeps them
away from the instruction, which is the entire point. The tracer remembers which
local names hold a statement handle. Flagging these punishes the correct fix,
which is the worst thing a SQL rule can do. `db.Prepare(dynamicSql)` is still a
sink, because a query assembled from user input is dangerous whether or not it
is prepared afterwards.

### The hardest judgement call: functions we don't model

`URLDecoder.decode(request.getHeader("x"), "UTF-8")` — is the result still
dirty? Two wrong answers were available:

- **Treat unknown functions as clean.** Safe-sounding. It produced **zero**
  verified flows across 2,766 files of OWASP's Java benchmark, every one of
  which is a known vulnerability. Useless.
- **Treat them as sanitising.** Never — assuming an unknown function fixes the
  problem is how scanners miss real bugs.

What NS-1 does instead: the value keeps its taint, and the hop is recorded as
**unmodelled**. The path shows exactly where our knowledge ran out, and the
finding's `limitations` names the function:

```
THIS PATH PASSES THROUGH 1 FUNCTION(S) WE DO NOT MODEL (`decode()`).
We assumed each one preserves the value. If any of them sanitises it,
this finding is wrong - check those hops first.
```

That is the honest version of a guess: make it, then show your work.

## Signature rules

<!-- derived:rule-matrix -->
| Rule | CWE | OWASP | JS | TS | PY | JAVA | PHP | GO | C | CPP |
|---|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| `sql-injection` | CWE-89 | A05:2025 Injection | ● | ● | ● | ● | ● | ● | ● | ● |
| `command-injection` | CWE-78 | A05:2025 Injection | ● | ● | ● | ◐ | ● | ◐ | ● | ● |
| `format-string` | CWE-134 | A05:2025 Injection | ○ | ○ | ○ | ○ | ○ | ○ | ● | ● |
| `unbounded-copy` | CWE-120 | A05:2025 Injection | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ◐ |
| `code-injection` | CWE-94 | A05:2025 Injection | ● | ● | ● | ◐ | ● | ○ | ○ | ○ |
| `xss` | CWE-79 | A05:2025 Injection | ● | ● | ◐ | ◐ | ◐ | ◐ | ○ | ○ |
| `ssrf` | CWE-918 | A01:2025 Broken Access Control | ● | ● | ● | ◐ | ● | ● | ○ | ○ |
| `unsafe-deserialization` | CWE-502 | A08:2025 Software or Data Integrity Failures | ◐ | ◐ | ● | ◐ | ● | ○ | ○ | ○ |
| `hardcoded-secret` | CWE-798 | A07:2025 Authentication Failures | ● | ● | ● | ● | ● | ● | ● | ● |
| `weak-hash` | CWE-327 | A04:2025 Cryptographic Failures | ● | ● | ● | ● | ● | ◐ | ● | ● |

● implemented  ◐ partial  ○ not implemented

10 rules across 8 languages. This table is generated from
`ALL_RULES` and `LANGUAGES` by `npm run sync:readme`, and `npm test` fails if it
drifts - the counts in it are not maintained by hand.
<!-- /derived -->

`secureScan rules --explain <id>` prints the full write-up for any rule,
including exactly what each ◐ is missing. Those notes are also printed at the
end of every scan — they are not buried in documentation.

---

## Output

**Terminal** (default): file, line:column, severity in colour, the confidence
tag, the matched source, the AST node path, a `why` paragraph and a `gap`
paragraph, followed by the confidence summary and the coverage ledger.

**`--json`**: a superset of the terminal report. The `honesty` block sits
*above* `findings` in the document so a consumer reading top to bottom meets the
caveats first. A dashboard cannot present these as confirmed vulnerabilities
without deliberately discarding the `confidence` field.

Useful flags:

```
--min-severity=high     hide low-severity noise in the terminal (kept in --json)
--fail-on=critical      CI exit code control; --fail-on=none always exits 0
--only=sql-injection    run a single rule
--exclude=tests,vendor  skip paths. A bare word matches any directory of that
                        name; * and ** work as usual (--exclude=**/*.min.js)
--no-cross-file         analyse each file alone: faster, far less memory, and
                        no finding that crosses a module boundary
--coverage-matrix       print the full rule × language table
--show-suppressed       list findings silenced by securescan:ignore comments
--sarif                 SARIF 2.1.0, for GitHub code scanning and any SARIF viewer
--compact               one line per finding
--no-config             ignore .securescan.json even if one is present
```

**`--sarif`**: real SARIF 2.1.0, typed against `@types/sarif`. The confidence
label is carried three ways so it cannot be lost in transit — a `[flow-verified]`
or `[signature-based, UNVERIFIED]` message prefix, a `properties.confidence`
field, and a `codeFlows` entry that exists **only** for verified findings. A
test fails if a `codeFlow` ever appears on an unverified one. See
`docs/examples/github-code-scanning.yml` for the workflow.

**`.securescan.json`**: project config for `exclude`, `only`, `failOn` and
`minSeverity`. Command-line flags win over the file, broken JSON exits 2 rather
than being ignored, and **a rule cannot be disabled by config** — by design, so
a repository cannot quietly switch off the check it fails. See
`docs/examples/securescan.json`.

`--exclude` never hides quietly. The report prints how many files and whole
directories it removed, because a blind spot you asked for is still a blind
spot:

```
--exclude (tests, vendor) skipped 118 file(s) and 2 whole director(ies):
tests, vendor - not scanned, not counted
```

Suppression is a comment: `// securescan:ignore sql-injection - table name is a
constant`. Suppressed findings are **counted and listed**, never erased.

---

## Testing

Three suites, because they fail at different things.

**`npm test` — 282 checks, annotation-driven.** Fixtures carry their own
expectations as comments, so there is no second list to keep in sync. Catches
regressions and honesty-contract violations. Its ceiling is that it only ever
checks what somebody already thought of.

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

---

## Measured on real code

The signature pass was validated against five real repositories — axios,
express, flask, gin and gson: **820 files, zero parse errors, ~4.5 seconds.**

The first run of that validation produced 179 findings, of which 167 were in test trees and most of
the rest were noise: the entropy heuristic was flagging `'application/x-www-form-urlencoded'`
and `'abcdefghijklmnopqrstuvwxyz'` as possible secrets, and `auth` was matching
inside `author`. Three fixes followed — a structural gate before the entropy
check, a severity downgrade (not a drop) for test paths, and a lookahead on the
`auth` pattern.

**Result: 179 → 56 findings, with 2 outside test trees.** Both survivors are
defensible: Flask's own `Markup(value)` escape hatch, and a `hashlib.sha1` whose
purpose the scanner cannot know.

That sequence — measure, fix, re-measure, write down what changed — is the
method, and the comments in `src/rules/lib/strings.ts` record it inline.

**Then we pointed it at its own source code**, which found a fourth bug. The
`sql-injection` rule's assignment branch was handed whole object literals — every
rule definition in `src/rules/` is one — and `analyzeStringExpression` merged
prose from a dozen unrelated fields into a single blob until `looksLikeSql()`
saw "select", "from" and "where" in it. NS-1 reported its own rule files as SQL
injection, three times.

The fix was a scope gate, `isStringBuildingExpression()`: before asking "does
this look like SQL?", check that the thing you are looking at is a single string
expression rather than a *container* full of unrelated strings. `npm run scan --
.\src` is now clean, and the fixture and corpus numbers are unchanged.

Scanning your own scanner is a cheap and unusually honest test. Run it after
every rule change.

### Measured on deliberately vulnerable applications

Libraries make poor taint fixtures — axios and express have no request handlers
feeding database calls, and the tracer correctly reported **zero** verified flows
across all 820 files of them. So the tracer was validated against real vulnerable
applications instead (OWASP NodeGoat, dvna, Vulnerable-Flask-App):
**56 files, 3 verified flows, 896 ms.** Each one is a textbook bug with a
complete receipt, for example:

```
Vulnerable-Flask-App/app/app.py:265   sql-injection   flow-verified
  L 255 source       `request.json` is HTTP request parameters (Flask/Django/DRF)
  L 255 propagation  stored in `content`
  L 259 propagation  read out of a tainted value as `content['search']`
  L 259 propagation  stored in `search_term`
  L 261 propagation  formatted into a larger string with %
  L 261 propagation  stored in `str_query`
  L 265 sink         reaches a database query via `db.engine.execute()`
```

Seven hops across ten lines. The 23 other findings in those repos stayed
`signature-based`, and the signature-pass corpus count was unchanged at 56 — the taint
engine added confidence without changing what the signature pass reports.

### Measured against OWASP Benchmark (ground truth)

BenchmarkJava is 2,740 Java test cases, each labelled by OWASP as a real
vulnerability or a deliberate decoy. It is the closest thing this field has to
an exam with an answer key, so here is the exam result, unedited:

<!-- derived:benchmark -->
| | cases | TP | FP | FN | TN | precision | recall |
|---|--:|--:|--:|--:|--:|--:|--:|
| **overall** | **1210** | **575** | **391** | **69** | **175** | **59.5%** | **89.3%** |

2740 files, 0 parse errors, 20.3 seconds, on engine 0.5.0 (2026-09-17).

**Precision is the weaker side.** 391 false positives against 69 false negatives - 5.7x as many - so the cost of this engine is triage time, not missed bugs.

Missed by category: xss 48, cmdi 20, sqli 1. Of the 391 false positives, **144 (37%)** carry BenchmarkJava's constant-branch decoy - the `if ((7 * 42) - num > 200)` shape that needs constant folding plus branch feasibility to see through, which the limitations list says this engine does not do. The remainder are ours.

Every number above is generated by `npm run benchmark` into
`docs/benchmark-result.json` - including the sentence naming the weaker side,
because an interpretation kept by hand goes stale exactly like a figure does.
<!-- /derived -->

**What the misses are.** Shapes the tracer does not model: values stored in a
`Map` or array and read back, `StringBuilder` mutation, and helpers living in
another class. Every one is in the limitations list above.

**What the decoys are.** The share named in the block above is BenchmarkJava's
deliberate trap, which is always the same shape:

```java
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;
```

`294 - 86 = 208`, so the constant branch always wins and `bar` is never tainted.
Seeing that needs constant folding plus branch feasibility — precisely the
"branch conditions are not evaluated" line in our own limitations. The benchmark
tests for a capability we say we do not have, and catches us where we said it
would.

That share used to be stated here as "most". It was **37%** when finally
measured, and it had been written when the false-positive count was 49 rather
than 345 — an empirical claim that outlived the thing that changed its subject.
It is generated now, from the scorer reading every false-positive file.

These numbers are *measured*, which is the point: a scanner that will not publish
its own exam result is asking you to take its word for something it has not
checked either.

### What moved the score, and what did not

**Cross-file tracing: no change.** It left BenchmarkJava at exactly the figure it
started from. The test cases are self-contained servlets, and the shared helpers
they *do* use are referenced by fully-qualified name with no `import`, so there
was nothing for an import graph to resolve. Honest result: zero.

**Framework source bindings: the whole score.** Recall sat at **13.8%** for a
long time because the Java source list was built from raw servlet getters, and
BenchmarkJava's own cases bind their inputs through Spring and JAX-RS
annotations. Adding `@RequestParam` / `@QueryParam` and friends, plus
`declaredTypes()` so `Runtime r = Runtime.getRuntime(); r.exec(cmd)` is seen as
a shell call, took recall to **76.4%**.

Precision went the other way, **64.5% → 58.8%**, and that trade is worth stating
plainly rather than hiding: finding five and a half times as many real
vulnerabilities also surfaces more false ones. Given the choice between a
scanner that misses six real bugs in seven and one that finds three in four at
the cost of more noise you can triage, this project takes the second — and
labels every finding so you can tell which pile you are looking at.

That is also why the table above is generated rather than typed. The 13.8%
figure sat in this file for roughly twenty versions after it stopped being true,
because it was prose restating a number the program already knew.

Where it did change things — **a point-in-time A/B from when cross-file tracing
landed**, kept because the govwa row is the argument, not because these are the
current totals (for those, run the instruments):

| project | before | after | why |
|---|--:|--:|---|
| govwa (Go) | 4 flows | **1 flow** | three were `stmt.QueryRow(param)` on a *prepared* statement — false positives, now gone |
| NodeGoat | 0 followed | 25 followed | import graph resolved; still no verified flow |
| 5 libraries | 56 findings | 56 findings | no regression, 7,446 calls followed, 4,248 declined as ambiguous |
| NS-1 itself | 0 edges | 77 edges, 75 followed | still zero findings on its own source |

The govwa row is the one that matters. Going from four findings to one is an
*improvement*: the three that disappeared were the tool telling a developer that
their correctly parameterised query was a critical vulnerability.

---

## What the engine does NOT do

Stated here, in the code, and in every scan report:

- **Only files inside the scan.** A call into `node_modules`, a JAR or a
  vendored package ends the trace. Call chains deeper than four also stop.
- **Ambiguous names are not guessed.** When several files in scope define the
  same function name, the trace stops and the decline is counted.
- **Re-exports, dynamic imports and build-tool path aliases** (tsconfig `paths`,
  webpack) are not resolved, and whether a function is really *exported* is not
  checked.
- **Object interiors are invisible.** `obj.field = dirty` and
  `sb.append(dirty)` are not tracked — we follow variables, not object state.
- **Sources are recognised by shape.** A `req.query`-looking expression is
  assumed to be a real HTTP request; we do not prove it with type inference.
- **Branch conditions are not evaluated.** A value cleaned only inside
  `if (isAdmin)` is treated as cleaned afterwards — and, in the other
  direction, `if (alwaysTrue) x = "safe"; else x = dirty;` is treated as dirty.
- **Loops are not iterated to a fixpoint.**
- **Unmodelled functions are assumed to preserve taint**, and named on the
  finding when they do.
- **No framework awareness.** Express routing and Django views are just code.
- **No template files.** `.html`, `.jinja`, `.jsp` are never parsed, so
  `{{ x|safe }}` inside a template is invisible.
- **No taint through a database or a queue.** Stored (second-order) XSS, where
  a value is written on one request and printed on a later one, is not followed.

### How much memory a scan costs

A tree-sitter syntax tree lives in a WebAssembly heap that JavaScript's garbage
collector cannot see into, so it is never reclaimed on its own — the only thing
that frees one is an explicit `delete()`. For most of this project's life,
nothing called it, and a scan therefore cost about **sixty times** the source it
was reading. Past roughly 44 MB of source on an 8 GB machine the operating
system killed the process, which is a worse failure than a slow answer because
it produces no answer at all.

The engine now holds as many trees as a stated budget allows and parses a file
again if something needs it after its tree was dropped. Measured on one 54 MB
corpus — **same binary, only the budget changed**:

| tree budget | peak RSS | time | marginal cost | findings |
|---|--:|--:|--:|--:|
| hold everything (old behaviour) | 1474 MB | 175.6s | 25.7× | 8544 |
| 256 MB | 716 MB | 188.5s | 7.25× | 8544 |

Half the memory for 7% more time, and the findings are byte-identical. On an
8 GB machine that moves the practical ceiling from about 312 MB of source to
about **1.1 GB**, and changes the failure mode from *killed* to *slower*. A scan
that spilled says so: `diagnostics.treeMemory.reparses` above zero means files
were parsed more than once, and `NS1_TREE_BUDGET_MB` trades memory back for
speed.

Two separate things were wrong, and both are worth naming because the second is
the more expensive kind of bug:

1. The index held a live syntax node for every function in the project, which
   pinned every tree whether or not anything ever traced into it. Recording two
   byte offsets and a node type instead took Django's marginal cost from 59.4×
   to 22.9× **with no eviction at all**.
2. The code said the trees were held *"because cross-file tracing needs to
   resolve into any file at any time"*, and pointed at `--no-cross-file` as the
   escape hatch. Measured, cross-file OFF used 535.8 MB against 528.8 MB with it
   ON. The ceiling was real; the explanation for it was invented, and an invented
   explanation is worse than none — it stops anybody looking.

The identity of every finding under eviction is enforced by `npm test`, which
scans the fixture tree twice, once with a budget small enough to evict almost
every tree, and fails if the two finding lists differ — and separately fails if
that budget turns out not to have evicted anything, because a test that guards
an empty room passes for the wrong reason.

## Roadmap

This used to be a table of phase numbers. They described the order *we* built
things, which stopped matching anything once the work happened out of order —
the banner read `PHASE 3C` while the version read `phase2`. A tool that sells
honest labelling cannot mislabel itself, so the roadmap now lists capabilities,
and `npm test` fails if a phase number reappears anywhere a user can read it.

**Built and verified**

| Capability | Evidence |
|---|---|
| Tree-sitter parsing, shape layer — see the coverage matrix above for rules × languages | 99 fixtures, zero parse errors |
| SARIF 2.1.0 export (`--sarif`) carrying the confidence label three ways | a test fails if a `codeFlow` appears on an unverified finding |
| `.securescan.json` config, `--exclude` / `--only` / `--fail-on` / `--min-severity` | a rule cannot be disabled by config, by design |
| Honesty labelling enforced by the type system | `flowVerifiedFinding()` throws on an incomplete path |
| Taint tracing within a function, kind-scoped sanitisers | verified flows asserted per-line by `EXPECT-FLOW` annotations |
| Call graph within a file, unmodelled hops named on the finding | measured against OWASP Benchmark |
| Cross-file tracing through a resolved import graph | 4 findings with paths spanning 2+ files |
| Prepared-statement awareness, `--exclude` | govwa: 4 findings → 1, three were correct code |
| Browser UI running the same compiled engine in a Web Worker | CLI and browser produce identical findings, checked by a test |
| Analysis deck: file tree, code with four gutter states, linked flow hops | `verifiedClean` and `fileRoles` back every mark |
| Three gauges that are never merged, each showing its arithmetic | a test fails if a combined risk score is ever exported |
| Blind spots counted per scan, not disclaimed in general | `traceLimits` from the tracer's own truncation points |

**Not built**

| Next | Why it matters |
|---|---|
| Remediation: context-aware fixes and before/after diffs | a finding you can act on beats a finding you can read |
| Language expansion — 31 more grammars already ship in `tree-sitter-wasms` | the parser layer already supports them; the dictionaries do not |
| Framework awareness (Express, Django, Spring) | today a value that only becomes attacker-controlled through a framework binding is not seen as a source |

---

## Project layout

```
src/
  core/finding.ts      the honesty contract — read this first
  core/coverage.ts     the "what we did not check" ledger
  parse/languages.ts   language registry (add a language here)
  parse/parser.ts      tree-sitter setup + what an AST is
  parse/astDump.ts     the human-readable tree printer
  engine/shapes.ts     tree-sitter queries → CallSite / Assignment
  taint/types.ts       source / propagation / sanitiser / sink, explained
  taint/dictionaries.ts  pure data: what is a source in Express, Flask, ...
  taint/tracer.ts      follows values through one function, builds the path
  engine/scan.ts       the pipeline, top to bottom
  engine/walk.ts       file discovery
  rules/contract.ts    the interface every rule implements
  rules/lib/strings.ts string-building analysis shared by all injection rules
  rules/*.ts           one file per vulnerability, each opening with an explanation
  report/human.ts      terminal output
  report/json.ts       machine-readable output
  cli.ts               argument parsing and commands
tests/
  fixtures/vulnerable/ deliberately broken code, one file per rule per language
  fixtures/safe/       the correct version of each — must produce zero findings
  run-tests.ts         the annotation-driven runner
docs/GLOSSARY.md       every security term used in this repo, in plain language
```

Two runtime dependencies: `web-tree-sitter` and `tree-sitter-wasms`. No CLI
framework, no colour library — both are short enough to read in full
(`src/cli.ts`, `src/report/colors.ts`).

---

## Licence

**AGPL-3.0-only.** The full text is in [LICENSE](LICENSE).

In plain language, because a licence nobody understands protects nobody:

- **Scanning your own code puts no obligation on you at all.** Running this tool
  over a closed-source, proprietary or commercial repository is the intended use
  and changes nothing about the code being scanned. The licence covers *this
  program*, not what you point it at.
- **Running it unmodified inside your company is free and unencumbered.**
- The obligation attaches in one case: if you **modify** it and let other people
  use your modified version **over a network**, section 13 says you must offer
  those users its source.

That last clause is the reason it is AGPL rather than GPL. `npm run ui` serves a
browser shell that runs the same compiled engine; under a permissive licence
somebody could host exactly that, change it, and never publish a line.

If those terms do not work for you — and for some companies they genuinely do
not — the copyright is held in one place and a commercial licence can be
discussed.

The licence is declared once, in `src/core/licence.ts`, and `npm test` fails if
this file, `package.json` or `LICENSE` disagrees with it. Four copies of a legal
fact is four chances to tell somebody something untrue, and this repository has
a documented history of exactly that: the README claimed 112 checks while 207
ran, and quoted a 13.8% recall figure for about twenty versions after it stopped
being true. A wrong check count embarrasses the author; a wrong licence misleads
whoever relied on it.
