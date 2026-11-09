# Defuse

**Static analysis that tells you which findings it proved and which it only
guessed.**

[![licence: AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0-792cf7?style=flat-square)](LICENSE)
[![no build step](https://img.shields.io/badge/install-npx,%20no%20toolchain-16c97c?style=flat-square)](#quick-start)
[![runtime dependencies: 2](https://img.shields.io/badge/runtime%20deps-2-6f6f6f?style=flat-square)](#quick-start)

```bash
npx github:sikkuumi/Defuse scan .
```

<!--
  DELIBERATELY FEW BADGES. A badge is a hand-kept copy of a fact the program
  already knows, which is the exact failure `sync-readme.mjs` exists to stop.
  Only figures that do not drift get one; the counts and the scores below are
  generated from the registry and from the benchmark result, so they cannot go
  stale without failing the build.
-->

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

### What the distinction is actually worth

Measured, not asserted — and measured separately for each label, because one
blended precision figure would be the same averaging this tool refuses to do
inside a single finding.

<!-- derived:label-split -->
| tier | TP | FP | FN | precision | recall | FPs that are decoys |
|---|--:|--:|--:|--:|--:|--:|
| `flow-verified only` | 602 | 0 | 42 | **100.0%** | 93.5% | 0 (0%) |
| `signature-only` | 42 | 35 | 602 | **54.5%** | 6.5% | 0 (0%) |
| `combined (published)` | 644 | 35 | 0 | **94.8%** | 100.0% | 0 (0%) |

658 `flow-verified`, 1198 `signature-based` findings, on engine 0.5.0 (2026-10-28).

**The green label is worth 45.5 points.** `flow-verified` runs 100.0% against `signature-based` at 54.5%. The gap is the whole claim this tool makes; it is measured here rather than asserted.

**No false positive carries the green label here.** All 602 `flow-verified` claims on this benchmark are real vulnerabilities. That is a statement about these scored test cases, not a promise about your code: a proof means the path exists in the source, and the ways that can still be wrong are the ones in the limitations list, which a synthetic benchmark does not exercise.
<!-- /derived -->

<!-- derived:counts -->
**10 rules** across **8 languages** (JavaScript, TypeScript, Python, Java, PHP, Go, C, C++).
<!-- /derived -->

---

## Quick start

**Run it without installing anything:**

```bash
npx github:sikkuumi/Defuse scan .
```

> Installed straight from the repository rather than the npm registry, where the
> name `defuse` is already taken by an unrelated package. Stated plainly rather
> than printing an `npx defuse` line that would not resolve: a README whose very
> first command fails is a worse first impression than one extra clause.

That is the whole setup. The WASM grammars ship inside the package and are
resolved from `node_modules`, so there is no toolchain to install, no compiler,
and nothing to configure — two runtime dependencies and a Node 18+ runtime.

Two install checks prove the published package reports exactly what a local build reports - see [docs/TESTING.md](docs/TESTING.md#install-checks).

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
npm run review-reasons -- scan.json .          # why is each "to review" finding still open? (a sorting aid)
npm run scoreboard                              # every practice app with an answer key: mistakes grouped by cause
```

`npm run identity` hashes the findings of twelve fixed targets, so a refactor that is meant to change nothing can prove it - see [docs/TESTING.md](docs/TESTING.md#identity-check).

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

Installed globally (`npm i -g github:sikkuumi/Defuse`), the command is `defuse`:

```bash
defuse scan ./src
defuse scan ./src --json > findings.json
defuse scan ./src --sarif > results.sarif   # for GitHub code scanning
defuse ast ./src/app.js                    # see the syntax tree
defuse rules --explain sql-injection       # read the write-up for a rule
```

---

## Browser UI

`npm run ui` serves a browser shell on :4173. Drop a folder on it and the same
compiled engine the CLI uses runs in a Web Worker, so nothing leaves your
machine. It shows severity, confidence and coverage as three gauges that are
never merged into one score, and a three-pane deck (files, code, findings)
with every hop of a flow linked. The full tour: [docs/UI.md](docs/UI.md).

---

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

Why a syntax tree instead of regular expressions, and why one shape layer lets each rule work in every language: [docs/ENGINE.md](docs/ENGINE.md).

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

Four words carry the design: **source**, **propagation**, **sanitiser**, **sink**. Sanitisers are kind-scoped (an HTML escaper does nothing for SQL), values are followed into other functions and other files through a resolved import graph, prepared statements are recognised as the fix, and a call the engine does not model makes a trace a possibility, never a proof. The full walk-through, with examples, is in [docs/ENGINE.md](docs/ENGINE.md).

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

`defuse rules --explain <id>` prints the full write-up for any rule,
including exactly what each ◐ is missing. Those notes are also printed at the
end of every scan — they are not buried in documentation.

Defuse also checks the PHP version a project declares (Dockerfile, compose, composer.json, `.php-version`) against dated php.net facts - see [docs/ENGINE.md](docs/ENGINE.md#the-php-version-check-runtime-version).

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
--full                  the long terminal report: reasoning, limits, OWASP table
--coverage-matrix       print the full rule × language table
--show-suppressed       list findings silenced by defuse:ignore comments
--sarif                 SARIF 2.1.0, for GitHub code scanning and any SARIF viewer
--report=report.html    also write a client-readable HTML report (prints to PDF)
--compact               one line per finding
--no-config             ignore .defuse.json even if one is present
```

**`--report=report.html`**: a report for the person who owns the code rather
than the person who ran the scan - one HTML file that loads nothing from the web,
runs no script, and prints to PDF from any browser. In order: what was **proven**,
each with the path Defuse followed; what is **to review**, grouped by check, with
what that check cannot tell; what was **checked and cleared**, with the reason;
and what was **not checked** at all, including that dependency folders are not
scanned and library versions are not checked. `--report-name` and `--report-by`
fill in the project name and "Prepared by", and `--report-note` adds one line under
the header (for example that the report is a draft). The browser UI has the same report
behind **Download report**, made by the same renderer from the same analysis.

```bash
npx github:sikkuumi/Defuse scan ./app --report=app-report.html --report-by="Your Name"
```

Two things are deliberate. Every piece of text taken from the scanned code is
escaped, and a test feeds the renderer a snippet built to break out of the page:
a security report that ran the code it quoted would be an attack on its reader.
And the value of a reported hardcoded secret is cut to its first few characters
and its length, because this file is made to be sent to someone - the full value
stays in the code and in the scan's own output.

**`--sarif`**: real SARIF 2.1.0, typed against `@types/sarif`. The confidence
label is carried three ways so it cannot be lost in transit — a `[flow-verified]`
or `[signature-based, UNVERIFIED]` message prefix, a `properties.confidence`
field, and a `codeFlows` entry that exists **only** for verified findings. A
test fails if a `codeFlow` ever appears on an unverified one. See
`docs/examples/github-code-scanning.yml` for the workflow.

**`.defuse.json`**: project config for `exclude`, `only`, `failOn` and
`minSeverity`. Command-line flags win over the file, broken JSON exits 2 rather
than being ignored, and **a rule cannot be disabled by config** — by design, so
a repository cannot quietly switch off the check it fails. See
`docs/examples/defuse.json`.

`--exclude` never hides quietly. The report prints how many files and whole
directories it removed, because a blind spot you asked for is still a blind
spot:

```
--exclude (tests, vendor) skipped 118 file(s) and 2 whole director(ies):
tests, vendor - not scanned, not counted
```

Suppression is a comment: `// defuse:ignore sql-injection - table name is a
constant`. Suppressed findings are **counted and listed**, never erased.

---

## Testing

Three suites, because they fail at different things.

**`npm test` — 1144 checks, annotation-driven.** Fixtures carry their own
expectations as comments, so there is no second list to keep in sync. Catches
regressions and honesty-contract violations. Its ceiling is that it only ever
checks what somebody already thought of.

`npm run metamorphic` generates programs whose answer is known by construction, and hand-written adversarial fixtures cover the design flaws neither suite finds. All three, and how to read the output: [docs/TESTING.md](docs/TESTING.md#test-suites).

---

## Measured on real code

Scans of five real repositories and three deliberately vulnerable apps, and the full history of what moved the score, are in [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md).

### Measured against OWASP Benchmark (ground truth)

BenchmarkJava is 2,740 Java test cases, each labelled by OWASP as a real
vulnerability or a deliberate decoy. It is the closest thing this field has to
an exam with an answer key, so here is the exam result, unedited:

<!-- derived:benchmark -->
| | cases | TP | FP | FN | TN | precision | recall |
|---|--:|--:|--:|--:|--:|--:|--:|
| **overall** | **1210** | **644** | **35** | **0** | **531** | **94.8%** | **100.0%** |

2766 files, 0 parse errors, 18.1 seconds, on engine 0.5.0 (2026-10-28).

**Precision is the weak side.** 35 false positives and no false negatives, so on this benchmark the cost of this engine is triage time, not missed bugs. That is a statement about these scored test cases, not about code in general - the limitations list is where the misses this benchmark cannot show are written down.

Nothing was missed in the scored categories. Of the 35 false positives, **0 (0%)** carry the shape of BenchmarkJava's constant-branch decoy - a condition like `if ((7 * 42) - num > 200)`. The data-flow pass, the SQL rule and the command-injection rule all decide such a condition, so the shape alone explains none of them: every false positive here is ours.

Every number above is generated by `npm run benchmark` into
`docs/benchmark-result.json` - including the sentence naming the weaker side,
because an interpretation kept by hand goes stale exactly like a figure does.
<!-- /derived -->

**That table is a training score.** Every BenchmarkJava miss and false positive
above was fixed by looking at BenchmarkJava, so 100% recall says the engine
learned that exam, not that it generalises. The honest number is one it was
not tuned on. **OWASP BenchmarkPython** (383 scored cases in the six
categories with a rule) was that set until 2026-11-08:

| BenchmarkPython, first run (held out) | precision | recall | proofs that were wrong |
|---|--:|--:|--:|
| before any fix | 69.9% | 76.6% | **10** |
| after fixing what it showed | 75.0% | 85.4% | **0** |
| second pass | 78.0% | 85.4% | **0** |

The 10 wrong proofs had three causes: an `eval` fenced to a single quoted
literal, a Python list read after `pop`, and `exec()` in a function blocking the
constant folder. XSS went from 0 of 31 to 14 when a str returned from a Flask
route became a sink. Having been fixed against, BenchmarkPython is now training
data too - `npm run scoreboard` runs it, and the next honest number needs the
next set nobody has looked at. Still missed there: XSS via a value stored in a
local dict and formatted out (`'{0[bar]}'.format(d)`), and request wrappers.

The second pass found what the answer key cannot: the Flask sink had made
about 60 **wrong proofs of XSS in files scored for other categories**, every one
through the benchmark's own `escape_for_html()`, which the engine does not
model and so assumed passes the value through. A hop whose own name says it
escapes, encodes or sanitises now makes a trace a possibility, not a proof
(an HTML escaper counts only against XSS; `b64decode(b64encode(x))` cleans
nothing). The 11 XSS proofs left there were read by hand and are real. Code
injection also gained the constant proof SQL had: 7 decoy `eval`s withdrawn,
each with a receipt. BenchmarkJava, DVWA and Juice Shop were re-run after both
changes: 0 wrong proofs, and BenchmarkJava unchanged at 94.8% / 100%.

**What the misses were.** All 38 were one shape - a helper calling a
same-named method on another object, read as recursion and cut short. That is
fixed, and recall is 100% on the scored cases; misses this benchmark cannot
show are in the limitations list above.

**What the decoys are.** The share named in the block above is BenchmarkJava's
deliberate trap, which is always the same shape:

```java
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;
```

`294 - 86 = 208`, so the constant branch always wins and `bar` is never tainted.
Seeing that needs constant folding plus branch feasibility. The data-flow pass
has both, and so do the SQL and command-injection rules. Until this release the
block above counted four false positives with the shape the other way round -
`(500 / 42) + num > 200`, where the branch that runs is the one that assigns the
"input". That input was a held object's fixed value, and those four went with
the 21 described below.

That share used to be stated here as "most". It was **37%** when finally
measured, and it had been written when the false-positive count was 49 rather
than 345 — an empirical claim that outlived the thing that changed its subject.
It is generated now, from the scorer reading every false-positive file.

These numbers are *measured*, which is the point: a scanner that will not publish
its own exam result is asking you to take its word for something it has not
checked either.

---

## What the engine does NOT do

Stated here, in the code, and in every scan report:

- **Only files inside the scan.** A call into `node_modules`, a JAR or a
  vendored package ends the trace. Call chains deeper than four are not
  followed: the value is carried past the cut and the finding says so.
- **Calls are resolved by name.** Java, Go, C and C++ also check the number of
  arguments, and Java checks the receiver's declared type. Elsewhere, two
  same-named functions can be confused.
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

What a scan costs in memory, per byte of source: [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md#how-much-memory-a-scan-costs).

---

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
| `.defuse.json` config, `--exclude` / `--only` / `--fail-on` / `--min-severity` | a rule cannot be disabled by config, by design |
| Honesty labelling enforced by the type system | `flowVerifiedFinding()` throws on an incomplete path |
| Taint tracing within a function, kind-scoped sanitisers | verified flows asserted per-line by `EXPECT-FLOW` annotations |
| Call graph within a file, unmodelled hops named on the finding | measured against OWASP Benchmark |
| Cross-file tracing through a resolved import graph | 4 findings with paths spanning 2+ files |
| Framework bindings as sources: Spring, JAX-RS, NestJS parameter decorators, Flask/FastAPI route path parameters | `SpringController.java`, `JaxrsResource.java`, `nest-decorated-params.ts`, `route-path-params.py` — each with a fence that must stay unproven |
| Prepared-statement awareness, `--exclude` | govwa: 4 findings → 1, three were correct code |
| Browser UI running the same compiled engine in a Web Worker | CLI and browser produce identical findings, checked by a test |
| Analysis deck: file tree, code with four gutter states, linked flow hops | `verifiedClean` and `fileRoles` back every mark |
| Three gauges that are never merged, each showing its arithmetic | a test fails if a combined risk score is ever exported |
| Blind spots counted per scan, not disclaimed in general | `traceLimits` from the tracer's own truncation points |
| PHP version check: Dockerfile, compose, composer.json, `.php-version` against dated php.net facts | `php-runtime.dockerfile`, and 27 checks that pin each decision with the scan date fixed |
| `defuse deps`: pinned library versions in package-lock.json, composer.lock, requirements.txt and go.mod against osv.dev. Opt-in, the one command that uses the network, and it sends names and versions only | 10 offline checks, including one that fails if a malformed OSV answer reads as "no advisories" |

**Not built**

| Next | Why it matters |
|---|---|
| Remediation: context-aware fixes and before/after diffs | a finding you can act on beats a finding you can read |
| The same version check for Node and Python; yarn, pnpm, Poetry, Maven and Cargo lockfiles in `defuse deps` | the language runtime is checked for PHP only, and those lockfiles are listed as not read |
| Language expansion — 31 more grammars already ship in `tree-sitter-wasms` | the parser layer already supports them; the dictionaries do not |
| Framework bindings still unread: Django URLconf kwargs, Spring `@ModelAttribute`, Pydantic/DTO object fields | each binds through a second file or an object’s fields, which the tracer does not follow |

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
