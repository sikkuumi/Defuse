# Measurements

Scans of real repositories and vulnerable apps, every change that moved the score, and what a scan costs in memory. The headline OWASP BenchmarkJava result stays in the README. Back to the [README](../README.md).

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
saw "select", "from" and "where" in it. Defuse reported its own rule files as SQL
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

---

### What moved the score, and what did not

**Django, scanned from the browser: two proofs that were wrong.** Django
(2,974 files) was scanned in the browser UI. Seven findings came back
`flow-verified`, and two of them were not true: a response Django sends as
`text/plain`, which a browser shows as text and never runs, and Django's own
CSRF token, read from `request.META["CSRF_COOKIE"]` - a key Django's middleware
writes only after checking the cookie is letters and digits. Both are fixed at
the root: a response that declares itself text, CSV or JSON in the call is not
a page, and those two server-written META keys are not client input. Everything
next to them stays reported - an SVG response, an `HTTP_*` header, an unknown
key, a fallback value that is the client's (`django-responses.py`). The same
scan turned up 8 MD5/SHA-1 calls that pass `usedforsecurity=False`, Python's
own statement that the digest is not for security - withdrawn now, each with a
receipt saying it rests on that statement - and 4 HIGH "secrets" that were a
key prefix, the word `POST`, an SQL template and a session key name. Django went
from 443 findings to 429, none added; BenchmarkJava, the ten real projects and
DVWA did not change by one finding.

The other thing that scan raised was a policy question. The CSRF trace passed
through three functions Defuse has no entry for, and a trace through an unknown
function is assumed to carry the value, with the hop named in the path. That
assumption stays: on BenchmarkJava, 243 of the 602 flow-verified findings on
real bugs pass through such a function, and every one of them is right.
Dropping them to `signature-based` would cost 40% of the proofs to remove a
mistake that had a better fix at its source.

**An object held in a local: 21 false positives.** All 21 had the same two
lines:

```java
SeparateClassRequest scr = new SeparateClassRequest(request);
String param = scr.getTheValue("BenchmarkTest00927");
```

`getTheValue` is BenchmarkJava's labelled safe source: it returns `"bar"`
whatever it is asked. The proof already read `new X(...).m(...)`, where the type
is exact. It did not read `scr.m(...)`, because a variable can hold any
subclass - and it now does when this one cannot: a local declared once with `=
new X(...)`, never written again, used only as the receiver of calls (never
passed anywhere, never written through), and X inherits nothing. One of the 21
also put the value in a map and read it back, so a map entry stored from a name
is now judged where it was put. False positives went from 56 to 35 and precision
from 92.0% to 94.8%; nothing new was reported; the ten real projects and DVWA
did not change by one finding. Each shape that must stay reported is a fixture
(`LocalObjectHelper.java`, `ContainerHeldValue.java`), and each guard was
switched off to watch its fixture fail.

**A third break-it round, on that step: 10 more ways in, in four shapes.** A
field outlives a call - `swap(tainted); swap("x")` returns the tainted value, and
a lazy cache keeps the first call's argument - so inside a helper a field
written from a parameter is now input. `o.new X()` creates o's own member class
X, not the X the name finds. A method that calls itself made the caller's
parameter read the callee's binding. And an object handed to reflection can have
a private field rewritten. All ten are fixed and are probes in
`tests/probes/r3-*`, next to 23 shapes from the same round that the proof
already read correctly, kept so they stay that way. None of the fixes changed
the benchmark or the real projects.

**What is left.** 33 of the 35 false positives call
`ThingFactory.createThing()`, which picks the class to load from a properties
file at run time; that is reflection, and the proof does not pretend to follow
it. The other two pass a fixed value through a Base64 round trip in a library
outside the scan.

**A helper in another file: 31 false positives.** Every command-injection false
positive left had the same line in it:

```java
cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
r.exec(cmd + bar);
```

Two things stood in the way. The command rule had never asked the constant
proof anything - only the SQL rule did - and the proof stopped at the call,
because the helper lives in another file. It now follows a call into another
file when Java leaves no choice about what runs: a static method named through
its class, exactly one class of that full name in the scan, exactly one method
of that name in it. A parameter of the helper stands for what this call passes,
when that is provably fixed itself and the helper never writes to the
parameter. `getOSCommandString` wraps literals around its argument, so for
`"echo"` it returns a fixed string on every path. An overload, a variable named
like the class, two classes with one name, an import that outranks a class in
the same package, a parameter the helper overwrites, a field it returns - each
is a fixture that must stay reported (`StaticHelperCommand.java`), and each
guard was switched off to watch its fixture fail. False positives went from 87
to 56 and precision from 88.1% to 92.0%; nothing new was reported; the ten real
projects did not change by one finding. Each withdrawal is a receipt in
`--json` naming the helper, its file and line, and the literal it was passed.

**Then it was handed to something whose only job was to break it - twice.**
Before shipping, an agent was set to write ordinary-looking programs in which
the proof calls a value fixed and it is not. The first round, in Java, found 32:
a class hidden by a pattern variable, a static import, an enum constant or an
inherited member type; an inherited overload that wins; `final` that was only a
word in a comment; a local that is out of scope where the value is read; a
`\u000a` in a comment, which javac reads as a newline. The second round, across
Go, Java, JavaScript, TypeScript and Python, found 28 more - most of them in the
older SQL proof rather than the new code: block-scoped declarations standing in
for an import or a package variable, Go's method receivers, `goto`, type
switches and `select`; records and enums; `toString()` reached through `+`; a
lone carriage return ending a comment. In every one the proof withdrew a
finding for a value the program did not fix, usually with a receipt calling it
constant. All 60 are fixed, each
is a small project in `tests/probes/` that `npm test` scans on its own, and each
guard was switched off to watch its probes fail. The fixes are narrower rules,
not more cleverness - a name must be declared where the read can see it, a
class that inherits anything is not read through, a file with text the compiler
reads differently from the parser is not read at all - and they changed nothing
on BenchmarkJava or the ten real projects. The command rule uses the proof in
Java only, where it has been tested hardest. The SQL rule's limitations say what
is still not seen.

Two smaller holes turned up on the way. A name declared outside the reading
function - a field, a module-level `let` - was judged by the writes around that
function only, so a sibling method writing the field was never seen, nor
another class writing a public one (`OuterWriteFence.*`). And the scan was
spending nearly a third of its BenchmarkJava time matching every fully-qualified class
name against all 2,766 file paths; indexing them by file name once took the
scan from 37 to 25 seconds with byte-identical results.

**Replaying a list: 75 false positives, and under a hundred.** 323 BenchmarkJava
cases build the same list - `add("safe")`, `add(param)`, `add("moresafe")`,
`remove(0)` - and read one position back. Tainted whole, `get(1)` came back
dirty; it is `"moresafe"`. The list proof is the map proof with positions
instead of keys: under the same conditions (created here, handed to nothing,
written only by straight-line statements in its own block), every `add` and
`remove(n)` that certainly runs before the read is replayed in order, and the
read takes what is left at that position. `remove("x")` by value, `add(i, v)`,
`set`, `addAll`, `clear`, `sort`, an iterator's `remove`, a copy constructor, a
variable index and a read inside a lambda each keep the old answer, and each is
a fixture. False positives went from 162 to 87 and precision from 79.9% to
88.1%; 59 real vulnerabilities moved from guessed to proven; the ten real
projects did not change by one finding.

**Reading a map by its key: 53 false positives, and 47 real bugs proven.**
Hundreds of BenchmarkJava cases put the request parameter into a `HashMap` next
to some literals and read one value back out. The engine taints a collection
whole, so `map.get("keyA")` - the literal - came back dirty, and 53 safe cases
were reported. The opposite side was as blunt: `map.get("keyB")`, the dirty
value, could only be reported as a guess about which element came out.

`keyed-container.java` had refused to match keys, rightly, for a request's
attributes: filters and frameworks can write under the same name out of sight.
A map created in the method, handed to nothing, and written only by
straight-line `put("literal", value);` statements is the case where nothing can
be out of sight - so for that map, and only that map, the key decides
(`taint/local-map.ts`). The SQL rule's constant proof needed one more fact for
the same cases: the value at the query is the last write that certainly runs
before it, so `bar = map.get("keyB"); bar = map.get("keyA");` is the literal.

Both proofs were probed before they shipped - a put in a `try`, a read in a
`catch`, a labeled `break`, a read inside a lambda that runs later, `putIfAbsent`,
`getOrDefault`, a put nested inside another put, a mutable value changed through
an alias, a closure writing the name, a `for` loop's update clause, a
`while`-`else`, a shadowing `:=` in Go - and every one is a fixture that must
stay reported. Precision went from 75.0% to 79.9%; the ten real projects did not
change by one finding. Every map read answered by key is listed in `--json`
under `collectionReadsResolved`.

**Deciding switches: 56 false positives, and the last three proven ones.** 299
of BenchmarkJava's cases are built around one switch:

```java
String guess = "ABC";
char switchTarget = guess.charAt(1);   // always 'B'
switch (switchTarget) { case 'A': bar = param; break; case 'B': bar = "bob"; break; ... }
```

The engine did not know `"ABC".charAt(1)` is `'B'`, so it assumed any case might
run. On the safe cases that meant reporting a value from a case that cannot
execute — including the only three false positives left under the green label.
On the vulnerable ones (`charAt(2)`) it meant the clean writes in the dead cases
read as "maybe this cleans it", so real bugs were reported as guesses. Deciding
the switch removed 56 false positives, took precision from 70.4% to 75.0%, and
moved 55 real vulnerabilities from guessed to proven. Every case skipped is
listed in `--json` under `unreachableCodeSkipped`, with the decision behind it.

**The folder was deleting real findings, and issuing receipts for it.** Before
the switch was built on top of it, the constant folder was probed with ordinary
code in every language — and it was wrong in all of them, in the dangerous
direction. It treated a name as fixed if the function wrote to it with `=`
exactly once, which is false for a parameter written once inside an `if`, a
field, a loop counter (`i++` has no `=`), and a value handed over by address
(`fmt.Sscan(s, &n)`, `scanf("%d", &n)`) or by reference (PHP's `preg_match`, a
C++ `int&`). In each case it decided a branch that really runs was dead and
dropped a real SQL or command injection - and where the sink was SQL, the rule
then printed a receipt calling the line provably constant. Eighteen such cases
now sit in
`folder-soundness.*` and `FolderSoundness.java`. BenchmarkJava could never have
caught it: its decoys are all `int num = 86;` declarations, which were the one
shape the old rule got right.

**Then it was handed to something whose only job was to break it.** With those
fixed, an agent was told to write ordinary-looking code in which a name *looks*
fixed and is not, compile and run each program to prove the tainted path really
executes, and scan a control with the condition made opaque. It came back with
58 more, in all seven languages: `n, err := strconv.Atoi(s)` in Go, `[n] = [x]`
and `with`/`eval` in JavaScript, `list($n) = ...` and `extract()` in PHP, a
Python `match` capture, `&(n)` and a macro in C, a reference in braces in C++,
octal literals, `7 / 2` read as 3 in languages where it is 3.5, `int` overflow,
an `unsigned` wrap, a GNU case range, and a second write at the end of a long
else-if chain that sat deeper than the search looked. Each one was a real
injection missed. They are all fixtures now (`*Probe*`, `folder-soundness-*`),
each guard was switched off in turn to watch its fixtures fail, and none of
them changed a single finding on BenchmarkJava or the ten real projects — which
is exactly why they had never been seen.

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
| Defuse itself | 0 edges | 77 edges, 75 followed | still zero findings on its own source |

The govwa row is the one that matters. Going from four findings to one is an
*improvement*: the three that disappeared were the tool telling a developer that
their correctly parameterised query was a critical vulnerability.

---

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
were parsed more than once, and `DEFUSE_TREE_BUDGET_MB` trades memory back for
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
