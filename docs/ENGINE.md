# Inside the engine

Why Defuse parses instead of pattern-matching, how the data-flow tracer follows a value, and the PHP version check. Back to the [README](../README.md).

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

Run `defuse ast <file>` on anything to see the tree for yourself.

### Why a shape layer

`db.query(...)` in JavaScript, `cursor.execute(...)` in Python,
`stmt.executeQuery(...)` in Java and `db.Query(...)` in Go are the same idea
expressed in four grammars with four different node names. `engine/shapes.ts`
holds one tree-sitter query per language that reduces all of them to a single
`CallSite` object.

The consequence: **a rule is written once and works in every language**, and
adding the next one means adding two query strings — not editing every rule.

---

## The data-flow engine

Four words carry the whole design — **source**, **propagation**, **sanitiser**,
**sink**. `src/taint/types.ts` explains each one from scratch.

The part most tools get wrong is that **soap is job-specific**. `escapeHtml(x)`
makes a value safe for a web page and does nothing whatsoever for a SQL query.
A scanner that keeps one boolean "is it clean?" silently accepts HTML escaping
in front of a database call. Defuse tracks *which kinds* of sink a value has been
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

Some soap also depends on **where the value lands**. String escaping such as
`mysqli_real_escape_string()` only protects a value inside quotes in the query,
so Defuse settles it where the value is spliced into the string:

```php
$id = mysqli_real_escape_string($conn, $_POST['id']);
mysqli_query($conn, "SELECT * FROM users WHERE name = '$id'");  // cleared: inside quotes
mysqli_query($conn, "SELECT * FROM users WHERE id = $id");      // proven: no quotes, `1 OR 1=1` gets through
```

When the query is put together somewhere Defuse cannot read (`sprintf`, a query
builder), it cannot see the quotes, so the line is reported as *to review* -
neither cleared nor proven.

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
cycle guard so recursion cannot loop, and a per-call-site cache. When either of
the first two stops the tracer, the value is carried past the unread call as a
named assumption — it is never declared clean because the tracer stopped
reading. Imports are
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

What Defuse does instead: the value keeps its taint, and the hop is recorded as
**unmodelled**. The path shows exactly where our knowledge ran out, and the
finding's `limitations` names the function:

```
THIS PATH PASSES THROUGH 1 FUNCTION(S) WE DO NOT MODEL (`decode()`).
We assumed each one preserves the value. If any of them sanitises it,
this finding is wrong - check those hops first.
```

That is the honest version of a guess: make it, then show your work.

**Fewer guesses, by knowing what common functions return.** The guess was
right for `stripslashes()` and wrong for a database read: `mysqli_query()` and
`mysqli_fetch_assoc()` return stored rows, not the query text, and an AI review
of Defuse's proofs on DVWA marked every path through them wrong. The
dictionaries now say what such functions hand back:

- functions that keep the attacker's text (`stripslashes`, `basename`,
  `preg_replace`, `new String`, `toCharArray`, ...) carry it with no guess;
- functions whose answer is a number, true/false or hex digits (`isset`,
  `strlen`, `md5($x)` but not `md5($x, true)`, `length()`, `equals()`, ...)
  cannot carry it, and a line they feed is cleared with a receipt;
- reads whose result is new data (database rows, a file's contents) end the
  trace. That clears nothing - the line is still reported by its pattern rule,
  unproven - and every stop is listed in `--json` under
  `tracesStoppedAtNewData`. The one exception: when the query itself is
  injectable, the attacker chooses the rows (`UNION SELECT`), and the path says
  so.

On DVWA, six proofs the review called wrong are no longer proven, and all 34 it
called real still are. Two older mistakes surfaced on the way and are fixed: a
guessed step silently erased the note that a path rested on an unchecked
branch, and code that escaped a value in only one arm of an if/else was listed
as checked and cleared. And a clean write in the *other* arm of an if/else is
no longer treated as an assumption, since at most one arm runs. Taken
together, BenchmarkJava's proven tier went from 562 to 602 real
vulnerabilities, still with no false proof.

**One scoreboard instead of one app at a time.** `npm run scoreboard` scans
every practice app that comes with an answer key - BenchmarkJava (OWASP's
verdict for every case), DVWA (an AI review of every proof, plus DVWA's own
fixed `impossible.php` files, in `scripts/answer-keys/`) and OWASP Juice Shop
(its own `vuln-code-snippet` markers and coding-challenge answers) - checks
every proof against its key, and prints the mistakes grouped by cause, false
claims first. A proof the key does not cover is "not in the key", never
"right", and a real proof that disappears is listed as lost. Its first run
drove the next three fixes:

- **What JavaScript reads and hashes return.** An ORM read (`findByPk`,
  `findOne`, `findMany`, ...) returns stored rows, not the id that picked them,
  so Juice Shop's `userProfile.ts` eval - a real bug, but second-order - is no
  longer a false proof that "the cookie reaches eval". `digest('hex')`,
  Python's `hexdigest()` and Java's `DigestUtils.*Hex` return hex digits.
  And a call chained onto a call that takes the request - `escape(req.query.x)
  .trim()` - was being read as the request value itself, skipping the
  escaping in the middle; sources are now matched by the names a call is
  reached through, never by what is passed along the way.
- **Angular XSS.** `bypassSecurityTrustHtml` and its siblings turn Angular's
  escaping off, and `route.snapshot.queryParams` is the address bar. Juice
  Shop's search-box XSS and its True-Client-IP header XSS are now proven; seven
  more bypass calls on stored data are to review.
- **Secrets.** Blockchain addresses and file names are public by design (20
  false alarms in Juice Shop); a key passed straight into `createHmac()`,
  `jwt.sign()`, `hmac.new()` or `hash_hmac()` is now found, where before only a
  NAMED key was.

**SSRF is about who picks the server.** A value spliced in after a fixed start
of the address - `https://api.example.com/users/${id}`, `${base}/orders/`,
`./${page}` - cannot send the request anywhere the code did not already
choose, and a value read from the address bar or browser storage is in code
that runs in the user's own browser, where no server makes the request. Both
used to be proven SSRF: eight on DVWA, all called wrong by the AI review, and
four in Juice Shop's Angular services. They are now reported as to review, with
the reason and the fixed start printed, because part of a path can still reach
another endpoint. The value's position travels with it through variables and
concatenation, and losing track of it keeps the old answer, never clears a line.

**Allow-lists are read where the program stands after them.** All seven wrong
DVWA proofs left on the scoreboard were one kind of mistake: a check that only
lets safe values through, not read. `if (!preg_match('/^\d+$/', $id)) { error }
else { query }`, an extension compared to `jpg`/`jpeg`/`png`, four octets each
passed through `is_numeric`. Defuse now reads such a check on the side where
it holds - the true branch, the else of a negated check, after
`if (!check) { exit; }`, the matching arm of a ternary - for as long as the
value is not written again, and the value comes out of it washed like the
output of a sanitiser. What counts, in PHP, JavaScript and Python: the
`is_numeric`/`ctype_*`/`isdigit()` family, a regex that pins the WHOLE value
to digits, letters and underscores (`/^\d+$/`, `/^(asc|desc)$/i`,
`re.fullmatch`), membership in a literal list, and `===` against a literal.
What does not: an unanchored or multi-line pattern, a top-level `|` (it splits
the anchors), `\s` (a newline), `preg_match(...) !== 0` (preg_match returns
FALSE on an error, and that would pass), a loose list of numbers (PHP 7's
`"abc" == 0`), and a bare word in SQL outside quotes, which is a column name.
Each of those is a fixture that must still be reported
(`allow-list-fence.*`), and each rule was switched off to watch a test fail.

Two older mistakes went with it, both of the kind this project treats as the
worst: lines printed as **checked and cleared** that were real injections.
The first version of these checks read the sink's text, skipped every string
node, and let a check on one value vouch for a query built from another. And
a string with several values spliced in - `"VALUES ({$id}, '{$ip}')"` - took
the FIRST value's washing as its own, so an `intval`'d id in front of a raw
`X-Forwarded-For` header made the whole INSERT look clean. DVWA has exactly
that: `bac/low.php` printed its log query as cleared, and `bac/medium.php`
proved it through the checked id instead of the header. Both are now proven
through the header, and the finding names it rather than the number beside
it. DVWA's scoreboard went from 46 proofs with 7 wrong to 41 with none wrong
(3 still unsure); BenchmarkJava and Juice Shop did not change by one finding.

**Every cleared line carries a receipt.** The report's "Checked and cleared"
section used to explain every line the data-flow engine cleared with the same
sentence - "a sanitiser for this kind of problem was proven to run" - including
lines no sanitiser had touched. Each one now says what cleaned the value and
on which line (`passed through htmlspecialchars() (line 8)`, `checked by
preg_match('/^\d+$/', $id) on line 12: only digits can pass`, `` `ps` is a
prepared statement``), that the value sits inside quotes when that is half the
reason, and that it was one of several values when it was. And it names what
it **took on trust**: any function Defuse does not model that the value went
through AFTER it was cleaned, which was assumed to hand back what it was given.
DVWA's ping output is cleared only because the ping's address was checked and
`shell_exec()` was trusted, and `sqli/impossible.php` prints database rows
cleared on trust of `execute()` and `fetchArray()` - the report now says so,
in a line marked **Assumes**. A function that ran BEFORE the cleaning is not
an assumption and is not listed (OWASP BenchmarkJava has 24 of those, a file
read through unmodelled classes and then escaped).

`npm test` now asks two things of every `EXPECT-CLEAN` line: that the receipt
exists, and that its reason quotes something actually written in that file -
a stock sentence quotes nothing and fails. It also found that `EXPECT-CLEAN`
in the SAFE fixtures had never been checked at all: "nothing fired in this
file" was the whole test, so a line that went silent for any other reason
passed as proved. And it found one more of last round's kind: a container
literal, like a template, took its FIRST element's cleaning as its own, so
`[shellQuote(a), b]` was printed as checked and cleared with `b` raw in the
command line. Findings and cleared lines on all three practice apps are
unchanged.

---

### The PHP version check (`runtime-version`)

Every rule above reads code. PHP2Shell (CVE-2026-109618 and CVE-2026-109619,
October 2026) was a flaw in PHP itself, so perfect code on PHP 8.2.20 was still
a server an attacker could take over. Reading code cannot find that; reading
the version a project declares can. Defuse reads:

- `FROM` lines that use the official `php` Docker image (build arguments with
  a default are filled in; other images and earlier build stages are skipped),
- `image:` lines in docker-compose and compose files,
- `composer.json` - `require.php` and `config.platform.php`,
- `.php-version`.

and compares each with a small table of php.net facts - support end dates and
critical advisories - that carries the date it was checked
(`src/platform/php-facts.ts`). A pinned release missing a fix is critical, a
branch out of support is high, a floating tag like `php:8.3-fpm` is a low
reminder to rebuild, and a composer range that allows only unsupported branches
is high. Whether a branch is out of support is decided by the scan date, so
8.2 turns unsupported on 1 January 2027 without an edit.

Every result is **signature-based**: a declaration is not the server, and each
message says which file it read and asks you to confirm with `php -v` where the
code runs. A PHP project that declares no version gets a note saying the
runtime was not checked, and a table older than 180 days at scan time says so.
It does not read other images that bundle PHP, CI matrices or `php.ini`, and
it is not a vulnerability database - it lists only critical, exploited issues.
Command line and client report only, not the browser page.
