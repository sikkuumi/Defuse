# Glossary

Every term this repo uses, in plain language. Written for someone new to both
security and parsers.

---

## Parsing

**AST (Abstract Syntax Tree)**
Your code, represented as a tree instead of text. "Abstract" because it drops
things that do not change meaning (spaces, most punctuation), "syntax" because
it follows the language's grammar, "tree" because code nests inside code.
`const total = price + tax;` becomes a `lexical_declaration` containing a
`variable_declarator` containing a `binary_expression`. Run
`defuse ast <file>` to see a real one.

**Parser**
The program that turns text into an AST. We use **tree-sitter**, GitHub's parser
toolkit: fast, error-tolerant (it produces a usable tree even for broken code),
and it has mature grammars for dozens of languages that all behave the same way.

**Grammar**
The rules of one language, compiled into a file the parser loads. We ship them as
`.wasm` (WebAssembly) files so no compiler is needed to install the tool — and so
the same files work unchanged in a browser, which is how the web UI runs the
very same engine.

**Node**
One item in the tree. It has a **type** (`call_expression`, `string`, `identifier`)
and a position in the source.

**Named vs anonymous node**
`db.query(x)` contains the dot and the parentheses as nodes too, but they carry
no meaning of their own — tree-sitter calls those *anonymous*. Rules almost never
care about them, so the AST printer hides them by default.

**Field**
A child's *role* rather than its position. In a `binary_expression` the children
are labelled `left`, `operator`, `right`. Matching on roles instead of "child
number 2" is what makes patterns survive grammar updates.

**Tree-sitter query**
A pattern written as nested parentheses that describes a shape of tree, with
`@names` marking the parts you want back. See `src/engine/shapes.ts` — that file
is annotated line by line.

---

## Security

**SAST — Static Application Security Testing**
Finding bugs by *reading* code without running it. This tool is a SAST tool.
The counterpart, **DAST**, tests a running application from the outside; **IAST**
instruments a running application from the inside.

**CWE — Common Weakness Enumeration**
The industry's shared numbered catalogue of *kinds* of bug. CWE-89 is SQL
injection, CWE-79 is XSS. Using CWE ids means your findings line up with everyone
else's tooling.

**OWASP Top 10**
A widely used list of the ten most significant web application risk categories,
revised every few years. We tag findings with the 2021 categories (A01–A10).

**Source**
A place where data an attacker might control enters your program: an HTTP
request, a query string, a form field, an uploaded file, a message queue.

**Sink**
A place where data becomes dangerous: a database query, a shell command, HTML
written to a page, a file path, a deserialiser.

**Taint analysis / data-flow analysis**
Following a value from a source, through assignments and function calls, to see
whether it reaches a sink without being cleaned. This is what turns a guess into
a proof. **Defuse does this in all five languages**, across functions and across
files where imports resolve — and where it cannot follow a value, the finding
stays `signature-based` rather than being upgraded on a hunch.

**Sanitisation**
Cleaning untrusted input before use. Note that for SQL the real fix is not
cleaning but **parameterisation** — sending the query and the values separately,
so a value can never be read as an instruction.

**Escaping**
Turning characters with special meaning into harmless text — `<` becomes `&lt;`
so a browser displays it instead of treating it as a tag. Escaping is the safe
default for HTML; sanitising (keeping the markup but stripping dangerous parts)
is only for when users are genuinely allowed to send HTML.

**Signature-based**
A pattern was matched in the syntax tree. We saw a shape that is *often* a
vulnerability. We did **not** trace where the data came from. Might be real,
might be a false positive — you still have to look.

**Flow-verified**
We traced actual data from a source to a sink and confirmed nothing sanitised it
along the way, and we can show you every hop. **A finding cannot carry this
label without a complete path attached — the constructor refuses to build one.**

**False positive**
The tool reported a problem that is not one. The main cost is not the wasted
minute — it is that people stop reading the reports.

**False negative**
A real problem the tool missed. Worse in consequence, invisible in practice,
which is why the coverage ledger exists.

**Entropy (Shannon entropy)**
A number for "how random does this text look?", in bits per character. English
prose scores about 2.5–3.5; a generated API key usually scores above 4. It is a
hint, never a verdict — a hash, a UUID or a base64 fixture scores the same as a
real key, which is why entropy-only findings carry a lower severity here.

**Secrets rotation**
Replacing a credential with a new one. Necessary after any leak, because you
cannot un-copy something. Deleting the line from your code does not help — the
value is still in git history.

---

## This project's own vocabulary

**Shape**
A language-neutral view of one piece of code. There are two: `CallSite`
(something is being called with arguments) and `Assignment` (a name is being
bound to a value). Rules see shapes, never raw AST nodes.

**Rule**
One thing the scanner knows how to look for, as a plain function over shapes.
Lives in `src/rules/`. Declares its own per-language support status and its own
limitations.

**Coverage ledger**
The "What this scan did NOT check" section printed at the end of every run:
engine limits, partial rules, missing rule/language combinations, and file types
present in the tree that were never opened.

**Suppression**
A comment that silences a specific rule on a specific line:
`// defuse:ignore sql-injection - table name is a constant`. Suppressed
findings are counted and listed in the report, never erased.
