# Contributing to Defuse

Thank you for looking. Before anything else, two things that are unusual about
this project and will save you a wasted afternoon if you read them first.

## The one rule everything else serves

**Every finding is labelled `signature-based` or `flow-verified`, and the two
mean precise, different things.**

- `signature-based` — a pattern matched in the syntax tree. Data flow was
  **not** traced. It is a lead, not a fact.
- `flow-verified` — attacker data was followed from a source to a sink, and the
  whole path is printed beside the finding.

This is not a presentation choice. It is the product. Every competitor reports
everything at one confidence and hides behind the word *possible*; the only
thing this tool has that they do not is that it refuses to.

The contract is enforced by the type system rather than by discipline:
`signatureFinding()` physically cannot accept a `flowPath`, and only
`flowVerifiedFinding()` can carry one. If you find yourself wanting to widen
that, you are almost certainly about to make the tool worse in the way it
exists to avoid.

A corollary that comes up constantly: **a rule may not set its own
confidence.** Only a printed path earns the green label.

## Fixture-first falsification

The rule is: **write the fixture before you touch the engine, and prove it
fails first.**

A fixture written after a change tends to describe what the code now does. A
fixture written before it states what you believe *should* happen, and then the
engine gets to disagree with you. Most of the real bugs in this project were
found exactly this way, by predictions that turned out to be wrong.

Fixtures live in `tests/fixtures/` and carry their own expectations as
comments, so there is no second list to keep in sync:

```
// EXPECT-FLOW command-injection      must be reported, and flow-verified
// EXPECT-SIGNATURE xss               must be reported, and NOT flow-verified
// EXPECT-NONE                        (top of file) nothing at all in this file
```

An annotation sits on the line **above** the vulnerable code; a finding is
accepted within three lines below it.

**Never soften an annotation to make it pass.** If a fixture fails, either the
engine is wrong and should be fixed, or the prediction was wrong and the
reasoning for the correction goes in a comment next to the case. A fixture
edited until it agrees with the code tests nothing.

A vulnerable line that the engine genuinely misses stays in the fixture,
unannotated, with a comment saying so. A known gap that is written down is
worth more than a gap nobody can see.

## Control for the cause before you name it

This one is recent and cost us a near-miss, so it is written down.

A TypeScript fixture failed four predictions. It would have been easy to file
four TypeScript bugs. Rewriting each failing case in plain JavaScript showed
that **three of the four failed there too** — they were general limitations of
the engine that TypeScript merely happened to expose. Only one was actually
TypeScript's.

So: before you attribute a failure to a language, a rule or a feature,
reproduce it somewhere that feature is absent. A wrong diagnosis published in a
project about not overclaiming is worse than no diagnosis.

## Things that are generated — do not hand-edit them

`npm test` compares these against freshly generated output, byte for byte:

- the `<!-- derived:... -->` blocks in `README.md` — run `npm run sync:readme`
- `docs/index.html` — run `npm run build:site`
- `docs/benchmark-result.json`, `docs/label-split-result.json` — these are
  measurements; see below

If a figure looks wrong, the fix is to re-measure, never to type a better
number.

## If you change the engine, re-measure

An engine change invalidates every published figure until it is re-run. Both of
these write their results to `docs/`:

```
npm run benchmark      # OWASP BenchmarkJava, combined precision and recall
npm run label-split    # the same corpus scored separately for each label
```

Then `npm run sync:readme` and `npm run build:site` so the README and the
landing page carry the new numbers.

A neutral result still gets recorded. "I expected this to change nothing" is
not the same sentence as "this changed nothing", and only one of them is
evidence.

## Running things

```
npm install
npm test               # annotation-driven - the one that must pass
npm run build:site     # regenerate the landing page
npm run doctor         # environment sanity
npm run ui             # the browser UI on :4173
```

Several standing instruments exist beyond `npm test` — `metamorphic`,
`identity`, `memory`, `install-check`, `git-install-check`, `benchmark`,
`label-split` and others; `package.json` has the current list. They fail at
different things on purpose. `npm test` only ever checks what somebody already
thought of, which is its ceiling and the reason the others exist.

(No count here on purpose. This file is not generated, so any number written
into it is a hand-kept copy of a fact the repository already holds — which is
the thing the house conventions below tell you not to do. The check count lives
in `README.md`, where a test keeps it honest.)

## House conventions

- **No phase numbers in user-facing text.** A test enforces this. Roadmap
  numbering ages badly and ends up lying to the reader.
- **No hand-kept counts.** Language counts, rule counts and check counts are
  derived. A badge is a hand-kept copy of a fact the program already knows.
- Findings in test and fixture files are **ranked down, never dropped**.
- Comments explain *why*, especially when the reason is a bug we already hit
  once. Several comments in `src/taint/tracer.ts` exist because the same defect
  turned up twice in different languages.
- Line endings are pinned to LF by `.gitattributes`. This is load-bearing — see
  the comment in that file before changing it.

## Reporting a false positive or a miss

The most useful report is a **minimal file that reproduces it**, plus what you
expected and what you got. If you can write it as a fixture with an annotation,
that is ideal — it becomes a permanent test the moment it is merged.

Scan output with `--format json` is helpful. Please do not paste proprietary
source; reduce it to the shape that triggers the behaviour.

## Contribution terms — please read before opening a pull request

Defuse is released under **AGPL-3.0-only**, and the copyright is held in one
place so that a commercial licence can also be offered to organisations for
which AGPL terms do not work. That dual arrangement is only possible while
every line can be licensed both ways.

Because of that, **contributions are accepted under the Contributor License
Agreement in [`CLA.md`](CLA.md)**, which asks you to grant a licence including
the right to sublicense. You keep your copyright; you are not signing it away.

If that does not suit you, that is completely reasonable — open an issue
instead. A well-described bug, a reproducer or a failing fixture is genuinely
valuable and carries no such requirement.

## Pull requests

1. One change per pull request. A fixture plus the fix it justifies is one
   change; three unrelated improvements are three pull requests.
2. `npm test` passes, and the check count in `README.md` matches.
3. Any new figure is measured, not asserted.
4. Say in the description what you expected before you ran it, and whether the
   engine agreed. That sentence is worth more here than in most projects.
