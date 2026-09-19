# What the two labels are actually worth

Measured on OWASP BenchmarkJava, 1,210 scored test cases, engine 0.5.0.
Reproduced the published 59.5% / 89.3% exactly before changing anything.

## The numbers

| tier | TP | FP | FN | precision | recall | FPs that are decoys |
|---|---|---|---|---|---|---|
| flow-verified only | 334 | 189 | 310 | **63.9%** | 51.9% | 97 (51%) |
| signature-only | 241 | 202 | 403 | **54.4%** | 37.4% | 47 (23%) |
| combined (published) | 575 | 391 | 69 | 59.5% | 89.3% | 144 (37%) |

Flow-verified precision is 63.9%, not the ~100% the label implies, and the two
labels sit 9.5 points apart rather than a chasm. Scored on non-decoy cases only
the gap widens to 78.4% vs 60.9%, which is the defensible version of the claim.

---

## CORRECTION to the first version of this document

The first draft said **"91 of 92 non-decoy flow-verified false positives involve
a collection"** and projected precision rising to 77.3% if container
granularity were fixed. That was wrong, and wrong in a specific way worth
recording.

I produced it by grepping each false-positive **file** for collection
boilerplate — `ArrayList`, `.put(`, `[0]`. BenchmarkJava files are full of that
whether or not the traced path goes anywhere near it. It was a pattern matched
in the text, presented as a proven cause: a signature-based finding wearing a
flow-verified label, in a document about not doing that.

Checked against the actual `flowPath` of each finding, of those 92 cases:

```
  18   the path really does route through a container read
  20   no container read, but a read-out hop
  54   neither
```

The 77.3% projection does not survive. What follows replaces it.

## Finding the real discriminator

Rather than guess again, every step description in every flow-verified path was
tallied and compared between true positives and non-decoy false positives.
One line separates them:

| step present in path | % of FP | % of TP | gap |
|---|---|---|---|
| **`collected into X via add()/append()/put()`** | **97%** | **29%** | **+68** |
| concatenated into a larger string with + | 60% | 51% | +9 |
| reaches a JDBC/JPA query | 43% | 36% | +8 |
| placed into a container (whole, not per element) | 20% | 19% | 0 |
| reaches an HTTP response body unescaped | 33% | 44% | −12 |
| returned from one branch of a conditional | 0% | 18% | −18 |
| passed through X, NOT in our dictionary | 13% | 43% | −30 |

The signal is on the **write** side, not the read side. Not "we read out of a
container" but "a tainted value was ever put into one."

Splitting every flow-verified case on that single step:

| | TP | FP | precision |
|---|---|---|---|
| path contains a collect step | 96 | 94 | **50.5%** |
| path contains none | 238 | 95 | **71.5%** |

A flow-verified finding that passed through `list.add()`, `sb.append()` or
`map.put()` is correct about as often as a coin. One that did not is correct
71.5% of the time.

## Refining it by how many writes the container got

The engine loses the element, not the container. So the question is whether
anything *else* went in. Counting writes to the collected-into receiver:

| | TP | FP | precision |
|---|---|---|---|
| container written once | 6 | 1 | 85.7% |
| container written 2+ times | 90 | 93 | **49.2%** |

Seven cases is too few to lean on, so treat the top row as directional. The
bottom row is 183 cases at a coin flip, and that is the bucket that cannot
honestly be called proven: with several values in the container the engine has
no idea which one came back out.

## The proposed rule

> A flow-verified finding whose path collects into a container that received
> **more than one write** is emitted as `signature-based` instead.

Nothing is dropped, nothing goes quiet — the finding still reports, it stops
claiming proof. Projected:

- flow-verified **63.9% → 71.8%** (TP 244, FP 96)
- 93 false green labels removed, 90 true ones lost — but those 90 were coin
  flips the engine got lucky on, not traces it could defend
- combined precision and recall **unchanged** at 59.5% / 89.3%

**It does not fight `keyed-container.java`.** Both collection fixtures there —
`collectionIsTheValue` and `accumulatorIsTheValue` — write to the container
exactly once, so they keep their green label and their `EXPECT` assertions
still hold. The narrowing this file warns about is narrowing *taint*; this
narrows only the *claim*, which is the distinction the fixture itself draws
about Jenkins.

## Still open

- The decoy detector in `benchmark.mjs` only recognises `if`-shaped decoys, so
  it misses the `switch` variant in `BenchmarkTest01256` and undercounts.
- `tracer.ts` and `dictionaries.ts` point readers at `safe/keyed-container.java`;
  the file is in `vulnerable/`.
- Flow-verified alone recalls 51.9%. The published 89.3% depends on the
  signature tier, and this change moves 183 more cases into it.
