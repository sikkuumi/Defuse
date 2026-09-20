/*
 * THE OPERATORS THAT RETURN ONE OF THEIR OPERANDS.
 *
 * BINARY_CARRIERS in the tracer holds two different kinds of operator.
 *
 *   COMPOSITION - `+`, `%`, `.` - builds a new value CONTAINING the operands.
 *   SELECTION   - `??`, `||`, `&&` - builds nothing and RETURNS one of them.
 *
 * Selection was missing entirely. `dirty ?? "fallback"` is `dirty` on every run
 * where dirty exists, which is every run an attacker cares about, and the
 * tracer was returning null for all three - so the finding fell back to
 * signature-based and a provable claim was reported as a guess.
 *
 * All three were added in one change and only `??` got a fixture, in a React
 * file, where it was incidental to what that file was testing. `||` and `&&`
 * went in on the strength of the same argument and were never exercised at
 * all. Engine behaviour introduced without a test is engine behaviour nobody
 * has checked, however good the reasoning was.
 */
const { exec } = require('child_process');

// Nullish coalescing: the fallback applies only when the value is absent.
function nullishCoalescing(req) {
  const dir = req.query.dir ?? '.';
  // EXPECT-FLOW command-injection
  exec('ls ' + dir);
}

// Logical OR: returns the left operand whenever it is truthy.
function logicalOr(req) {
  const dir = req.query.dir || '.';
  // EXPECT-FLOW command-injection
  exec('ls ' + dir);
}

// Logical AND: returns the right operand when the left is truthy, so a guard
// written this way hands the dirty value straight through.
function logicalAnd(req) {
  const dir = req.query.dir && req.query.dir;
  // EXPECT-FLOW command-injection
  exec('ls ' + dir);
}

/*
 * THE CONTROL, and the reason the list is short.
 *
 * Arithmetic is NOT in BINARY_CARRIERS, deliberately. Whatever `dirty - 1` is,
 * it is a number, and a number cannot be a shell command - so carrying taint
 * across it would manufacture a flow that does not exist.
 *
 * The signature pass still reports it, because a command built by
 * concatenation is a shape worth a look whatever the tracer concluded - and
 * that is the right answer. EXPECT-SIGNATURE is the sharper assertion than
 * silence would have been: the finding may appear, it must NOT carry a proof.
 * A flow-verified label here would mean arithmetic had been let into the
 * carrier list, and the whole point of that list being short is that a number
 * cannot be a shell command.
 */
function arithmeticDoesNotCarry(req) {
  const offset = req.query.n - 1;
  // EXPECT-SIGNATURE command-injection
  exec('sleep ' + offset);
}
