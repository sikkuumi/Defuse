/*
 * `+=` EXTENDS A VALUE. FOR A LONG TIME IT REPLACED IT.
 *
 * Every node in the tracer's ASSIGNMENT_NODES was applied as "the target now
 * holds the right-hand side". That is right for `=` and wrong for `+=`, so a
 * CLEAN right-hand side deleted whatever the target was already carrying.
 *
 * The bug surfaced in a C++ fixture and looked like a C++ problem. Rewriting
 * the same three lines elsewhere showed JavaScript, TypeScript, Python, Java
 * and Go all lost the value identically - seven languages, in the most ordinary
 * string-building shape there is - and the fix is one shared line of tracer.
 *
 * A one-line fix across seven languages deserves more than the single C++
 * fixture that found it, which is why this file exists in each of them.
 */
const { exec } = require('child_process');

// The exact shape that was broken: dirty first, then a harmless closing piece.
function trailingConstant(req) {
  let cmd = 'ls ';
  cmd += req.query.dir;
  cmd += ' -l';
  // EXPECT-FLOW command-injection
  exec(cmd);
}

// The other order. This one always worked, and is here so a regression that
// only breaks one direction cannot hide behind the other.
function leadingConstant(req) {
  let cmd = 'grep ';
  cmd += '-F ';
  cmd += req.query.term;
  // EXPECT-FLOW command-injection
  exec(cmd);
}

/*
 * THE OVER-FIX GUARD, and the reason this case is unannotated rather than
 * absent.
 *
 * The fix makes a clean `+=` stop clearing taint. The obvious way to get that
 * wrong is to make clean assignment stop clearing taint in general - and then
 * every washed value in every language stays dirty forever, which is a false
 * positive factory rather than a fix.
 *
 * `cmd = 'ls -l'` is a real overwrite. Whatever was in cmd is gone. If this
 * line is ever reported, the fix went too far and this file says so.
 */
function realReassignmentStillClears(req) {
  let cmd = 'ls ';
  cmd += req.query.dir;
  cmd = 'ls -l';
  exec(cmd);
}
