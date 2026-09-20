/*
 * JAVASCRIPT IS THE CONTROL, AND A CONTROL IS NOT A FORMALITY.
 *
 * See constant-branch.py for the story. When the folder turned out to be broken
 * in Python and half-broken in PHP, the obvious next thought was "the folder is
 * Java-shaped" - and that thought is only worth anything if somewhere it is NOT
 * broken. JavaScript names condition, consequence and alternative exactly as
 * Java does, on both the ternary and the `if`, so it should have worked from
 * the first commit without anyone testing it.
 *
 * It did. That is what makes the two failures grammar differences rather than
 * a language-agnostic bug in the folder, and it is why this file exists even
 * though every case in it passed before a line was changed: the fix touched
 * shared code that JavaScript was already getting right, and a control with no
 * test behind it stops being a control the moment somebody edits the thing it
 * was controlling for.
 */
const db = require('./db');

// ---------------------------------------------------------------- DEAD BRANCHES

function ternaryAlwaysTrue(req) {
  const param = req.query.p;
  const num = 106;
  const bar = (7 * 18) + num > 200 ? 'constant' : param;
  // EXPECT-SIGNATURE sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function ternaryAlwaysFalse(req) {
  const param = req.query.p;
  const bar = 1 > 2 ? param : 'constant';
  // EXPECT-SIGNATURE sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function ifElseDeadArm(req) {
  const param = req.query.p;
  const num = 106;
  let bar;
  if ((7 * 18) + num > 200) {
    bar = 'constant';
  } else {
    bar = param;
  }
  // EXPECT-SIGNATURE sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function neverTaken(req) {
  let bar = 'constant';
  if (false) {
    bar = req.query.p;
  }
  // EXPECT-SIGNATURE sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

// ------------------------------------------------------------------ LIVE BRANCHES

function ternaryPicksTheTaint(req) {
  const param = req.query.p;
  const num = 106;
  const bar = (7 * 18) + num > 200 ? param : 'constant';
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function ifLiveArm(req) {
  const param = req.query.p;
  let bar;
  if (1 < 2) {
    bar = param;
  } else {
    bar = 'constant';
  }
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function undecidableCondition(req) {
  let bar = 'constant';
  if (req.query.mode === 'raw') {
    bar = req.query.p;
  }
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

// Not foldable by arithmetic alone. Deciding this would need a model of String,
// which is the creeping cleverness that turns a folder into a liability.
function notFoldable(req) {
  const param = req.query.p;
  const bar = 'abc'.length > 2 ? param : 'constant';
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}
