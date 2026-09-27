/*
 * A SWITCH ON A NUMBER, IN JAVASCRIPT.
 *
 * JavaScript falls through like C and Java, so a case with no `break` runs the
 * next one too. Numbers are decided; STRINGS ARE NOT - the folder has no string
 * values at all, so `switch ('b')` keeps every case live and a dead case in it
 * is still reported. That is the last function here, and it is a false positive
 * kept on purpose rather than a guess made silently.
 */
const db = require('./db');

// ---------------------------------------------------------------- DECIDED

function deadCase(req) {
  const param = req.query.p;
  const mode = 2;
  let bar;
  switch (mode) {
    case 1:
      bar = param;
      break;
    case 2:
      bar = 'constant';
      break;
    default:
      bar = param;
  }
  // EXPECT-CLEAN sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function liveCase(req) {
  const param = req.query.p;
  const mode = 1;
  let bar;
  switch (mode) {
    case 1:
      bar = param;
      break;
    case 2:
      bar = 'constant';
      break;
  }
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

// ---------------------------------------------------------------- THE FENCE

function fallsThrough(req) {
  const param = req.query.p;
  const mode = 2;
  let bar;
  switch (mode) {
    case 2:
      bar = 'constant';
    case 3:
      bar = param;
      break;
    default:
      bar = 'other';
  }
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

// NOT DECIDED: a string selector. Case 'a' cannot run, but the folder does not
// compare strings, so it is kept live and the line is still reported.
function stringSelector(req) {
  const param = req.query.p;
  const mode = 'b';
  let bar;
  switch (mode) {
    case 'a':
      bar = param;
      break;
    case 'b':
      bar = 'constant';
      break;
  }
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

module.exports = { deadCase, liveCase, fallsThrough, stringSelector };
