// FIXTURE: a washed value beside an unwashed one in one template - see
// vulnerable/washed-neighbour.php.
const db = require('./db');

function logAccess(req) {
  const a = parseInt(req.query.a, 10);
  // EXPECT-FLOW sql-injection
  return db.query(`INSERT INTO log VALUES (${a}, '${req.query.note}')`);
}

// A container literal had the same habit: `[shellQuote(a), b]` was the
// quoted `a`, so the command was printed as checked and cleared with `b` raw.
const { exec } = require('child_process');

function listBoth(req) {
  const args = [shellQuote(req.query.a), req.query.b];
  // EXPECT-FLOW command-injection
  exec('ls ' + args.join(' '));
}

module.exports = { logAccess, listBoth };
