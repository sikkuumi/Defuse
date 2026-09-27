/*
 * THE LAST CERTAIN WRITE DECIDES THE VALUE - AND THE SHAPES WHERE IT DOES NOT.
 *
 * The SQL rule's constant proof used to need EVERY write to a name to be a
 * literal, so a dirty value overwritten one line later sank it. Now the write
 * that certainly runs last before the read is the only one that counts - when
 * it is a statement directly in a block holding the read, and no other write
 * comes after it anywhere. KeyedMapRead.java is where this was needed; this is
 * the same rule in JavaScript, with the ways it could go wrong.
 */
const db = require('./db');

function overwritten(req) {
  let bar = req.query.p;
  bar = 'safe';
  // EXPECT-CLEAN sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

// A closure writes `bar` out of sight of a walk that stops at nested functions.
// `readSetting` is defined nowhere in the scan, so the tracer has no source to
// follow and only the pattern rule can speak - and it must not be talked out of
// it by the one write it can see.
function writtenInClosure(req) {
  let bar = 'safe';
  const set = () => {
    bar = readSetting(req.id);
  };
  set();
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

// The loop's update runs AFTER the body: the first pass reads the unknown value.
// (Unknown, not proven dirty - so this is a guess, and the guess must stand.)
function forUpdate(req) {
  let bar;
  for (bar = readSetting(req.id); bar.length < 10; bar = 'safe') {
    // EXPECT sql-injection
    db.query("SELECT * FROM t WHERE x = '" + bar + "'");
  }
}

module.exports = { overwritten, writtenInClosure, forUpdate };
