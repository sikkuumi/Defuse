/*
 * The JavaScript half of FolderSoundness.java: each function has exactly one
 * `=` to the name its condition reads, and each one was a real SQL injection
 * the folder hid behind a "provably constant" receipt.
 *
 *   varInIf       `var` is hoisted to the whole function, so outside the if it
 *                 is undefined when the if did not run - not 500
 *   loopCounter   `i++` writes without an `=`
 *   paramOnce     a parameter holds the caller's value before any `=`
 */
const db = require('./db');

function varInIf(req) {
  const param = req.query.p;
  if (param === '') {
    var n = 500;
  }
  const bar = n > 200 ? 'safe' : param;
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function loopCounter(req) {
  const param = req.query.p;
  for (let i = 0; i < 10; i++) {
    const bar = i > 5 ? param : 'safe';
    // EXPECT-FLOW sql-injection
    db.query("SELECT * FROM t WHERE x = '" + bar + "'");
  }
}

function paramOnce(req, num) {
  const param = req.query.p;
  if (param === '') num = 500;
  const bar = num > 200 ? 'safe' : param;
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

module.exports = { varInIf, loopCounter, paramOnce };
