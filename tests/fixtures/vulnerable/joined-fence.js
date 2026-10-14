/*
 * The other side of joined-constant.js: a join is only as fixed as EVERY piece
 * of it. One piece from `readSetting` - defined nowhere, so the tracer has no
 * source to follow - and the pattern rule's guess must stand, whichever side
 * of the `+` the unknown piece is on.
 */
const db = require('./db');

function unknownOnTheRight(req) {
  const table = 'users_' + readSetting(req.id);
  // EXPECT sql-injection
  return db.query('SELECT * FROM ' + table);
}

function unknownOnTheLeft(req) {
  const table = readSetting(req.id) + '_archive';
  // EXPECT sql-injection
  return db.query('SELECT * FROM ' + table);
}

module.exports = { unknownOnTheRight, unknownOnTheLeft };
