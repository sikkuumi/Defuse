// FIXTURE: flows that cross a FUNCTION BOUNDARY, JavaScript.
// Phase 3a stopped at the call; Phase 3b follows the value in and back out.
const db = require('./db');

// Forward: the taint arrives as a parameter and reaches a sink in here.
function runQuery(sqlText) {
  // EXPECT-FLOW sql-injection
  return db.query(sqlText);
}
function handlerForward(req) {
  runQuery("SELECT * FROM users WHERE id = " + req.query.id);
}

// Backward: the helper FETCHES the source itself and returns it.
function readName(req) {
  return req.query.name;
}
function handlerReturn(req) {
  const name = readName(req);
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
}
