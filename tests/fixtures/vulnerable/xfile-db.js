// FIXTURE (cross-file): the SINK lives here. The source is in xfile-handler.js.
const conn = require('./conn');

function runQuery(sqlText) {
  // EXPECT-FLOW sql-injection
  return conn.query(sqlText);
}

module.exports = { runQuery };
