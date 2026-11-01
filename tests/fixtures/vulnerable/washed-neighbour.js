// FIXTURE: a washed value beside an unwashed one in one template - see
// vulnerable/washed-neighbour.php.
const db = require('./db');

function logAccess(req) {
  const a = parseInt(req.query.a, 10);
  // EXPECT-FLOW sql-injection
  return db.query(`INSERT INTO log VALUES (${a}, '${req.query.note}')`);
}

module.exports = { logAccess };
