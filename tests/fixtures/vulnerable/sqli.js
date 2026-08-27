// FIXTURE: SQL injection, JavaScript. Every finding here is intentional.
// Annotations: "EXPECT <rule-id>" on the line ABOVE the vulnerable line.
const db = require('./db');

function getUserByIdConcat(req) {
  const userId = req.query.id;
  // EXPECT sql-injection
  return db.query("SELECT * FROM users WHERE id = " + userId);
}

function getUserByIdTemplate(req) {
  // EXPECT sql-injection
  return db.query(`SELECT id, email FROM users WHERE email = '${req.body.email}'`);
}

function buildThenRun(req) {
  // EXPECT sql-injection
  const sql = "DELETE FROM sessions WHERE token = '" + req.cookies.token + "'";
  return db.execute(sql);
}
