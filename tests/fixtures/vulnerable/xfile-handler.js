// FIXTURE (cross-file): the SOURCE lives here. The sink is in xfile-db.js.
const { runQuery } = require('./xfile-db');

function handler(req) {
  runQuery("SELECT * FROM users WHERE id = " + req.query.id);
}
