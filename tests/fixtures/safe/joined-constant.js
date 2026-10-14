// A name bound to literals joined with `+` is as fixed as the literals. The
// constant proof learned this for BenchmarkJava's command helper, which wraps
// "cmd.exe /c " around its argument; it holds in JavaScript the same way.
// joined-fence.js has the other side. In safe/, any finding is a failure.
const db = require('./db');

function archived() {
  const base = 'users';
  const table = base + '_archive';
  return db.query('SELECT * FROM ' + table);
}

module.exports = { archived };
