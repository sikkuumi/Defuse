// The other side of outer-write-fence.js: a module-level binding that nothing
// else in the file writes. In safe/, any finding is a failure.
const db = require('./db');

const TABLE = 'users';
let order = 'id';

function list() {
  return db.query('SELECT * FROM ' + TABLE + ' ORDER BY ' + order);
}

module.exports = { list };
