/*
 * The JavaScript half of OuterWriteFence.java: a module-level `let` is one
 * variable shared by every function in the file, and any of them can write it.
 * `readSetting` is defined nowhere, so the tracer has no source to follow.
 */
const db = require('./db');

let table = 'users';

function setTable(req) {
  table = readSetting(req.id);
}

function listTable() {
  // EXPECT sql-injection
  return db.query('SELECT * FROM ' + table);
}

// Declared outside with no value, so the only write in view is this
// function's own 'safe' - and setMode(), called in between, writes the shared
// variable after it. A name this function does not declare is a name some
// other function can assign, whether or not a write of its own is in view.
let mode;

function setMode(req) {
  mode = readSetting(req.id);
}

function runMode(req) {
  mode = 'safe';
  setMode(req);
  // EXPECT sql-injection
  return db.query("SELECT * FROM t WHERE x = '" + mode + "'");
}

module.exports = { setTable, listTable, setMode, runMode };
