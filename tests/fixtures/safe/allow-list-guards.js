// FIXTURE: allow-list checks in JavaScript - see safe/allow-list-guards.php
// for why each shape is here. Every sink must be CLEARED, not merely quiet.
// The fence is vulnerable/allow-list-fence.js.
const crypto = require('crypto');
const { exec } = require('child_process');
const db = require('./db');

// Leave early on anything that is not digits.
function byId(req, res) {
  const id = req.query.id;
  if (!/^\d+$/.test(id)) {
    return res.status(400).end();
  }
  // EXPECT-CLEAN sql-injection
  return db.query('SELECT * FROM t WHERE id = ' + id);
}

// A column name from a fixed list. includes() compares strictly.
function sorted(req) {
  const sort = req.query.sort;
  if (['name', 'price', 'date'].includes(sort)) {
    // EXPECT-CLEAN sql-injection
    return db.query(`SELECT * FROM products ORDER BY ${sort}`);
  }
  return null;
}

// One of two exact words.
function mode(req, res) {
  if (req.query.mode === 'full' || req.query.mode === 'brief') {
    // EXPECT-CLEAN xss
    res.write('<p>' + req.query.mode + '</p>');
  }
}

// The receiver form of a regex check.
function lang(req, res) {
  const l = req.query.lang;
  if (l.match(/^[a-z]{2}$/)) {
    // EXPECT-CLEAN xss
    res.write('<html lang="' + l + '">');
  }
}

// Built before the check, from the very value the check then limits.
function upload(req, res) {
  const ext = req.body.ext;
  const file = crypto.randomUUID() + '.' + ext;
  if (ext.toLowerCase() === 'png' || ext.toLowerCase() === 'jpg') {
    // EXPECT-CLEAN xss
    res.write('<a href="/u/' + file + '">done</a>');
  }
}

module.exports = { byId, sorted, mode, lang, upload, exec };
