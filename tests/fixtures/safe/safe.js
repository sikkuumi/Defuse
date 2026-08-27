// FIXTURE: the SAFE versions of everything in ../vulnerable.
// EXPECT-NONE  (this whole file must produce zero findings)
const crypto = require('crypto');
const { execFile } = require('child_process');
const db = require('./db');

// Parameterised query: the value can never become part of the instruction.
function getUser(userId) {
  return db.query("SELECT * FROM users WHERE id = ?", [userId]);
}

// textContent never parses HTML - tags become visible characters.
function renderGreeting(el, userName) {
  el.textContent = "Welcome " + userName;
}

// Secrets come from the environment, so the code holds a name, not a value.
const dbPassword = process.env.DB_PASSWORD;

// A modern hash for integrity work.
function fingerprint(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Arguments as a list: no shell parses them, so ";" is just a character.
function pingHost(host) {
  execFile('ping', ['-c', '1', host], () => {});
}

module.exports = { getUser, renderGreeting, dbPassword, fingerprint, pingHost };
