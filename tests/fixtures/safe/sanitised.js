// FIXTURE: flows that ARE properly sanitised. The tracer must confirm they are
// clean, and the signature guesses at these lines must be RETRACTED.
// EXPECT-NONE
const db = require('./db');
const escapeHtml = require('escape-html');

// A number cannot carry a quote or a semicolon.
function numericId(req) {
  const id = parseInt(req.query.id, 10);
  return db.query("SELECT * FROM users WHERE id = " + id);
}

// Escaped for HTML, used in HTML - the right soap for the job.
function escapedForHtml(req, el) {
  el.innerHTML = "<b>Hello " + escapeHtml(req.query.name) + "</b>";
}

// Parameterised: the value is never part of the instruction.
function parameterised(req) {
  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}
