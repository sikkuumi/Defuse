// FIXTURE: what common JavaScript calls return, so a proof does not rest on a guess.
const crypto = require('crypto');
const express = require('express');
const { User } = require('./models');

const app = express();

// An ORM read returns a stored row, not the id that picked it. Juice Shop's
// routes/userProfile.ts: the cookie chooses the user, and the username saved on
// an EARLIER request reaches eval - a real bug, but second-order, so the proof
// that "the cookie reaches eval" was false. Now a fair guess, not a proof.
app.get('/profile', async (req, res) => {
  const user = await User.findByPk(req.cookies.uid);
  // EXPECT-SIGNATURE code-injection
  eval(user.username);
  res.end();
});

// A hex digest is letters and digits, whatever went in.
app.get('/fingerprint', (req, res) => {
  const fp = crypto.createHash('sha256').update(req.query.text).digest('hex');
  // EXPECT-CLEAN xss
  res.write('<p>' + fp + '</p>');
});

// digest() with no encoding returns raw bytes, which this engine does not
// describe - so the line stays reported, never cleared.
app.get('/raw', (req, res) => {
  const raw = crypto.createHash('sha256').update(req.query.text).digest();
  // EXPECT xss
  res.write('<p>' + raw + '</p>');
});

// A method called on the RESULT of a sanitiser. The request value is inside
// the chain, and the whole call used to be read as the request itself - the
// escaping in the middle was skipped and the line was "proven" XSS.
app.get('/greet', (req, res) => {
  // EXPECT-CLEAN xss
  res.write('<p>' + escapeHtml(req.query.name).trim() + '</p>');
});

module.exports = app;
