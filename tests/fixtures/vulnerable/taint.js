// FIXTURE: flows the taint engine must VERIFY, JavaScript.
// "EXPECT-FLOW <rule>" means: a finding must appear AND be labelled flow-verified.
const db = require('./db');
const { exec } = require('child_process');
const escapeHtml = require('escape-html');

function throughAVariable(req) {
  const userId = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + userId;
  // EXPECT-FLOW sql-injection
  return db.query(sql);
}

function straightIntoTheSink(req) {
  // EXPECT-FLOW command-injection
  exec("ping -c 1 " + req.body.host);
}

function intoTheDom(req, el) {
  // EXPECT-FLOW xss
  el.innerHTML = "<b>Hello " + req.query.name + "</b>";
}

// The right soap for the wrong job: HTML escaping does nothing for SQL.
function wrongSoap(req) {
  const cleanedForHtml = escapeHtml(req.query.id);
  // EXPECT-FLOW sql-injection
  db.query("SELECT * FROM users WHERE id = " + cleanedForHtml);
}
