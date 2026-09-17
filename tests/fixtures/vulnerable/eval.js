const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
  // EXPECT-FLOW code-injection
  const total = eval(req.body.preTax);
  res.json({ total });
});

app.get('/fn', (req, res) => {
  // EXPECT-FLOW code-injection
  const f = new Function('x', req.query.body);
  res.json({ v: f(1) });
});

app.get('/logs', (req, res) => {
  // Deliberately NOT reported: ReDoS is CWE-1333, an availability bug, not
  // code execution. Filing it under CWE-94 would put the wrong number on it.
  const regex = new RegExp(req.query.filter);
  res.json({ ok: regex.test('a') });
});

app.get('/later', (req, res) => {
  // EXPECT-FLOW code-injection
  setTimeout(req.query.cb, 100);
  res.end();
});

// SAFE: a fixed pattern, and a number.
app.get('/safe', (req, res) => {
  const r = new RegExp('^[a-z]+$');
  const n = eval('1 + 1');
  res.json({ ok: r.test('x'), n });
});
