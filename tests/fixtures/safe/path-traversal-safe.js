// FIXTURE: the fixes for path traversal, which must stay quiet.
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// Only the last name survives: no folder, no `..`.
app.get('/read', (req, res) => {
  const name = path.basename(req.query.name);
  // EXPECT-CLEAN path-traversal
  res.send(fs.readFileSync(path.join('uploads', name), 'utf8'));
});

// With root, send() refuses a path that climbs out of it.
app.get('/file/:f', (req, res) => {
  res.sendFile(req.params.f, { root: path.join(__dirname, 'public') });
});

// A number holds no dot and no slash.
app.get('/invoice', (req, res) => {
  const id = parseInt(req.query.id, 10);
  // EXPECT-CLEAN path-traversal
  res.send(fs.readFileSync(`invoices/${id}.pdf`));
});

module.exports = { app };
