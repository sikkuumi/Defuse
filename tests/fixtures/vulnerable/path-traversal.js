// FIXTURE: path traversal (CWE-22). The request names a file; `../` in the
// name climbs out of the folder the code meant.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { readFileSync } = require('fs');
const app = express();

app.get('/read', (req, res) => {
  // EXPECT-FLOW path-traversal
  res.send(fs.readFileSync('uploads/' + req.query.name, 'utf8'));
});

// path.join does not stop `../`: join('uploads', '../../etc/passwd') climbs.
app.get('/join', (req, res) => {
  const file = path.join(__dirname, 'uploads', req.params.file);
  // EXPECT-FLOW path-traversal
  res.sendFile(file);
});

app.post('/delete', async (req, res) => {
  // EXPECT-FLOW path-traversal
  await fs.promises.unlink(`/var/data/${req.body.id}`);
  res.end();
});

app.get('/bare', (req, res) => {
  // EXPECT-FLOW path-traversal
  res.send(readFileSync(req.query.p));
});

// Juice Shop's /ftp route, shaped the same way.
app.get('/ftp/:file', (req, res) => {
  // EXPECT-FLOW path-traversal
  res.download(path.resolve('ftp/', req.params.file));
});

// A `..` blocklist first: not proven, not cleared - `..\` on Windows gets past it.
app.get('/checked', (req, res) => {
  if (req.query.f.includes('..')) return res.sendStatus(400);
  // EXPECT-SIGNATURE path-traversal
  res.send(fs.readFileSync('files/' + req.query.f));
});

// The right fix, but what it compares is not read: to review, not cleared.
app.get('/contained', (req, res) => {
  const base = path.resolve('files');
  const full = path.resolve(base, req.query.f);
  if (!full.startsWith(base + path.sep)) return res.sendStatus(403);
  // EXPECT-SIGNATURE path-traversal
  res.send(fs.readFileSync(full));
});

// Juice Shop's code challenges: an unknown key gets a 404 before the read. Only
// listed names get through if the lookup is exact - not read here, so to review.
const snippets = { login: 'login.ts' };
app.post('/snippet', (req, res) => {
  const key = req.body.key;
  if (snippets[key] == null) {
    res.status(404).json({ error: `No code challenge for ${key}` });
    return;
  }
  // EXPECT-SIGNATURE path-traversal
  res.send(fs.readFileSync('codefixes/' + key + '.yml'));
});

// Juice Shop: the cookie picks which user; the path holds that user's stored id.
const sessions = new Map();
app.post('/avatar', (req, res) => {
  const user = sessions.get(req.cookies.token);
  fs.writeFileSync(`avatars/${user.id}.png`, req.body);
  res.end();
});

// A command-line tool: whoever runs it could open the file themselves.
function cli() {
  // EXPECT-SIGNATURE path-traversal
  return fs.readFileSync(process.argv[2], 'utf8');
}

module.exports = { app, cli };
