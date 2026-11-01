// FIXTURE: SSRF means the attacker chooses WHERE a server's request goes.
//
// Juice Shop's Angular services and DVWA's help pages were both proven SSRF by
// this engine, and an AI review of the DVWA proofs called every one wrong: the
// value was spliced in AFTER a fixed address (`https://host/path/`, `./`), so
// the request could only ever go where the code said. Controlling part of a
// path is worth a look - `../` can reach another endpoint on the same server -
// but it is not a request to a server the attacker picks.
const express = require('express');
const app = express();

// The whole URL is the attacker's.
app.get('/a', async (req, res) => {
  // EXPECT-FLOW ssrf
  res.send(await fetch(req.query.url));
});

// The attacker writes the host.
app.get('/b', async (req, res) => {
  // EXPECT-FLOW ssrf
  res.send(await fetch(`https://${req.query.host}/status`));
});

// A host with no slash after it: `@evil.example` or `.evil.example` moves it.
app.get('/c', async (req, res) => {
  // EXPECT-FLOW ssrf
  res.send(await fetch('https://api.example.com' + req.query.suffix));
});

// A clean base with nothing after it might end without a slash. Kept proven.
app.get('/d', async (req, res) => {
  const base = process.env.API_BASE;
  // EXPECT-FLOW ssrf
  res.send(await fetch(base + req.query.rest));
});

// ------------------------------------------------ the destination is fixed

// Fixed address, attacker sets only the path.
app.get('/e', async (req, res) => {
  // EXPECT-SIGNATURE ssrf
  res.send(await fetch(`https://api.example.com/users/${req.query.id}`));
});

// A clean base from configuration, then a slash: the base decides the host.
app.get('/f', async (req, res) => {
  const base = process.env.API_BASE;
  // EXPECT-SIGNATURE ssrf
  res.send(await fetch(`${base}/orders/${req.params.id}`));
});

// Built in two steps: where the value sits travels with it.
app.get('/g', async (req, res) => {
  const path = '/v1/items/' + req.query.item;
  // EXPECT-SIGNATURE ssrf
  res.send(await fetch(`${process.env.API}${path}`));
});

// A clean base and then a query: the base decides the host.
app.get('/h', async (req, res) => {
  // EXPECT-SIGNATURE ssrf
  res.send(await fetch(process.env.SEARCH + '?q=' + req.query.q));
});

// ------------------------------------------- browser code is not a server

// Juice Shop's basket service: the user's own browser makes this request.
function loadBasket() {
  const id = sessionStorage.getItem('bid');
  // EXPECT-SIGNATURE ssrf
  return fetch('/rest/basket/' + id);
}

// Even a whole URL from the address bar is the browser's request, not a server's.
function follow() {
  // EXPECT-SIGNATURE ssrf
  return fetch(window.location.hash.slice(1));
}

// A whole address kept in browser storage: still the browser's own request.
function openSaved() {
  const target = localStorage.getItem('endpoint');
  // EXPECT-SIGNATURE ssrf
  return fetch(target);
}

module.exports = { app, loadBasket, follow, openSaved };
