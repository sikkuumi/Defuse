const express = require('express');
const http = require('http');
const axios = require('axios');
const app = express();

app.post('/sync', (req, res) => {
  // EXPECT-FLOW ssrf
  http.get(req.body.syncUrl, (r) => r.pipe(res));
});

app.get('/preview', async (req, res) => {
  // EXPECT-FLOW ssrf
  const data = await fetch(req.query.target);
  res.send(await data.text());
});

app.get('/proxy', async (req, res) => {
  // EXPECT-FLOW ssrf
  res.json(await axios.get(req.query.u));
});

// SAFE: the host is fixed, only a path segment varies. Nobody can redirect this.
app.get('/weather', async (req, res) => {
  const r = await fetch('https://api.weather.example/v1/current');
  res.send(await r.text());
});
