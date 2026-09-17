/**
 * A static file server, because .wasm must arrive with the right Content-Type
 * and `file://` cannot load ES modules. Forty lines, no dependencies.
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..', 'ui');
const port = Number(process.env.PORT ?? 4173);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', `http://localhost:${port}`);
  const relative = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = path.join(root, path.normalize(relative).replace(/^(\.\.[/\\])+/, ''));

  try {
    const body = await readFile(filePath);
    response.writeHead(200, {
      'Content-Type': TYPES[path.extname(filePath)] ?? 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    response.end(body);
  } catch {
    response.writeHead(404, { 'Content-Type': 'text/plain' });
    response.end('not found');
  }
}).listen(port, () => {
  console.log(`Defuse UI -> http://localhost:${port}`);
});
