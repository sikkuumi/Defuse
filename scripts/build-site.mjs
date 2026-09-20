/**
 * GENERATE docs/index.html
 * ========================
 *
 * The landing page is derived from the same measurement files the README reads,
 * so it cannot quote a number the engine has moved past. Run after
 * `npm run benchmark` or `npm run label-split`; `npm test` fails if you forget.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderSite } from '../dist/src/report/site.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const benchmarkPath = join(root, 'docs/benchmark-result.json');
const splitPath = join(root, 'docs/label-split-result.json');

if (!existsSync(benchmarkPath) || !existsSync(splitPath)) {
  console.error('missing docs/benchmark-result.json or docs/label-split-result.json -');
  console.error('run `npm run benchmark` and `npm run label-split` first.');
  process.exit(1);
}

const html = renderSite(
  JSON.parse(readFileSync(benchmarkPath, 'utf8')),
  JSON.parse(readFileSync(splitPath, 'utf8')),
);
writeFileSync(join(root, 'docs/index.html'), html);
console.log(`docs/index.html regenerated (${html.length} bytes)`);
