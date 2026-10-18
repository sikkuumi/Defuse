/**
 * GENERATE docs/index.html AND docs/pricing.html
 * ==============================================
 *
 * The landing page is derived from the same measurement files the README reads,
 * so it cannot quote a number the engine has moved past. Run after
 * `npm run benchmark` or `npm run label-split`; `npm test` fails if you forget.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderSite } from '../dist/src/report/site.js';
import { renderPricing } from '../dist/src/report/pricing.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const benchmarkPath = join(root, 'docs/benchmark-result.json');
const splitPath = join(root, 'docs/label-split-result.json');

if (!existsSync(benchmarkPath) || !existsSync(splitPath)) {
  console.error('missing docs/benchmark-result.json or docs/label-split-result.json -');
  console.error('run `npm run benchmark` and `npm run label-split` first.');
  process.exit(1);
}

const benchmark = JSON.parse(readFileSync(benchmarkPath, 'utf8'));
const html = renderSite(benchmark, JSON.parse(readFileSync(splitPath, 'utf8')));
writeFileSync(join(root, 'docs/index.html'), html);
console.log(`docs/index.html regenerated (${html.length} bytes)`);
const pricing = renderPricing(benchmark);
writeFileSync(join(root, 'docs/pricing.html'), pricing);
console.log(`docs/pricing.html regenerated (${pricing.length} bytes)`);
