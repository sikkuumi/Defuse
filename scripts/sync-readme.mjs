/**
 * REGENERATE THE DERIVED BLOCKS IN README.md
 * ==========================================
 *
 * Run `npm run sync:readme` after changing a rule, adding a language, or
 * re-running the benchmark. `npm test` fails if you forget.
 *
 * WHY. A fresh reader pointed at this repository produced a list of things the
 * README asserted that the code contradicted: 5 rules against a registry of 8,
 * 5 languages against 6 with PHP missing entirely, "Not SARIF" beside a working
 * SARIF 2.1.0 exporter, and 13.8% recall beside a scorer measuring 76.4%.
 *
 * Every one had been true when written. The prose was a hand-kept copy of facts
 * the program already knew, and the copy went stale - which is the same disease
 * this scanner exists to avoid in its own findings. A tool that sells calibrated
 * honesty cannot be casually wrong about itself.
 *
 * The blocks below are generated. Everything outside them is written by hand,
 * on purpose - narrative is not derivable and should not pretend to be.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  renderRuleMatrix,
  renderCounts,
  renderBenchmark,
  replaceBlock,
} from '../dist/src/report/coverage-table.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const readmePath = join(root, 'README.md');
const resultPath = join(root, 'docs/benchmark-result.json');

let markdown = readFileSync(readmePath, 'utf8');

markdown = replaceBlock(markdown, 'rule-matrix', renderRuleMatrix());
markdown = replaceBlock(markdown, 'counts', renderCounts());

if (existsSync(resultPath)) {
  markdown = replaceBlock(
    markdown,
    'benchmark',
    renderBenchmark(JSON.parse(readFileSync(resultPath, 'utf8'))),
  );
} else {
  console.warn('docs/benchmark-result.json missing - run `npm run benchmark` first.');
}

writeFileSync(readmePath, markdown);
console.log('README.md derived blocks regenerated: rule-matrix, counts, benchmark');
