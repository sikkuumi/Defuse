/**
 * OWASP BENCHMARK SCORER
 * ======================
 *
 * The handwritten fixtures find bugs; the metamorphic suite proves properties;
 * this measures. BenchmarkJava is 2,740 Java files, each one a labelled test
 * case: the CSV says whether the file really is vulnerable and to what.
 *
 * We score only the three categories this scanner has rules for. Counting
 * ourselves against path traversal or weak randomness - which we do not
 * implement at all - would let an unimplemented rule quietly earn credit for
 * every true negative it never looked at. The uncovered categories are already
 * reported honestly in the OWASP coverage panel; they do not belong here.
 *
 * Usage:  node scripts/benchmark.mjs
 */
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const benchmark = join(root, 'corpus2/BenchmarkJava');

/** Our rule ids, mapped to the Benchmark's category names. */
const RULE_TO_CATEGORY = {
  'sql-injection': 'sqli',
  'command-injection': 'cmdi',
  xss: 'xss',
};
const SCORED = new Set(Object.values(RULE_TO_CATEGORY));

const expected = new Map();
const csv = readFileSync(join(benchmark, 'expectedresults-1.2.csv'), 'utf8').split('\n');
for (const line of csv.slice(1)) {
  const [name, category, real] = line.split(',').map((f) => (f ?? '').trim());
  if (!name || !SCORED.has(category)) continue;
  expected.set(name, { category, vulnerable: real === 'true' });
}

// The CLI exits non-zero when it finds anything, which is correct for CI and
// makes execFileSync throw. The findings are still on stdout, so take them.
let raw;
try {
  raw = execFileSync(
    'node',
    [join(root, 'dist/src/cli.js'), 'scan', join(benchmark, 'src/main/java/org/owasp/benchmark/testcode'), '--json'],
    { encoding: 'utf8', maxBuffer: 1024 * 1024 * 512, stdio: ['ignore', 'pipe', 'ignore'] },
  );
} catch (error) {
  raw = error.stdout ?? '';
  if (!raw) throw error;
}
// The CLI writes a progress line to stdout before the payload; skip to the JSON.
const result = JSON.parse(raw.slice(raw.indexOf('{')));

/** Reported: test case -> set of categories we flagged in it. */
const reported = new Map();
for (const finding of result.findings) {
  const category = RULE_TO_CATEGORY[finding.ruleId];
  if (!category) continue;
  const match = /BenchmarkTest\d+/.exec(finding.location.file);
  if (!match) continue;
  if (!reported.has(match[0])) reported.set(match[0], new Set());
  reported.get(match[0]).add(category);
}

let tp = 0;
let fp = 0;
let fn = 0;
let tn = 0;
const missedBy = {};
for (const [name, { category, vulnerable }] of expected) {
  const flagged = reported.get(name)?.has(category) ?? false;
  if (vulnerable && flagged) tp++;
  else if (vulnerable && !flagged) {
    fn++;
    missedBy[category] = (missedBy[category] ?? 0) + 1;
  } else if (!vulnerable && flagged) fp++;
  else tn++;
}

const precision = tp / (tp + fp);
const recall = tp / (tp + fn);
console.log(`OWASP BenchmarkJava - sqli, cmdi and xss only (the categories we implement)`);
console.log(`  scored test cases : ${expected.size}`);
console.log(`  TP ${tp}   FP ${fp}   FN ${fn}   TN ${tn}`);
console.log(`  precision ${(precision * 100).toFixed(1)}%   recall ${(recall * 100).toFixed(1)}%`);
console.log(`  missed by category: ${JSON.stringify(missedBy)}`);
