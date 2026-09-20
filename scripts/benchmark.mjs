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
 *
 * SCAN SCOPE: THE WHOLE APPLICATION, NOT JUST testcode/.
 *
 * This used to point at src/main/java/org/owasp/benchmark/testcode, and that
 * was a flaw in this harness rather than a property of the corpus. The test
 * cases depend on helper classes in a sibling directory - a request wrapped in
 * `helpers/SeparateClassRequest` is the most common shape in the whole corpus -
 * and scanning only testcode/ hands the engine a call whose definition it was
 * never given. No scanner can follow an edge into a file that is not in the
 * scan, and nobody points a SAST tool at one package of an application.
 *
 * Measured both ways on the same engine, so the size of the correction is on
 * the record rather than folded in quietly:
 *
 *     testcode/ only   TP 575  FP 391  FN 69   precision 59.5%  recall 89.3%
 *     whole tree       TP 606  FP 401  FN 38   precision 60.2%  recall 94.1%
 *
 * Both figures moved in the same direction, which is the reassuring case: a
 * wider scan that had only raised recall would be worth suspecting.
 * Usage:  node scripts/benchmark.mjs
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
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
    [join(root, 'dist/src/cli.js'), 'scan', join(benchmark, 'src/main/java/org/owasp/benchmark'), '--json'],
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
const falsePositives = [];
for (const [name, { category, vulnerable }] of expected) {
  const flagged = reported.get(name)?.has(category) ?? false;
  if (vulnerable && flagged) tp++;
  else if (vulnerable && !flagged) {
    fn++;
    missedBy[category] = (missedBy[category] ?? 0) + 1;

  } else if (!vulnerable && flagged) {
    fp++;
    falsePositives.push(name);
  }
  else tn++;
}

const precision = tp / (tp + fp);
const recall = tp / (tp + fn);
console.log(`OWASP BenchmarkJava - sqli, cmdi and xss only (the categories we implement)`);
console.log(`  scored test cases : ${expected.size}`);
console.log(`  TP ${tp}   FP ${fp}   FN ${fn}   TN ${tn}`);
console.log(`  precision ${(precision * 100).toFixed(1)}%   recall ${(recall * 100).toFixed(1)}%`);
console.log(`  missed by category: ${JSON.stringify(missedBy)}`);

/*
 * IS THE "DELIBERATE TRAPS" CLAIM STILL TRUE?
 *
 * The README asserted for a long time that "most false positives are the
 * benchmark's deliberate traps" - BenchmarkJava's constant-branch decoys:
 *
 *     int num = 86;
 *     if ((7 * 42) - num > 200) bar = "This_should_always_happen";
 *     else bar = param;
 *
 * That sentence was written when FP was 49. FP is now 345, a 7x rise caused by
 * the Spring and JAX-RS source bindings, and nobody re-checked whether the
 * composition of those false positives is still the same. An empirical claim
 * that survives the thing that changed its subject is not a claim any more, it
 * is a leftover.
 *
 * So it is measured rather than asserted: read every false-positive file and
 * look for the decoy's shape - a constant-arithmetic condition guarding the
 * assignment. Whatever the number turns out to be is what the README will say.
 */
const TRAP_SHAPES = [
  /if\s*\(\s*\(?\s*\d+\s*[*+\-/]\s*\d+\s*\)?\s*[-+*/]?\s*\w*\s*[<>=]/, // (7 * 42) - num > 200
  /if\s*\(\s*\d+\s*[<>=]+\s*\d+\s*\)/,                                  // if (5 > 3)
  /This_should_always_happen|Nothing_to_see_here|safe_value/i,          // the decoy strings
];
let trapped = 0;
for (const name of falsePositives) {
  const file = join(benchmark, `src/main/java/org/owasp/benchmark/testcode/${name}.java`);
  if (!existsSync(file)) continue;
  const body = readFileSync(file, 'utf8');
  if (TRAP_SHAPES.some((re) => re.test(body))) trapped++;
}
const trapShare = fp === 0 ? 0 : trapped / fp;
console.log(`  of ${fp} false positives, ${trapped} carry the constant-branch decoy (${(trapShare * 100).toFixed(0)}%)`);

/*
 * WRITE THE RESULT DOWN, so the README cannot outlive it.
 *
 * The README carried 64.5% precision / 13.8% recall for about twenty versions
 * after the engine measured 58.8% / 76.4%. Both were honest when written; the
 * first was simply left behind by the Spring and JAX-RS source bindings.
 *
 * A number a human retypes into prose is a number that goes stale silently. So
 * the scorer now emits its own result and `npm test` compares the README's
 * table against this file - re-measure, or the build fails. It cannot be
 * quietly wrong any more, only loudly out of date.
 */
const resultPath = join(root, 'docs/benchmark-result.json');
// Placeholder replaced below - the trap measurement runs first now.
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
writeFileSync(
  resultPath,
  `${JSON.stringify(
    {
      scored: expected.size,
      tp,
      fp,
      fn,
      tn,
      precision: `${(precision * 100).toFixed(1)}%`,
      recall: `${(recall * 100).toFixed(1)}%`,
      missedByCategory: missedBy,
      filesParsed: result.diagnostics?.stats?.filesParsed ?? 0,
      parseErrors: result.diagnostics?.stats?.filesWithParseErrors ?? 0,
      durationMs: result.diagnostics?.stats?.durationMs ?? 0,
      decoyFalsePositives: trapped,
      decoyShare: `${(trapShare * 100).toFixed(0)}%`,
      engineVersion: pkg.version,
      measuredAt: new Date().toISOString().slice(0, 10),
    },
    null,
    2,
  )}\n`,
);
console.log(`\n  written to docs/benchmark-result.json`);
