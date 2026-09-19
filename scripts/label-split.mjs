/**
 * LABEL SPLIT SCORER
 * ==================
 *
 * scripts/benchmark.mjs answers "how accurate is Defuse?" with one pair of
 * numbers. That pair is a blend. It counts a test case as flagged when ANY
 * finding lands in it, whether that finding was a pattern match or a traced
 * data path - which means the headline precision is an average across two
 * populations the whole tool exists to keep apart.
 *
 * Averaging them is exactly the move the honesty convention refuses when a
 * single finding does it. Doing it in the scorer is the same error one level up.
 *
 * So this scores the two labels separately and asks the question a user
 * actually has:
 *
 *     "If I only acted on the green ones, how often would I be wrong?"
 *
 * THE ATTRIBUTION RULE, stated because it is a choice and not a fact:
 *
 *   flow-verified tier  A test case counts as flagged if at least one
 *                       flow-verified finding of the right category is in it.
 *
 *   signature-only tier A test case counts as flagged if it has a signature
 *                       finding of the right category and NO flow-verified one.
 *
 * The two tiers therefore partition the combined flagged set: every case the
 * blended scorer counts lands in exactly one of them, so TP and FP add back up.
 * Recall does not: measured alone, the flow-verified tier must miss every case
 * only the signature pass caught. That is not a regression, it is the price of
 * the label, and reporting it is the point.
 *
 * Usage:  node scripts/label-split.mjs
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const benchmark = join(root, 'corpus2/BenchmarkJava');

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
const result = JSON.parse(raw.slice(raw.indexOf('{')));

/*
 * REFUSE TO GUESS. If the payload does not actually carry the label, every
 * number below would be a fabrication with a confident format. Stop instead.
 */
const LABELS = new Set(['signature-based', 'flow-verified']);
const unlabelled = result.findings.filter((f) => !LABELS.has(f.confidence));
if (unlabelled.length > 0) {
  console.error(
    `refusing to score: ${unlabelled.length} finding(s) carry no recognised confidence label ` +
      `(saw ${JSON.stringify([...new Set(unlabelled.map((f) => f.confidence))])}).`,
  );
  process.exit(1);
}

/** test case -> { verified: Set<category>, signature: Set<category> } */
const reported = new Map();
for (const finding of result.findings) {
  const category = RULE_TO_CATEGORY[finding.ruleId];
  if (!category) continue;
  const match = /BenchmarkTest\d+/.exec(finding.location.file);
  if (!match) continue;
  if (!reported.has(match[0])) reported.set(match[0], { verified: new Set(), signature: new Set() });
  const entry = reported.get(match[0]);
  if (finding.confidence === 'flow-verified') entry.verified.add(category);
  else entry.signature.add(category);
}

const blank = () => ({ tp: 0, fp: 0, fn: 0, tn: 0, falsePositives: [], missed: {} });
const verifiedTier = blank();
const signatureTier = blank();
const combined = blank();
let bothLabels = 0; // cases where the same category was reported under both labels

const record = (tier, vulnerable, flagged, name, category) => {
  if (vulnerable && flagged) tier.tp++;
  else if (vulnerable && !flagged) {
    tier.fn++;
    tier.missed[category] = (tier.missed[category] ?? 0) + 1;
  } else if (!vulnerable && flagged) {
    tier.fp++;
    tier.falsePositives.push(name);
  } else tier.tn++;
};

for (const [name, { category, vulnerable }] of expected) {
  const entry = reported.get(name);
  const byFlow = entry?.verified.has(category) ?? false;
  const bySignature = entry?.signature.has(category) ?? false;
  if (byFlow && bySignature) bothLabels++;

  record(verifiedTier, vulnerable, byFlow, name, category);
  record(signatureTier, vulnerable, bySignature && !byFlow, name, category);
  record(combined, vulnerable, byFlow || bySignature, name, category);
}

/*
 * THE DECOY QUESTION, asked of each tier separately.
 *
 * BenchmarkJava plants cases where tainted data is assigned inside a branch
 * that constant arithmetic guarantees is never taken. The data flow is real;
 * the reachability is not. A flow-verified finding there is right about the
 * path and wrong about whether the path runs - a different, milder failure
 * than inventing a path that does not exist. Worth separating, because the fix
 * is different: constant-branch evaluation, not better tracing.
 */
const TRAP_SHAPES = [
  /if\s*\(\s*\(?\s*\d+\s*[*+\-/]\s*\d+\s*\)?\s*[-+*/]?\s*\w*\s*[<>=]/,
  /if\s*\(\s*\d+\s*[<>=]+\s*\d+\s*\)/,
  /This_should_always_happen|Nothing_to_see_here|safe_value/i,
];
const decoysIn = (names) => {
  let trapped = 0;
  for (const name of names) {
    const file = join(benchmark, `src/main/java/org/owasp/benchmark/testcode/${name}.java`);
    if (!existsSync(file)) continue;
    if (TRAP_SHAPES.some((re) => re.test(readFileSync(file, 'utf8')))) trapped++;
  }
  return trapped;
};

const pct = (n) => `${(n * 100).toFixed(1)}%`;
const summarise = (label, tier) => {
  const precision = tier.tp + tier.fp === 0 ? 0 : tier.tp / (tier.tp + tier.fp);
  const recall = tier.tp + tier.fn === 0 ? 0 : tier.tp / (tier.tp + tier.fn);
  const decoys = decoysIn(tier.falsePositives);
  return {
    label,
    tp: tier.tp,
    fp: tier.fp,
    fn: tier.fn,
    tn: tier.tn,
    precision: pct(precision),
    recall: pct(recall),
    decoyFalsePositives: decoys,
    decoyShare: tier.fp === 0 ? '0%' : `${((decoys / tier.fp) * 100).toFixed(0)}%`,
    nonDecoyFalsePositives: tier.fp - decoys,
    missedByCategory: tier.missed,
  };
};

const rows = [
  summarise('flow-verified only', verifiedTier),
  summarise('signature-only', signatureTier),
  summarise('combined (published)', combined),
];

const findingCounts = result.findings.reduce((acc, f) => {
  acc[f.confidence] = (acc[f.confidence] ?? 0) + 1;
  return acc;
}, {});

console.log('OWASP BenchmarkJava - sqli, cmdi and xss, scored once per label\n');
console.log(`  scored test cases : ${expected.size}`);
console.log(`  findings emitted  : ${JSON.stringify(findingCounts)}`);
console.log(`  cases where the same category came back under BOTH labels: ${bothLabels}\n`);
const pad = (s, n) => String(s).padEnd(n);
const padS = (s, n) => String(s).padStart(n);
console.log(
  `  ${pad('tier', 22)}${padS('TP', 5)}${padS('FP', 6)}${padS('FN', 5)}${padS('precision', 11)}${padS('recall', 9)}${padS('FP that are decoys', 21)}`,
);
for (const r of rows) {
  console.log(
    `  ${pad(r.label, 22)}${padS(r.tp, 5)}${padS(r.fp, 6)}${padS(r.fn, 5)}${padS(r.precision, 11)}${padS(r.recall, 9)}${padS(`${r.decoyFalsePositives} (${r.decoyShare})`, 21)}`,
  );
}

/*
 * RECONCILIATION. The two tiers are supposed to partition the combined flagged
 * set. If they do not, the attribution rule above has a hole in it and every
 * number printed is suspect, so say so loudly rather than let it pass.
 */
const tpSum = verifiedTier.tp + signatureTier.tp;
const fpSum = verifiedTier.fp + signatureTier.fp;
const ok = tpSum === combined.tp && fpSum === combined.fp;
console.log(
  `\n  reconciliation: ${tpSum} + ${fpSum} vs combined ${combined.tp} TP / ${combined.fp} FP -> ${ok ? 'OK' : 'MISMATCH'}`,
);
if (!ok) process.exitCode = 1;

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
writeFileSync(
  join(root, 'docs/label-split-result.json'),
  `${JSON.stringify(
    {
      scored: expected.size,
      findingsByConfidence: findingCounts,
      casesWithBothLabels: bothLabels,
      tiers: rows,
      reconciles: ok,
      engineVersion: pkg.version,
      measuredAt: new Date().toISOString().slice(0, 10),
    },
    null,
    2,
  )}\n`,
);
console.log('  written to docs/label-split-result.json');
