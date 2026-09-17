/**
 * DVWA SCORER - the first recall measurement outside Java
 * =======================================================
 *
 * WHY THIS EXISTS.
 *
 * The only recall figure this project has ever published came from
 * BenchmarkJava: 76.4%, Java only. Scanning OWASP WebGoat proved that number
 * measures a Java dialect almost nobody writes any more - WebGoat produced zero
 * traced findings until Spring bindings were added, because BenchmarkJava is
 * raw servlet code from end to end.
 *
 * So "no recall number outside Java" stopped being a footnote and became the
 * longest-open item on the roadmap. Five of six languages had no measurement at
 * all, which means every claim about them was an opinion.
 *
 * WHY DVWA.
 *
 * Its directory layout IS the ground truth, and it is unusually good:
 *
 *     vulnerabilities/<category>/source/low.php        vulnerable
 *     vulnerabilities/<category>/source/medium.php     vulnerable
 *     vulnerabilities/<category>/source/high.php       vulnerable
 *     vulnerabilities/<category>/source/impossible.php SECURE - the fix
 *
 * Four files per category, same feature, same author, differing only in how
 * hard the bug is to reach - and one of them deliberately fixed. That last file
 * is the part worth having: `impossible.php` uses a real prepared statement
 * with bindParam, so a scanner that reports it is punishing the fix, which is
 * the failure mode this project has hit five times.
 *
 * Recall and the fix-test are therefore measured on the same corpus, by
 * construction, with no labelling work of our own to get wrong.
 *
 * WHAT IS SCORED, and what is not.
 *
 * Only the categories this scanner has rules for - the same discipline as the
 * BenchmarkJava scorer. DVWA also ships file inclusion, CSRF, brute force,
 * weak session ids and open redirect. We implement none of those, and counting
 * ourselves against them would hand an unimplemented rule credit for true
 * negatives it never looked at. They are reported as unscored below rather than
 * quietly dropped.
 *
 * Usage:  node scripts/dvwa.mjs [path-to-DVWA]
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const dvwa = process.argv[2] ?? join(root, 'corpus2/DVWA');

if (!existsSync(join(dvwa, 'vulnerabilities'))) {
  console.error(`DVWA not found at ${dvwa}`);
  console.error('  git clone --depth 1 https://github.com/digininja/DVWA.git corpus2/DVWA');
  process.exit(2);
}

/** DVWA's directory names, mapped to the rule that should catch them. */
const CATEGORY_RULE = {
  sqli: 'sql-injection',
  sqli_blind: 'sql-injection',
  exec: 'command-injection',
  xss_r: 'xss',
};

/**
 * Categories we DO have a rule for and still cannot score, because the bug is
 * not in the file the layout implies. Found by reading the six "misses" rather
 * than reporting them:
 *
 *   xss_d/source/low.php is 48 bytes and reads "# No protections, anything
 *   goes". The DOM XSS - document.write of a value taken from
 *   document.location.href - lives in xss_d/index.php, inside a <script> block
 *   in a .php file. Not in the scored file, and not JavaScript we parse.
 *
 *   xss_s/source/*.php contain only the INSERT half. The stored value is read
 *   back and printed elsewhere, on a later request. That is second-order taint
 *   through a database, which this tracer cannot follow and does not claim to.
 *
 * Excluding these RAISES the reported recall, so it is worth being blunt: they
 * were never detectable from the files being scored, and counting them as
 * misses was measuring the harness rather than the engine. The stored-XSS
 * limitation is real and is listed below as unscored, not as solved.
 */
const MISLABELLED = [
  'xss_d - the DOM sink is in index.php, not in source/; and it is JS inside PHP',
  'xss_s - source/ holds only the INSERT; the output is a later request (second-order)',
];

/** Present in DVWA, deliberately not scored - we have no rule for these. */
const UNSCORED = [
  'fi (file inclusion / path traversal)',
  'upload (unrestricted file upload)',
  'csrf',
  'brute (credential brute force)',
  'weak_id (predictable session ids)',
  'authbypass',
  'bac (broken access control)',
  'open_redirect',
  'captcha',
  'cryptography',
  'csp',
];

const VULNERABLE_FILES = ['low.php', 'medium.php', 'high.php'];
const SECURE_FILE = 'impossible.php';

/* ---- build the expected map from the directory layout ---- */
const expected = new Map(); // "category/file.php" -> { rule, vulnerable }
const skippedEmpty = [];
for (const [category, rule] of Object.entries(CATEGORY_RULE)) {
  const dir = join(dvwa, 'vulnerabilities', category, 'source');
  if (!existsSync(dir)) continue;
  const present = new Set(readdirSync(dir));
  for (const file of VULNERABLE_FILES) {
    if (!present.has(file)) continue;
    /*
     * A GUARD AGAINST MISLABELLING, because I did exactly that.
     *
     * A file asserted to contain a vulnerability has to contain some code. The
     * first run of this scorer counted nine misses; six were files like
     * xss_d/source/low.php, which is a single comment. Scoring an empty file as
     * a miss measures the label, not the scanner, and it is the same failure as
     * a scanner reporting a finding it cannot support.
     */
    const body = readFileSync(join(dir, file), 'utf8')
      .replace(/<\?php|\?>/g, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*(#|\/\/).*$/gm, '')
      .trim();
    if (body.length < 40) {
      skippedEmpty.push(`${category}/${file}  (${body.length} bytes of code - nothing to find)`);
      continue;
    }
    expected.set(`${category}/${file}`, { rule, vulnerable: true });
  }
  if (present.has(SECURE_FILE)) {
    expected.set(`${category}/${SECURE_FILE}`, { rule, vulnerable: false });
  }
}

/* ---- scan ---- */
// The CLI exits non-zero when it finds anything, which is correct for CI and
// makes execFileSync throw. The findings are still on stdout, so take them.
let raw;
try {
  raw = execFileSync(
    'node',
    [join(root, 'dist/src/cli.js'), 'scan', join(dvwa, 'vulnerabilities'), '--json'],
    { encoding: 'utf8', maxBuffer: 1024 * 1024 * 256, stdio: ['ignore', 'pipe', 'ignore'] },
  );
} catch (error) {
  raw = error.stdout ?? '';
}
const report = JSON.parse(raw);

/** Which (category/file, rule) pairs did we actually report? */
const reported = new Set();
const flowVerified = new Set();
for (const finding of report.findings) {
  const match = /vulnerabilities[/\\]([^/\\]+)[/\\]source[/\\]([^/\\]+)$/.exec(finding.location.file);
  if (!match) continue;
  const key = `${match[1]}/${match[2]}`;
  reported.add(`${key}::${finding.ruleId}`);
  if (finding.verified) flowVerified.add(`${key}::${finding.ruleId}`);
}

/* ---- score ---- */
let tp = 0;
let fn = 0;
let fp = 0;
let tn = 0;
let provenTp = 0;
const missed = [];
const punishedFixes = [];

for (const [key, { rule, vulnerable }] of expected) {
  const hit = reported.has(`${key}::${rule}`);
  if (vulnerable) {
    if (hit) {
      tp++;
      if (flowVerified.has(`${key}::${rule}`)) provenTp++;
    } else {
      fn++;
      missed.push(`${key}  (${rule})`);
    }
  } else if (hit) {
    fp++;
    punishedFixes.push(`${key}  (${rule}) - this is the FIXED variant`);
  } else {
    tn++;
  }
}

const pct = (n, d) => (d === 0 ? '  n/a' : `${((n / d) * 100).toFixed(1)}%`);

console.log('DVWA - PHP and JavaScript, scored on the categories we implement');
console.log(`  scored files      : ${expected.size}  (${tp + fn} vulnerable, ${fp + tn} fixed)`);
console.log(`  TP ${tp}   FN ${fn}   FP ${fp}   TN ${tn}`);
console.log(`  recall            : ${pct(tp, tp + fn)}   of the vulnerable variants`);
console.log(`  SAMPLE IS SMALL   : ${tp + fn} vulnerable files. BenchmarkJava scores 1,210.`);
console.log(`                      Treat this as a smoke test with ground truth, not a rate.`);
console.log(`  fix respected     : ${pct(tn, tn + fp)}   of impossible.php files stayed quiet`);
console.log(`  of the ${tp} caught : ${provenTp} were flow-verified, ${tp - provenTp} signature-based`);

if (missed.length > 0) {
  console.log(`\n  missed (${missed.length}):`);
  for (const m of missed) console.log(`    - ${m}`);
}
if (punishedFixes.length > 0) {
  console.log(`\n  PUNISHED THE FIX (${punishedFixes.length}) - reported a corrected file:`);
  for (const p of punishedFixes) console.log(`    ! ${p}`);
}
if (skippedEmpty.length > 0) {
  console.log(`\n  skipped - labelled vulnerable but hold no code (${skippedEmpty.length}):`);
  for (const e of skippedEmpty) console.log(`    ${e}`);
}
console.log(`\n  HAVE A RULE, STILL CANNOT SCORE (${MISLABELLED.length}):`);
for (const m of MISLABELLED) console.log(`    ${m}`);
console.log(`\n  not scored (no rule for these): ${UNSCORED.length} categories`);
for (const u of UNSCORED) console.log(`    ${u}`);
