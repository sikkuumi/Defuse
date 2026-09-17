/**
 * IDENTITY CHECK - did a refactor change any answer?
 * ==================================================
 *
 * WHY THIS IS THE NINTH INSTRUMENT.
 *
 * The other eight ask whether the answers are right, or whether the scan can
 * finish. This one asks a narrower and, during a rewrite, more useful question:
 * **are the answers the SAME ones as before I touched anything?**
 *
 * The distinction matters because the eight instruments are summaries. A change
 * can move two findings in opposite directions and leave "precision 59.5%,
 * recall 89.3%" untouched; the benchmark would nod, and a real regression would
 * ship. install-check.mjs makes exactly this argument about the packaged binary
 * ("is the tarball the same program?"). This makes it about the engine.
 *
 * HOW IT WORKS. Scan a fixed list of targets, strip the two fields that are
 * allowed to differ between runs (the timestamp and the duration), hash the
 * rest, and compare against a recorded baseline. Everything else is in scope on
 * purpose - not just findings, but the diagnostic counters underneath them:
 * files parsed, functions indexed, cross-file resolutions made, ambiguities
 * declined. A refactor that produced the same findings by a different route
 * would change those, and that is worth knowing before believing it was
 * behaviour-preserving.
 *
 *   npm run identity -- --record     capture the current behaviour as truth
 *   npm run identity                 assert nothing has moved since
 *
 * RECORDING IS THE DANGEROUS HALF. A baseline recorded after a bug is a bug
 * with a certificate. Record only from a tree whose other instruments you have
 * just run and believed.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE = join(root, 'tests/identity-baseline.json');

const recording = process.argv.includes('--record');
const verbose = process.argv.includes('--verbose');

/**
 * The targets. Chosen to cover each language's tracer, both the cross-file and
 * single-file paths, and one target (BenchmarkJava) big enough that a memory
 * change would show up as a different answer if it broke anything.
 */
const TARGETS = [
  ['fixtures', 'tests/fixtures'],
  ['axios', 'corpus/axios'],
  ['express', 'corpus/express'],
  ['flask', 'corpus/flask'],
  ['gin', 'corpus/gin'],
  ['gson', 'corpus/gson'],
  ['NodeGoat', 'corpus2/NodeGoat'],
  ['Vulnerable-Flask-App', 'corpus2/Vulnerable-Flask-App'],
  ['dvna', 'corpus2/dvna'],
  ['govwa', 'corpus2/govwa'],
  ['BenchmarkJava', 'corpus2/BenchmarkJava'],
  ['dvwa', '/tmp/dvwa'],
];

/**
 * Fields allowed to differ between two runs of the same code on the same input.
 *
 * Kept deliberately short. Every entry here is a place where a real regression
 * could hide, so the list is the thing to argue about, not to grow quietly.
 */
function normalise(report) {
  delete report.scannedAt;
  delete report.target; // absolute path; differs by checkout, not by behaviour
  if (report.diagnostics?.stats) delete report.diagnostics.stats.durationMs;
  // Every finding carries its own wall-clock stamp. Found the hard way: the
  // first comparison this script ever ran reported that 11 of 12 targets had
  // changed, on a tree where nothing had. The clock was the only thing moving.
  for (const finding of report.findings ?? []) delete finding.detectedAt;
  return report;
}

function scan(path) {
  const absolute = path.startsWith('/') ? path : join(root, path);
  if (!existsSync(absolute)) return null;
  // `scan` exits non-zero when it finds something, which is correct for CI and
  // makes execFileSync throw. The output is on the error object either way.
  let stdout;
  try {
    stdout = execFileSync(
      'node',
      ['--max-old-space-size=6144', join(root, 'dist/src/cli.js'), 'scan', absolute, '--json'],
      { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] },
    );
  } catch (error) {
    stdout = error.stdout;
    if (typeof stdout !== 'string' || stdout.length === 0) throw error;
  }
  return normalise(JSON.parse(stdout));
}

const previous = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, 'utf8')) : {};
const current = {};
let checked = 0;
let missing = 0;
let moved = 0;
let reportOnly = 0;

console.log(`IDENTITY CHECK - ${recording ? 'recording baseline' : 'comparing against baseline'}\n`);

for (const [label, path] of TARGETS) {
  const report = scan(path);
  if (!report) {
    console.log(`  ${label.padEnd(22)} SKIPPED (not present)`);
    missing++;
    continue;
  }

  const json = JSON.stringify(report);
  const entry = {
    hash: createHash('sha256').update(json).digest('hex').slice(0, 16),
    /**
     * A second hash over the findings ALONE.
     *
     * The whole-report hash is the strict test, and it is strict about things
     * that are allowed to change on purpose: adding a diagnostic counter moves
     * it. The findings hash does not care about any of that. When a refactor is
     * meant to be invisible, this is the number that has to hold; when the
     * report gains a field, this is what says the engine still agrees with
     * itself. Both are printed because "which one moved" is the diagnosis.
     */
    findingsHash: createHash('sha256')
      .update(JSON.stringify(report.findings ?? []))
      .digest('hex')
      .slice(0, 16),
    // Recorded alongside the hash so a mismatch says WHAT moved, not just that
    // something did. A hash alone sends you back to bisecting by hand.
    total: report.summary.total,
    flowVerified: report.summary.byConfidence['flow-verified'] ?? 0,
    signature: report.summary.byConfidence['signature-based'] ?? 0,
    filesParsed: report.diagnostics.stats.filesParsed,
    functionsIndexed: report.honesty.crossFileResolution.functionsIndexed ?? 0,
    resolved: report.honesty.crossFileResolution.resolved ?? 0,
    ambiguous: report.honesty.crossFileResolution.ambiguous ?? 0,
  };
  current[label] = entry;
  checked++;

  if (recording) {
    console.log(`  ${label.padEnd(22)} ${entry.hash}  ${entry.total} findings`);
    continue;
  }

  const before = previous[label];
  if (!before) {
    console.log(`  ${label.padEnd(22)} NO BASELINE - run with --record`);
    continue;
  }
  if (before.hash === entry.hash) {
    if (verbose) console.log(`  ${label.padEnd(22)} same  (${entry.total} findings)`);
    continue;
  }

  const findingsMoved = before.findingsHash !== entry.findingsHash;
  if (findingsMoved) moved++;
  else reportOnly++;

  console.log(`  ${label.padEnd(22)} ${findingsMoved ? 'FINDINGS CHANGED' : 'report changed, findings identical'}`);
  for (const key of Object.keys(entry)) {
    if (key === 'hash' || key === 'findingsHash') continue;
    if (before[key] !== entry[key]) {
      console.log(`      ${key.padEnd(18)} ${before[key]}  ->  ${entry[key]}`);
    }
  }
  if (findingsMoved && Object.keys(entry).every((k) => k.endsWith('ash') || before[k] === entry[k])) {
    console.log('      counters identical - the difference is inside a finding.');
    console.log('      Diff the two --json outputs directly; a moved line number');
    console.log('      or a changed proof step will not show up in a count.');
  }
}

if (recording) {
  writeFileSync(BASELINE, `${JSON.stringify(current, null, 2)}\n`);
  console.log(`\n  recorded ${checked} targets to tests/identity-baseline.json`);
  console.log('  A baseline recorded after a bug is a bug with a certificate.');
  console.log('  Run the other instruments before trusting this file.\n');
  process.exit(0);
}

console.log(
  `\n  ${checked} targets checked, ${moved} with changed findings` +
    (reportOnly > 0 ? `, ${reportOnly} report-only` : '') +
    (missing > 0 ? `, ${missing} not present` : ''),
);
if (moved === 0) {
  console.log(
    reportOnly === 0
      ? '  Every answer is byte-identical to the baseline.\n'
      : '  Every FINDING is byte-identical to the baseline; only report\n' +
          '  metadata moved. Re-record once you have said why it moved.\n',
  );
  process.exit(0);
}
console.log('\n  A change here is not automatically wrong - but it is never');
console.log('  automatically right either. Say which findings moved and why.\n');
process.exit(1);
