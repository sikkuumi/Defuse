/**
 * MEMORY CURVE - how much RAM does a scan cost per byte of source?
 * ================================================================
 *
 * WHY THIS IS THE EIGHTH INSTRUMENT.
 *
 * Every other instrument asks whether the answers are RIGHT. This one asks
 * whether the scan can FINISH, which on a large repository is the prior
 * question: a correct analysis that the operating system kills is not an
 * analysis.
 *
 * The limitation block has carried three measured points for a while -
 * 31MB of source peaking at 2.1GB, 63MB at 4.1GB, 86MB at 5.2GB - written down
 * by hand after somebody watched a scan die. Hand-written numbers in this
 * project have a poor record (see report/coverage-table.ts), and a ceiling
 * nobody re-measures is a ceiling that moves without telling anyone.
 *
 * It moved. Running this instrument is what found the cause - trees that were
 * never freed, and a comment in analyze.ts blaming cross-file tracing for it
 * that a two-line experiment disproved. See src/parse/tree-store.ts.
 *
 * WHAT IT MEASURES. Peak resident set size of a real `scan` child process
 * against increasing slices of real source, and the ratio between them. The
 * scan runs as a subprocess on purpose: the WASM heap this is chasing does not
 * show up usefully in process.memoryUsage() from inside, and peak RSS is what
 * actually gets a process killed.
 *
 * Usage:  npm run memory [path-to-source] [--slices=4]
 */
import { execFileSync, spawn } from 'node:child_process';
import { readdirSync, statSync, mkdtempSync, rmSync, mkdirSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const target = process.argv.find((a) => !a.startsWith('-') && a !== process.argv[0] && a !== process.argv[1])
  ?? join(root, 'corpus2/BenchmarkJava');
const sliceCount = Number(
  (process.argv.find((a) => a.startsWith('--slices=')) ?? '--slices=4').split('=')[1],
);

const EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.java', '.php', '.go']);

/** Every scannable file under a directory, with its size. */
function collect(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      collect(full, out);
    } else if (EXTENSIONS.has(entry.name.slice(entry.name.lastIndexOf('.')))) {
      try {
        out.push({ path: full, bytes: statSync(full).size });
      } catch {
        /* unreadable, skip */
      }
    }
  }
  return out;
}

/**
 * Run a scan as a child process and watch its peak RSS.
 *
 * Sampled rather than reported, because the number that matters is the high
 * water mark the kernel saw, not whatever the process believed about itself
 * when it finished.
 */
function scanPeakRss(dir) {
  return new Promise((resolve) => {
    const child = spawn(
      'node',
      ['--max-old-space-size=6144', join(root, 'dist/src/cli.js'), 'scan', dir, '--json'],
      { stdio: ['ignore', 'ignore', 'ignore'] },
    );
    let peak = 0;
    const sample = setInterval(() => {
      try {
        const rss = Number(
          execFileSync('ps', ['-o', 'rss=', '-p', String(child.pid)], { encoding: 'utf8' }).trim(),
        );
        if (Number.isFinite(rss)) peak = Math.max(peak, rss * 1024);
      } catch {
        /* process gone */
      }
    }, 60);
    const started = Date.now();
    child.on('close', (code, signal) => {
      clearInterval(sample);
      resolve({ peak, ms: Date.now() - started, killed: signal !== null, signal });
    });
  });
}

const mb = (bytes) => (bytes / 1024 / 1024).toFixed(1);

const files = collect(target).sort((a, b) => a.path.localeCompare(b.path));
if (files.length === 0) {
  console.error(`No scannable source under ${target}`);
  process.exit(2);
}
const totalBytes = files.reduce((sum, f) => sum + f.bytes, 0);

console.log('MEMORY CURVE - peak RSS against source size\n');
console.log(`  target : ${target}`);
console.log(`  source : ${files.length} files, ${mb(totalBytes)} MB\n`);
console.log('   files      source        peak RSS      ratio     time');
console.log('  ------  ----------  ------------  ---------  -------');

const rows = [];
for (let slice = 1; slice <= sliceCount; slice++) {
  const take = Math.round((files.length * slice) / sliceCount);
  const subset = files.slice(0, take);
  const bytes = subset.reduce((sum, f) => sum + f.bytes, 0);

  // Copy into a scratch tree so each slice is a self-contained scan target.
  const work = mkdtempSync(join(tmpdir(), 'ns1-mem-'));
  for (const file of subset) {
    const destination = join(work, relative(target, file.path));
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(file.path, destination);
  }

  const { peak, ms, killed, signal } = await scanPeakRss(work);
  rmSync(work, { recursive: true, force: true });

  const ratio = bytes > 0 ? peak / bytes : 0;
  rows.push({ files: take, bytes, peak, ratio, ms, killed });
  console.log(
    `  ${String(take).padStart(6)}  ${(mb(bytes) + ' MB').padStart(10)}  ` +
      `${(mb(peak) + ' MB').padStart(12)}  ${(ratio.toFixed(1) + 'x').padStart(9)}  ` +
      `${((ms / 1000).toFixed(1) + 's').padStart(7)}` +
      (killed ? `  KILLED (${signal})` : ''),
  );
}

/* -------------------------------------------------------------------------- *
 * WHAT THE CEILING ACTUALLY IS - and why the first version of this got it wrong.
 *
 * The original summary divided the budget by the WORST ratio in the table. That
 * ratio is always the smallest slice, and the smallest slice is almost entirely
 * fixed cost - Node itself plus seven WebAssembly grammars, which is ~120-350 MB
 * before a single line of source is read. Dividing by it answers the question
 * "what if the fixed cost were charged per byte", which nothing does.
 *
 * A scan costs a FIXED amount plus a MARGINAL amount per byte, and only the
 * marginal part decides how big a repository can get. Fitting both and reporting
 * them separately turns one misleading number into two useful ones:
 *
 *     peak  =  baseline  +  marginal x source
 *
 * Least squares over every row, so a single noisy sample cannot set the answer.
 * -------------------------------------------------------------------------- */
function fitLine(points) {
  const n = points.length;
  const sumX = points.reduce((s, p) => s + p.x, 0);
  const sumY = points.reduce((s, p) => s + p.y, 0);
  const sumXY = points.reduce((s, p) => s + p.x * p.y, 0);
  const sumXX = points.reduce((s, p) => s + p.x * p.x, 0);
  const denominator = n * sumXX - sumX * sumX;
  if (n < 2 || denominator === 0) return { slope: points[0].y / points[0].x, intercept: 0 };
  const slope = (n * sumXY - sumX * sumY) / denominator;
  return { slope, intercept: (sumY - slope * sumX) / n };
}

const worst = rows.reduce((a, b) => (b.ratio > a.ratio ? b : a), rows[0]);
const { slope: marginal, intercept: baseline } = fitLine(
  rows.map((r) => ({ x: r.bytes, y: r.peak })),
);
const budget = 8 * 1024 * 1024 * 1024; // a typical 8GB laptop
const headroom = budget - Math.max(baseline, 0);
const ceiling = marginal > 0 ? headroom / marginal : Infinity;

const treeBudgetMb = process.env.NS1_TREE_BUDGET_MB;
console.log(
  `\n  tree budget    : ${treeBudgetMb ? `${treeBudgetMb} MB (NS1_TREE_BUDGET_MB)` : 'default'}\n` +
    `  fixed cost     : about ${mb(Math.max(baseline, 0))} MB before any source is read\n` +
    `  marginal cost  : ${marginal.toFixed(1)}x each byte of source\n` +
    `  implied ceiling: about ${(ceiling / 1024 / 1024).toFixed(0)} MB of source on an 8 GB machine\n` +
    `  (worst single-slice ratio was ${worst.ratio.toFixed(1)}x, which is the fixed cost\n` +
    `   charged against a small sample - not a number to plan with.)\n`,
);
console.log('  A scan the operating system kills is not a scan. This number is the');
console.log('  prior question to every accuracy figure in the other instruments.\n');
