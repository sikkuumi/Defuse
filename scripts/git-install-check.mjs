/**
 * GIT INSTALL CHECK - does `npx github:USER/REPO` actually work?
 * =============================================================
 *
 * WHY THIS IS SEPARATE FROM install-check.mjs.
 *
 * That one packs a tarball with `npm pack` and installs it. This one commits
 * the working tree to a real git repository and installs THAT. They look like
 * the same test and they exercise different halves of the packaging:
 *
 *   npm pack        ships whatever `files` lists, already compiled.
 *   git install     ships whatever is COMMITTED, and compiles it on the user's
 *                   machine by running the `prepare` script.
 *
 * So this is the only check that can catch: a `.gitignore` that excludes
 * something the build needs, a `prepare` script that fails outside the author's
 * environment, a devDependency the compile needs that was moved or dropped, or
 * a `dist/` directory that only works because it was built here and copied.
 *
 * WHY IT MATTERS MORE THAN USUAL RIGHT NOW. An AGPL project that is not on npm
 * is installed one way: straight from the repository. That is the command in
 * the README, so it is the first thing a stranger runs, and the first thing
 * that can fail in front of them.
 *
 * WHAT IT ASSERTS. Not that the install exits 0 - an install can succeed and
 * leave a binary that finds nothing. It scans the same sample through the
 * git-installed binary and through the local build and requires the findings to
 * be IDENTICAL, which is the same bar install-check holds the tarball to.
 *
 * Usage:  npm run git-install-check
 */
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const run = (cmd, args, cwd, env) =>
  execFileSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 64,
    env: { ...process.env, ...env },
  });

const fingerprint = (json) =>
  JSON.parse(json)
    .findings.map((f) =>
      [f.ruleId, f.location.file.split(/[/\\]/).pop(), f.location.startLine, f.confidence].join('|'),
    )
    .sort();

const scan = (bin, args, cwd) => {
  try {
    return run(bin[0], [...bin.slice(1), ...args], cwd);
  } catch (error) {
    if (!error.stdout) throw error;
    return error.stdout;
  }
};

let workdir;
let problems = 0;
const note = (ok, text) => {
  if (!ok) problems++;
  console.log(`  ${ok ? '✓' : '✗'} ${text}`);
};
const step = (label, fn) => {
  try {
    return fn();
  } catch (error) {
    const detail = (error.stderr || error.stdout || error.message || '')
      .split('\n')
      .filter((l) => l.trim())
      .slice(-4)
      .join('\n      ');
    note(false, `${label} FAILED\n      ${detail}`);
    return null;
  }
};

/**
 * Directories never worth copying into the throwaway repository.
 *
 * Not a substitute for .gitignore - `git add -A` below applies the real one,
 * which is the point. This list only keeps the COPY fast: the corpora are a
 * quarter of a gigabyte of other people's source code and copying them to
 * discard them a second later is thirty wasted seconds per run.
 */
const SKIP = new Set(['node_modules', 'dist', 'corpus', 'corpus2', '.git']);

try {
  console.log('GIT INSTALL CHECK - commit the tree, install from git, compare the output\n');

  workdir = mkdtempSync(join(tmpdir(), 'ns1-git-'));
  const repo = join(workdir, 'repo');
  const app = join(workdir, 'app');
  const sample = join(app, 'sample');
  mkdirSync(repo, { recursive: true });
  mkdirSync(sample, { recursive: true });

  console.log('  copying the working tree and committing it...');
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    cpSync(join(root, entry.name), join(repo, entry.name), { recursive: true });
  }

  // `git add -A` applies the project's own .gitignore, so what lands in this
  // commit is exactly what would land in a push. That is the whole idea: the
  // question is whether the REPOSITORY is installable, not whether this
  // directory is.
  if (
    step('creating the throwaway repository', () => {
      run('git', ['init', '-q', '.'], repo);
      run('git', ['add', '-A'], repo);
      run(
        'git',
        ['-c', 'user.email=check@localhost', '-c', 'user.name=install check', 'commit', '-qm', 'release'],
        repo,
      );
    }) === null
  ) {
    throw new Error('halt');
  }

  const tracked = run('git', ['ls-files'], repo).trim().split('\n').filter(Boolean);

  const fixtures = join(root, 'tests/fixtures/vulnerable');
  const wanted = ['sqli.js', 'sqli.ts', 'cmdi.py', 'xss.php', 'xss.java', 'taint.go'];
  const present = new Set(readdirSync(fixtures));
  const copied = wanted.filter((f) => present.has(f));
  mkdirSync(app, { recursive: true });
  for (const f of copied) copyFileSync(join(fixtures, f), join(sample, f));

  run('npm', ['init', '-y'], app);
  console.log('  installing from git (this runs `prepare`, so it compiles)...');
  const installed =
    step('npm install from the git repository', () =>
      // NOT --silent. The output is captured and thrown away on success, so
      // quietening npm buys nothing and costs the only thing that matters when
      // this fails: the compiler error explaining WHY. The first run of this
      // instrument against a deliberately broken .gitignore reported nothing
      // but "Command failed", which is a failure you cannot act on.
      run('npm', ['install', `git+file://${repo}`, '--no-audit', '--no-fund'], app),
    ) !== null;
  if (!installed) throw new Error('halt');

  const output = step('running the git-installed `securescan` binary', () =>
    scan(['npx', 'securescan'], ['scan', './sample', '--json'], app),
  );
  if (output === null) throw new Error('halt');

  const local = scan(['node', join(root, 'dist/src/cli.js')], ['scan', sample, '--json'], root);

  const a = fingerprint(output);
  const b = fingerprint(local);
  const parsed = JSON.parse(output);

  note(
    tracked.length > 0 && tracked.includes('LICENSE') && tracked.some((f) => f.startsWith('src/')),
    `${tracked.length} files committed, including src/ and LICENSE`,
  );
  note(a.length > 0, `git-installed binary produced ${a.length} finding(s) on ${copied.length} sample file(s)`);
  note(
    JSON.stringify(a) === JSON.stringify(b),
    `findings identical to the local build (${a.length} vs ${b.length})`,
  );
  note(
    a.some((f) => f.includes('flow-verified')),
    'at least one flow-verified finding survived a from-source install',
  );
  note(
    parsed.tool.license !== undefined && parsed.tool.license !== 'UNLICENSED',
    `the installed binary reports its licence as ${parsed.tool.license ?? '(nothing)'}`,
  );

  if (JSON.stringify(a) !== JSON.stringify(b)) {
    console.log('\n  only in the git install:');
    for (const f of a.filter((x) => !b.includes(x))) console.log(`    + ${f}`);
    console.log('  only in the local build:');
    for (const f of b.filter((x) => !a.includes(x))) console.log(`    - ${f}`);
  }

  console.log(
    problems === 0
      ? '\n  A CLONE OF THIS REPOSITORY BUILDS AND BEHAVES IDENTICALLY\n'
      : `\n  ${problems} PROBLEM(S) - \`npx github:...\` would not give a stranger this program\n`,
  );
} catch (error) {
  if (error.message !== 'halt') {
    problems++;
    console.log(`  ✗ unexpected: ${error.message}`);
  }
} finally {
  if (workdir) rmSync(workdir, { recursive: true, force: true });
}

process.exitCode = problems === 0 ? 0 : 1;
