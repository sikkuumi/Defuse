/**
 * INSTALL CHECK - does the published package actually run?
 * =======================================================
 *
 * WHY THIS IS AN INSTRUMENT AND NOT A UNIT TEST.
 *
 * Every other check in this project asks whether the ENGINE is right. This one
 * asks whether the thing a stranger downloads is the same program. Those are
 * different questions and only one of them is answered by `npm test`, because
 * the whole class of failure here lives outside the source tree:
 *
 *   - a file the engine needs is not in `files`, so it is missing from the tarball
 *   - `bin` points at a path that does not exist once compiled
 *   - the shebang is absent, so the binary is not executable
 *   - the WASM grammars resolve relative to the repo and not to node_modules
 *   - the tarball ships but the CLI cannot find its own dictionaries
 *
 * None of those can be caught by importing a module in a test that runs inside
 * the repository, because inside the repository everything is present. The only
 * honest test is to build the package, install it somewhere that is not here,
 * run it, and compare.
 *
 * WHAT IT ASSERTS. Not "the CLI exits 0" - a scanner that finds nothing also
 * exits 0. It scans a fixture sample twice, once through the installed binary
 * and once through the local build, and requires the findings to be IDENTICAL:
 * same rules, same lines, same confidence labels, same severities. A packaged
 * scanner that reports differently from the developer's copy is worse than one
 * that fails to start, because it fails quietly.
 *
 * Usage:  npm run install-check
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, mkdirSync, copyFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, encoding: 'utf8', maxBuffer: 1024 * 1024 * 64 });

/** Findings reduced to the facts a user would notice. */
const fingerprint = (json) =>
  JSON.parse(json)
    .findings.map((f) =>
      [
        f.ruleId,
        f.location.file.split(/[/\\]/).pop(),
        f.location.startLine,
        f.confidence,
        f.severity,
      ].join('|'),
    )
    .sort();

const scan = (bin, args, cwd) => {
  // The CLI exits non-zero when it finds something, which is correct for CI.
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

/*
 * A FAILURE HERE IS THE POINT, so it has to read like a finding rather than a
 * stack trace. The first version let npm's exception escape, which meant the
 * two failures this instrument exists to catch - a directory missing from
 * `files`, and `bin` pointing at a path that does not survive compilation -
 * both surfaced as forty lines of node internals. An instrument that cannot
 * say what broke is a crash with extra steps.
 */
const step = (label, fn) => {
  try {
    return fn();
  } catch (error) {
    const detail = (error.stderr || error.stdout || error.message || '')
      .split('\n')
      .filter((l) => l.trim())
      .slice(-3)
      .join('\n      ');
    note(false, `${label} FAILED\n      ${detail}`);
    return null;
  }
};

try {
  console.log('INSTALL CHECK - build a tarball, install it elsewhere, compare the output\n');

  console.log('  building and packing...');
  run('npm', ['run', 'build', '--silent'], root);
  const packed = step('npm pack', () => run('npm', ['pack', '--silent'], root));
  if (packed === null) throw new Error('halt');
  const tarball = packed.trim().split('\n').pop();

  workdir = mkdtempSync(join(tmpdir(), 'defuse-install-'));
  const sample = join(workdir, 'sample');
  mkdirSync(sample, { recursive: true });

  // One file per language, so a grammar that failed to ship is visible.
  const fixtures = join(root, 'tests/fixtures/vulnerable');
  const wanted = ['sqli.js', 'sqli.ts', 'cmdi.py', 'xss.php', 'xss.java', 'taint.go'];
  const present = new Set(readdirSync(fixtures));
  const copied = wanted.filter((f) => present.has(f));
  for (const f of copied) copyFileSync(join(fixtures, f), join(sample, f));

  run('npm', ['init', '-y'], workdir);
  if (step('npm install of the tarball', () =>
        run('npm', ['install', join(root, tarball), '--silent'], workdir)) === null) {
    throw new Error('halt');
  }

  const installed = step('running the installed `defuse` binary', () =>
    scan(['npx', 'defuse'], ['scan', './sample', '--json'], workdir));
  if (installed === null) throw new Error('halt');
  const local = scan(
    ['node', join(root, 'dist/src/cli.js')],
    ['scan', sample, '--json'],
    root,
  );

  const a = fingerprint(installed);
  const b = fingerprint(local);
  const languages = new Set(JSON.parse(installed).findings.map((f) => f.location.file.split('.').pop()));

  note(a.length > 0, `installed binary produced ${a.length} finding(s) on ${copied.length} sample file(s)`);
  note(
    JSON.stringify(a) === JSON.stringify(b),
    `findings identical to the local build (${a.length} vs ${b.length})`,
  );
  note(
    a.some((f) => f.includes('flow-verified')),
    'at least one flow-verified finding survived packaging (the tracer and its dictionaries shipped)',
  );
  note(languages.size >= 3, `findings span ${languages.size} file type(s) - the WASM grammars resolved from node_modules`);

  if (JSON.stringify(a) !== JSON.stringify(b)) {
    console.log('\n  only in the installed package:');
    for (const f of a.filter((x) => !b.includes(x))) console.log(`    + ${f}`);
    console.log('  only in the local build:');
    for (const f of b.filter((x) => !a.includes(x))) console.log(`    - ${f}`);
  }

  console.log(
    problems === 0
      ? '\n  PACKAGE IS INSTALLABLE AND BEHAVES IDENTICALLY\n'
      : `\n  ${problems} PROBLEM(S) - the published package is not the program you tested\n`,
  );
} catch (error) {
  if (error.message !== 'halt') {
    problems++;
    console.log(`  ✗ unexpected: ${error.message}`);
  }
} finally {
  if (workdir) rmSync(workdir, { recursive: true, force: true });
  for (const f of readdirSync(root)) {
    if (/^defuse-.*\.tgz$/.test(f)) rmSync(join(root, f), { force: true });
  }
}

process.exitCode = problems === 0 ? 0 : 1;
