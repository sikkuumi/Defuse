/**
 * THE SCOREBOARD - every app with an answer key, one command, mistakes grouped
 * ============================================================================
 *
 * Finding mistakes one scan at a time was too slow: scan an app, read the
 * findings, find one wrong proof, fix it, repeat. Every fix that mattered was
 * really a fix to a KIND of mistake - "a database read is not the request
 * value", "an address with a fixed start cannot be SSRF" - and each kind showed
 * up in several apps at once. So this scans every practice app that comes with
 * an answer key, checks every finding against its key, and prints the mistakes
 * grouped by cause, biggest group first. Fix the top group, run it again.
 *
 * THE KEYS, and how far to trust each one:
 *
 *   BenchmarkJava  OWASP's expectedresults CSV: a human-written verdict for
 *                  every test case. The strongest key here.
 *   DVWA           scripts/answer-keys/dvwa.json - an AI review of every proof,
 *                  plus DVWA's own layout (impossible.php is the fixed version).
 *   Juice Shop     its own `vuln-code-snippet vuln-line` markers, its coding-
 *                  challenge snippets (`_correct` is the fix), and
 *                  scripts/answer-keys/juice-shop.json for the rest.
 *
 * A proof the key does not cover is listed as "not in the key" - unchecked,
 * not right. A key line that was proven before and is not any more is listed
 * as a LOST proof, because that is a regression whatever its cause.
 *
 * Usage:  npm run scoreboard            (fetch commands are printed for any app missing)
 *         npm run scoreboard -- --json  (the same, as JSON on stdout)
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const asJson = process.argv.includes('--json');
const KEYS = join(root, 'scripts/answer-keys');

/* ------------------------------------------------------------------ apps -- */

const APPS = [
  {
    name: 'BenchmarkJava',
    dir: 'corpus2/BenchmarkJava',
    fetch: 'git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git corpus2/BenchmarkJava',
    score: scoreBenchmark,
  },
  {
    name: 'DVWA',
    dir: 'corpus2/DVWA',
    key: 'dvwa.json',
    fetch: 'git clone https://github.com/digininja/DVWA.git corpus2/DVWA',
    score: scoreDvwa,
  },
  {
    name: 'Juice Shop',
    dir: 'corpus2/juice-shop',
    key: 'juice-shop.json',
    fetch: 'git clone https://github.com/juice-shop/juice-shop.git corpus2/juice-shop',
    score: scoreJuiceShop,
  },
];

/* --------------------------------------------------------------- helpers -- */

function scan(dir) {
  let raw;
  try {
    raw = execFileSync('node', [join(root, 'dist/src/cli.js'), 'scan', '.', '--json', '--fail-on=none'], {
      cwd: dir,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 512,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch (error) {
    raw = error.stdout ?? '';
  }
  return JSON.parse(raw).findings.map((f) => ({ ...f, file: f.location.file.split('\\').join('/') }));
}

const at = (f) => `${f.ruleId} ${f.file}:${f.location.startLine}`;
const proven = (f) => f.confidence === 'flow-verified';

function headCommit(dir) {
  try {
    return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

/** A tally with mistakes attached. Each mistake is one line, filed under a group. */
function board(name) {
  return { app: name, proven: 0, right: 0, wrong: 0, unsure: 0, unkeyed: 0, notes: [], mistakes: [] };
}
const mistake = (b, kind, group, item) => b.mistakes.push({ app: b.app, kind, group, item });

/**
 * Score proofs against keyed entries. Every proof is right, wrong, unsure or
 * not in the key; every keyed "real" line that is no longer proven is a loss.
 */
function scoreAgainstEntries(b, findings, entries, skip = () => false) {
  const byKey = new Map(entries.map((e) => [`${e.rule} ${e.file}:${e.line}`, e]));
  const provenNow = new Set();
  for (const f of findings) {
    if (!proven(f) || skip(f)) continue;
    b.proven++;
    provenNow.add(at(f));
    const e = byKey.get(at(f));
    if (!e) {
      b.unkeyed++;
      mistake(b, 'not in the key', `${f.ruleId} proofs nobody has checked`, at(f));
    } else if (e.verdict === 'real') b.right++;
    else if (e.verdict === 'wrong') {
      b.wrong++;
      mistake(b, 'wrong proof', e.cause ?? 'cause not recorded', at(f));
    } else {
      b.unsure++;
      mistake(b, 'unsure proof', e.cause ?? 'the review could not decide', at(f));
    }
  }
  for (const e of entries) {
    const k = `${e.rule} ${e.file}:${e.line}`;
    if (e.verdict === 'real' && !provenNow.has(k)) {
      const still = findings.find((f) => at(f) === k);
      mistake(b, 'lost proof', still ? 'a real proof is now only "to review"' : 'a real proof is now silent', k);
    }
  }
}

/* ------------------------------------------------------------ BenchmarkJava -- */

function scoreBenchmark(app, findings) {
  const b = board(app.name);
  const csv = readdirSync(app.dir).find((f) => /^expectedresults-.*\.csv$/.test(f));
  if (!csv) {
    b.notes.push('no expectedresults CSV found - nothing to score against');
    return b;
  }
  const CAT = { 'sql-injection': 'sqli', 'command-injection': 'cmdi', xss: 'xss' };
  const expected = new Map();
  for (const line of readFileSync(join(app.dir, csv), 'utf8').split('\n').slice(1)) {
    const [name, category, real] = line.split(',').map((s) => (s ?? '').trim());
    if (name && Object.values(CAT).includes(category)) expected.set(name, { category, real: real === 'true' });
  }
  const cases = new Map(); // test name -> { proven, reported }
  for (const f of findings) {
    const name = /BenchmarkTest\d+/.exec(f.file)?.[0];
    const want = name && expected.get(name);
    if (!want || CAT[f.ruleId] !== want.category) continue;
    const c = cases.get(name) ?? { proven: false, reported: false, rule: f.ruleId };
    c.reported = true;
    if (proven(f)) c.proven = true;
    cases.set(name, c);
  }
  for (const [name, want] of expected) {
    const c = cases.get(name);
    if (c?.proven) {
      b.proven++;
      if (want.real) b.right++;
      else {
        b.wrong++;
        mistake(b, 'wrong proof', `${want.category}: proof in a case the benchmark marks safe`, name);
      }
    } else if (want.real) {
      mistake(
        b,
        c?.reported ? 'not proven' : 'missed',
        c?.reported ? `${want.category}: real, but only "to review"` : `${want.category}: real, and silent`,
        name,
      );
    }
  }
  b.notes.push(`scored ${expected.size} test cases (sqli, cmdi, xss) per case, against ${csv}`);
  return b;
}

/* ------------------------------------------------------------------- DVWA -- */

function scoreDvwa(app, findings, key) {
  const b = board(app.name);
  scoreAgainstEntries(b, findings, key.entries);
  // DVWA's layout: low/medium/high are vulnerable; impossible.php is the fix.
  const CATEGORY_RULE = { sqli: 'sql-injection', sqli_blind: 'sql-injection', exec: 'command-injection', xss_r: 'xss' };
  for (const [category, rule] of Object.entries(CATEGORY_RULE)) {
    for (const level of ['low', 'medium', 'high']) {
      const file = `vulnerabilities/${category}/source/${level}.php`;
      if (!existsSync(join(app.dir, file))) continue;
      const here = findings.filter((f) => f.file === file && f.ruleId === rule);
      if (here.some(proven)) continue;
      mistake(b, here.length > 0 ? 'not proven' : 'missed', `${rule}: DVWA's ${level} level ${here.length > 0 ? 'only "to review"' : 'is silent'}`, file);
    }
  }
  return b;
}

/* ------------------------------------------------------------- Juice Shop -- */

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git' || name === 'dist' || name === 'build') continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, out);
    else if (/\.(ts|js|tsx|jsx|html|yml|yaml)$/.test(name)) out.push(full);
  }
  return out;
}

function scoreJuiceShop(app, findings, key) {
  const b = board(app.name);
  const snippets = board('Juice Shop snippets');
  const isSnippet = (f) => f.file.startsWith('data/static/codefixes/');
  const isTest = (f) => /^test\//.test(f.file) || /\.spec\.ts$/.test(f.file);

  scoreAgainstEntries(b, findings, key.entries, (f) => isSnippet(f) || isTest(f));

  // Coding-challenge snippets: `_correct` is the fix, every other variant is
  // vulnerable by Juice Shop's own answer. Scored apart from the app itself,
  // because the app never runs them.
  for (const f of findings.filter((x) => proven(x) && isSnippet(x))) {
    snippets.proven++;
    if (/_correct\.\w+$/.test(f.file)) {
      snippets.wrong++;
      mistake(snippets, 'wrong proof', 'proof in the FIXED version of a snippet', at(f));
    } else snippets.right++;
  }

  // The vuln-line markers: what Juice Shop itself says is vulnerable.
  let inScope = 0;
  const outOfScope = new Set();
  for (const full of walk(app.dir)) {
    const file = relative(app.dir, full).split('\\').join('/');
    if (file.startsWith('data/static/codefixes/') || file.startsWith('test/')) continue;
    readFileSync(full, 'utf8').split('\n').forEach((text, i) => {
      const m = /vuln-code-snippet vuln-line (.+?)\s*(?:-->|\*\/)?\s*$/.exec(text);
      if (!m) return;
      for (const challenge of m[1].trim().split(/\s+/)) {
        const rule = key.challengeRules[challenge];
        if (!rule) {
          outOfScope.add(challenge);
          continue;
        }
        inScope++;
        const here = findings.filter((f) => f.file === file && f.location.startLine === i + 1 && f.ruleId === rule);
        const where = `${file}:${i + 1} (${challenge})`;
        if (here.length === 0) mistake(b, 'missed', `${rule}: a line Juice Shop marks is silent`, where);
        else if (key.expectProof.includes(challenge) && !here.some(proven)) {
          mistake(b, 'not proven', `${rule}: a marked line is only "to review"`, where);
        }
      }
    });
  }
  b.notes.push(
    `${inScope} marked line/challenge pairs in scope; ${outOfScope.size} marked challenges are kinds of problem ` +
      `Defuse does not check (${[...outOfScope].sort().slice(0, 6).join(', ')}${outOfScope.size > 6 ? ', ...' : ''})`,
  );
  return [b, snippets];
}

/* ------------------------------------------------------------------- main -- */

const boards = [];
const missing = [];
for (const app of APPS) {
  app.dir = join(root, app.dir);
  if (!existsSync(app.dir)) {
    missing.push(`${app.name}: ${app.fetch}`);
    continue;
  }
  const key = app.key ? JSON.parse(readFileSync(join(KEYS, app.key), 'utf8')) : null;
  const commit = headCommit(app.dir);
  const findings = scan(app.dir);
  const result = [app.score(app, findings, key)].flat();
  if (key?.commit && commit !== key.commit) {
    result[0].notes.push(`WARNING: checked out at ${commit.slice(0, 7)}, key written for ${key.commit.slice(0, 7)} - line numbers may not match`);
  }
  boards.push(...result);
}

const mistakes = boards.flatMap((b) => b.mistakes);
const groups = new Map();
for (const m of mistakes) {
  const k = `${m.kind}\u0000${m.app}\u0000${m.group}`;
  if (!groups.has(k)) groups.set(k, { kind: m.kind, app: m.app, group: m.group, items: [] });
  groups.get(k).items.push(m.item);
}
// Wrong and lost proofs first - a false claim outranks a missed one - then by size.
const RANK = { 'wrong proof': 0, 'lost proof': 1, 'unsure proof': 2, 'not in the key': 3, missed: 4, 'not proven': 5 };
const ordered = [...groups.values()].sort((a, b) => RANK[a.kind] - RANK[b.kind] || b.items.length - a.items.length);

if (asJson) {
  console.log(JSON.stringify({ boards: boards.map(({ mistakes: _, ...rest }) => rest), groups: ordered, missing }, null, 1));
} else {
  const pad = (s, n) => String(s).padStart(n);
  console.log('\nDEFUSE SCOREBOARD - proofs checked against answer keys\n');
  console.log(`  ${'app'.padEnd(22)}${pad('proven', 8)}${pad('right', 8)}${pad('wrong', 8)}${pad('unsure', 8)}${pad('no key', 8)}`);
  for (const b of boards) {
    console.log(`  ${b.app.padEnd(22)}${pad(b.proven, 8)}${pad(b.right, 8)}${pad(b.wrong, 8)}${pad(b.unsure, 8)}${pad(b.unkeyed, 8)}`);
  }
  for (const b of boards) for (const n of b.notes) console.log(`  note (${b.app}): ${n}`);
  for (const m of missing) console.log(`  not scanned - fetch it with: ${m}`);
  console.log('\nMISTAKES, GROUPED - false claims first, then biggest group\n');
  for (const g of ordered) {
    console.log(`  ${pad(g.items.length, 4)}  ${g.kind.padEnd(15)} ${g.app.padEnd(20)} ${g.group}`);
    for (const item of g.items.slice(0, 3)) console.log(`        ${item}`);
    if (g.items.length > 3) console.log(`        ... and ${g.items.length - 3} more`);
  }
  console.log('');
}
