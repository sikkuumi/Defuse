/**
 * PROPERTY-BASED TESTING FOR A SCANNER
 * ====================================
 *
 * The fixture suite next door tests cases somebody thought of. That is its
 * strength - a human noticing "an escaped f-string should be RETRACTED, not
 * merely unflagged" is not something scale produces - and it is also its ceiling:
 * it can only ever check what was already imagined.
 *
 * Scanning huge real repositories does not fix that. It gives you volume with no
 * answer key: 2,000 findings on a codebase nobody has labelled tells you the
 * scanner did something, not whether it did the right thing. Ground-truth
 * corpora (OWASP Benchmark) help, but they are one language, one style, and they
 * age.
 *
 * So this file goes the other way. Instead of hunting for code whose answer we
 * know, it GENERATES code whose answer is known BY CONSTRUCTION:
 *
 *     source  ->  a chain of N propagation steps  ->  sink
 *                 with a sanitiser that is absent / matching / wrong-kind
 *
 * Every combination has a verdict that follows from the engine's own stated
 * contract, so a disagreement is a bug in one of the two - and either way it is
 * worth knowing. Four relations are checked:
 *
 *   NO SANITISER      must be flow-verified. Anything less is a miss.
 *   MATCHING SANITISER must be RETRACTED - reported in verifiedClean, not as a
 *                     finding. "Silent" is not good enough: silence is also what
 *                     happens when the sink was never recognised.
 *   WRONG-KIND        must STILL be flow-verified. An HTML escaper does not make
 *                     a value safe for SQL, and a scanner that thinks otherwise
 *                     is the dangerous kind of wrong.
 *   PAST DEPTH LIMIT  must NOT be flow-verified. The limit is documented; this
 *                     checks the documentation is true.
 *
 * Run with: npm run metamorphic
 */

import { analyze } from '../src/core/analyze.js';
import { useNodeGrammars } from '../src/parse/node-grammars.js';
import { color, g } from '../src/report/colors.js';

type Kind = 'sql' | 'command' | 'xss';
type Guard = 'none' | 'matching' | 'wrong-kind' | 'universal';

interface Case {
  readonly name: string;
  readonly files: readonly { path: string; source: string }[];
  readonly expect: 'flow-verified' | 'retracted' | 'not-verified';
  readonly kind: Kind;
}

/* ------------------------------------------------------------------ python */

const PY_SINK: Record<Kind, (v: string) => string> = {
  sql: (v) => `    return conn.execute("SELECT * FROM t WHERE id = " + ${v})`,
  command: (v) => `    return subprocess.run("ping -c 1 " + ${v}, shell=True)`,
  xss: (v) => `    return render_template_string("<h1>" + ${v} + "</h1>")`,
};

/** Which wash actually covers which sink, straight from the dictionaries. */
const PY_GUARD: Record<Kind, string> = {
  sql: 'int',            // covers sql/command/xss
  command: 'shlex.quote',
  xss: 'html.escape',
};
/** A wash for a DIFFERENT kind - must not be credited. */
const PY_WRONG: Record<Kind, string> = {
  sql: 'html.escape',
  command: 'html.escape',
  xss: 'shlex.quote',
};

function pythonCase(kind: Kind, steps: number, guard: Guard): Case {
  const lines = [
    'import subprocess, shlex, html, sqlite3',
    'from flask import request, render_template_string',
    '',
    'def handler(request, conn):',
    '    v0 = request.args.get("id")',
  ];
  let v = 'v0';
  for (let i = 1; i <= steps; i += 1) {
    const next = `v${i}`;
    const form = i % 3;
    if (form === 0) lines.push(`    ${next} = ${v}`);
    else if (form === 1) lines.push(`    ${next} = "p" + ${v}`);
    else lines.push(`    ${next} = f"{${v}}"`);
    v = next;
  }
  if (guard === 'matching') lines.push(`    ${v} = ${PY_GUARD[kind]}(${v})`);
  if (guard === 'universal') lines.push(`    ${v} = int(${v})`);
  if (guard === 'wrong-kind') lines.push(`    ${v} = ${PY_WRONG[kind]}(${v})`);
  lines.push(PY_SINK[kind](v));

  return {
    name: `py/${kind}/steps=${steps}/guard=${guard}`,
    files: [{ path: `gen_py_${kind}_${steps}_${guard}.py`, source: lines.join('\n') + '\n' }],
    expect: guard === 'matching' || guard === 'universal' ? 'retracted' : 'flow-verified',
    kind,
  };
}

/* -------------------------------------------------------------- javascript */

const JS_SINK: Record<Kind, (v: string) => string> = {
  sql: (v) => `  return db.query("SELECT * FROM t WHERE id = " + ${v});`,
  command: (v) => `  return exec("ping -c 1 " + ${v});`,
  xss: (v) => `  return document.write("<h1>" + ${v} + "</h1>");`,
};
const JS_GUARD: Record<Kind, string> = {
  sql: 'parseInt',
  command: 'shellQuote',
  xss: 'escapeHtml',
};
const JS_WRONG: Record<Kind, string> = {
  sql: 'escapeHtml',
  command: 'escapeHtml',
  xss: 'shellQuote',
};

function jsCase(kind: Kind, steps: number, guard: Guard): Case {
  const lines = ['function handler(req, db) {', '  const v0 = req.query.id;'];
  let v = 'v0';
  for (let i = 1; i <= steps; i += 1) {
    const next = `v${i}`;
    const form = i % 3;
    if (form === 0) lines.push(`  const ${next} = ${v};`);
    else if (form === 1) lines.push(`  const ${next} = "p" + ${v};`);
    else lines.push(`  const ${next} = \`\${${v}}\`;`);
    v = next;
  }
  let final = v;
  if (guard === 'matching') { lines.push(`  const w = ${JS_GUARD[kind]}(${v});`); final = 'w'; }
  if (guard === 'universal') { lines.push(`  const w = parseInt(${v}, 10);`); final = 'w'; }
  if (guard === 'wrong-kind') { lines.push(`  const w = ${JS_WRONG[kind]}(${v});`); final = 'w'; }
  lines.push(JS_SINK[kind](final), '}');

  return {
    name: `js/${kind}/steps=${steps}/guard=${guard}`,
    files: [{ path: `gen_js_${kind}_${steps}_${guard}.js`, source: lines.join('\n') + '\n' }],
    expect: guard === 'matching' || guard === 'universal' ? 'retracted' : 'flow-verified',
    kind,
  };
}

/* ------------------------------------------------- the documented depth cap */

/**
 * Genuinely NESTED calls, not a sequence of them. `MAX_CALL_DEPTH` is 4, and the
 * capability block says chains deeper than that are not followed - so at depth 6
 * the flow must NOT come back verified. If it does, the limit is a fiction.
 */
function depthCase(depth: number): Case {
  const lines = ['import sqlite3', 'from flask import request', ''];
  for (let i = 1; i <= depth; i += 1) {
    lines.push(`def s${i}(x): return ${i === depth ? 'x' : `s${i + 1}(x)`}`);
  }
  lines.push('', 'def handler(request, conn):', '    v = s1(request.args.get("id"))',
    '    return conn.execute("SELECT * FROM t WHERE id = " + v)');
  return {
    name: `py/depth=${depth}`,
    files: [{ path: `gen_depth_${depth}.py`, source: lines.join('\n') + '\n' }],
    expect: depth <= 4 ? 'flow-verified' : 'not-verified',
    kind: 'sql',
  };
}

/* ---------------------------------------------------------------- the runner */

function build(): Case[] {
  const cases: Case[] = [];
  const kinds: Kind[] = ['sql', 'command', 'xss'];
  const guards: Guard[] = ['none', 'matching', 'wrong-kind', 'universal'];
  for (const kind of kinds) {
    for (let steps = 0; steps <= 6; steps += 1) {
      for (const guard of guards) {
        cases.push(pythonCase(kind, steps, guard));
        cases.push(jsCase(kind, steps, guard));
      }
    }
  }
  for (let depth = 1; depth <= 7; depth += 1) cases.push(depthCase(depth));
  return cases;
}

async function main(): Promise<number> {
  useNodeGrammars();
  const cases = build();
  console.log(`\n${color.bold('NS-1 SecureScan — property-based (metamorphic) suite')}`);
  console.log(color.dim(`${cases.length} generated programs, each with a verdict known by construction\n`));

  const failures: { name: string; want: string; got: string }[] = [];
  const byRelation = new Map<string, { pass: number; fail: number }>();

  for (const testCase of cases) {
    const result = await analyze(testCase.files);
    const rule = { sql: 'sql-injection', command: 'command-injection', xss: 'xss' }[testCase.kind];
    const verified = result.findings.some(
      (f) => f.ruleId === rule && f.confidence === 'flow-verified',
    );
    const retracted = result.verifiedClean.some((c) => c.ruleId === rule);

    const got = verified ? 'flow-verified' : retracted ? 'retracted' : 'not-verified';
    const ok = got === testCase.expect;

    const relation = testCase.name.includes('depth=')
      ? 'depth limit'
      : `guard=${testCase.name.split('guard=')[1]}`;
    const tally = byRelation.get(relation) ?? { pass: 0, fail: 0 };
    tally[ok ? 'pass' : 'fail'] += 1;
    byRelation.set(relation, tally);

    if (!ok) failures.push({ name: testCase.name, want: testCase.expect, got });
  }

  for (const [relation, tally] of [...byRelation.entries()].sort()) {
    const total = tally.pass + tally.fail;
    const mark = tally.fail === 0 ? color.green(g('tick')) : color.red(g('cross'));
    console.log(`  ${mark} ${relation.padEnd(18)} ${tally.pass}/${total}`);
  }

  if (failures.length > 0) {
    console.log(`\n${color.bold('  Disagreements')} ${color.dim('(generated expectation vs engine)')}`);
    for (const f of failures.slice(0, 25)) {
      console.log(`    ${color.red(g('cross'))} ${f.name.padEnd(34)} want ${f.want}, got ${color.yellow(f.got)}`);
    }
    if (failures.length > 25) console.log(color.dim(`    ... and ${failures.length - 25} more`));
  }

  const passed = cases.length - failures.length;
  console.log(
    `\n  ${failures.length === 0
      ? color.green(color.bold(`ALL ${cases.length} GENERATED CASES AGREE`))
      : color.red(color.bold(`${failures.length} of ${cases.length} DISAGREE`))}\n`,
  );
  void passed;
  return failures.length === 0 ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
