#!/usr/bin/env node
/**
 * THE COMMAND-LINE INTERFACE
 *
 * Hand-rolled argument parsing, no library. It is about 60 lines, you can read
 * all of them, and it means the tool has exactly two runtime dependencies -
 * both of them the parser.
 *
 * Commands:
 *   secureScan scan <path>     scan a file or directory
 *   secureScan ast <file>      print the syntax tree (learning / debugging)
 *   secureScan rules           list the rules and what they do NOT cover
 *   secureScan doctor          check every grammar loads and every query compiles
 *
 * EXIT CODES matter for CI:
 *   0  nothing at or above the --fail-on threshold
 *   1  findings at or above the threshold
 *   2  the tool itself failed (bad arguments, unreadable path, internal error)
 */

import { stat } from 'node:fs/promises';
import path from 'node:path';
import { SEVERITY_ORDER, type Severity } from './core/finding.js';
import { buildCoverageReport } from './core/coverage.js';
import { scan } from './engine/scan.js';
import { SHAPE_QUERY_SOURCES } from './engine/shapes.js';
import { dumpAst } from './parse/astDump.js';
import { detectLanguage, LANGUAGES } from './parse/languages.js';
import { getLanguage, initEngine } from './parse/parser.js';
import { parseFile, useNodeGrammars } from './parse/node-grammars.js';
import { ALL_RULES, validateRegistry } from './rules/registry.js';
import { color, g, setAsciiMode, wrapText } from './report/colors.js';
import { renderHuman } from './report/human.js';
import { renderJson } from './report/json.js';

interface Args {
  readonly command: string;
  readonly positional: readonly string[];
  readonly flags: ReadonlyMap<string, string | true>;
}

/**
 * Flags that TAKE A VALUE, so `--explain xss` works as well as `--explain=xss`.
 *
 * Without this list the parser cannot tell `--explain xss` (one flag with a
 * value) from `--json somefile.js` (a boolean flag followed by a path) - both
 * are "a flag then a word". Every real CLI parser solves it the same way: by
 * being told in advance which flags expect something after them.
 */
const VALUE_FLAGS = new Set([
  'explain',
  'only',
  'exclude',
  'min-severity',
  'fail-on',
  'depth',
  'max-lines',
]);

function parseArgs(argv: readonly string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === undefined) continue;

    if (token.startsWith('--')) {
      const body = token.slice(2);
      const eq = body.indexOf('=');
      if (eq !== -1) {
        flags.set(body.slice(0, eq), body.slice(eq + 1));
        continue;
      }
      // `--explain xss`: consume the next token as this flag's value, but only
      // if it exists and is not itself a flag.
      const next = argv[i + 1];
      if (VALUE_FLAGS.has(body) && next !== undefined && !next.startsWith('-')) {
        flags.set(body, next);
        i++;
        continue;
      }
      flags.set(body, true);
    } else if (token.startsWith('-') && token.length > 1) {
      flags.set(token.slice(1), true);
    } else {
      positional.push(token);
    }
  }

  return { command: positional[0] ?? '', positional: positional.slice(1), flags };
}

function flagString(args: Args, name: string): string | undefined {
  const value = args.flags.get(name);
  return typeof value === 'string' ? value : undefined;
}

const SEVERITIES = new Set(Object.keys(SEVERITY_ORDER));

function parseSeverity(value: string | undefined, fallback: Severity): Severity {
  if (!value) return fallback;
  if (!SEVERITIES.has(value)) {
    throw new Error(`unknown severity '${value}'. Use one of: ${[...SEVERITIES].join(', ')}`);
  }
  return value as Severity;
}

/* ------------------------------------------------------------------ help -- */

function printHelp(): void {
  const b = color.bold;
  console.log(`
${b('NS-1 SecureScan')} — honesty-first static application security testing
${color.dim('Signature matching plus data-flow verification, in all five languages.')}
${color.dim('Flows are followed across functions and, where imports resolve, across files.')}

${b('USAGE')}
  secureScan scan <path> [options]
  secureScan ast <file> [options]
  secureScan rules [--explain <rule-id>]
  secureScan doctor

${b('SCAN OPTIONS')}
  --json                    machine-readable output (superset of the terminal report)
  --compact                 with --json, emit a single line
  --min-severity=<level>    hide findings below this level in the terminal report
                            (they remain in --json).  critical|high|medium|low|info
  --fail-on=<level>         exit code 1 at or above this level. default: high
                            use --fail-on=none to always exit 0
  --only=<ids>              comma-separated rule ids, e.g. --only=sql-injection,xss
  --exclude=<globs>         comma-separated paths to skip. A bare word matches any
                            directory of that name; * and ** work as usual.
                            e.g. --exclude=tests,vendor,**/*.min.js
  --show-suppressed         list findings silenced by securescan:ignore comments
  --coverage-matrix         print the full rule x language support table
  --no-cross-file           do not resolve imports; analyse each file alone.
                            Faster and uses far less memory on huge trees, at
                            the cost of every finding that crosses a module.
  --ascii                   plain ASCII output - no box-drawing characters.
                            Chosen automatically when redirecting on Windows.
  --quiet                   suppress the per-file progress line

${b('AST OPTIONS')}
  --depth=<n>               how deep to print (default 12)
  --anonymous               include punctuation/keyword nodes
  --max-lines=<n>           truncate output (default 400)

${b('EXIT CODES')}
  0  nothing at or above the --fail-on threshold
  1  findings at or above it
  2  the tool failed

${b('THE POINT OF THIS TOOL')}
  Every finding is labelled ${color.yellow('signature-based')} or ${color.green('flow-verified')}.
  ${color.yellow('signature-based')} = we matched a shape. Unverified, may be a false positive.
  ${color.green('flow-verified')}   = we followed attacker data from its source into the sink
                    and print every hop, so you can check the claim yourself.
  The report also lists what was NOT checked. That is the product.
`);
}

/* ------------------------------------------------------------------ scan -- */

async function commandScan(args: Args): Promise<number> {
  const target = args.positional[0];
  if (!target) {
    console.error(color.red('error: scan needs a path.  usage: secureScan scan <path>'));
    return 2;
  }
  /* Extra paths used to be dropped in silence. `scan src ui docs` printed a
   * clean, confident report for `src` and said nothing about the two
   * directories it never opened - a scanner reporting on less than it was
   * asked about, without saying so, which is the one failure mode this whole
   * project is built to avoid. Refuse instead of quietly narrowing. */
  if (args.positional.length > 1) {
    console.error(
      color.red(
        `error: scan takes ONE path, but ${args.positional.length} were given ` +
          `(${args.positional.join(', ')}).`,
      ),
    );
    console.error(
      '       Scan the common parent and narrow with --exclude=<globs>, ' +
        'or run the scans separately.',
    );
    return 2;
  }

  let resolved: string;
  try {
    resolved = path.resolve(target);
    await stat(resolved);
  } catch {
    console.error(color.red(`error: cannot read '${target}'`));
    return 2;
  }

  const asJson = args.flags.has('json');
  const quiet = args.flags.has('quiet') || asJson;
  const only = flagString(args, 'only')?.split(',').map((s) => s.trim()).filter(Boolean) ?? [];

  for (const id of only) {
    if (!ALL_RULES.some((r) => r.id === id)) {
      console.error(
        color.red(`error: unknown rule '${id}'. Known: ${ALL_RULES.map((r) => r.id).join(', ')}`),
      );
      return 2;
    }
  }

  const minSeverity = parseSeverity(flagString(args, 'min-severity'), 'info');
  const failOnRaw = flagString(args, 'fail-on') ?? 'high';
  const failOn = failOnRaw === 'none' ? null : parseSeverity(failOnRaw, 'high');

  const exclude =
    flagString(args, 'exclude')?.split(',').map((s) => s.trim()).filter(Boolean) ?? [];

  const result = await scan(resolved, {
    only,
    exclude,
    noCrossFile: args.flags.has('no-cross-file'),
    ...(quiet
      ? {}
      : {
          onProgress: (done, total, file) => {
            process.stderr.write(
              `\r${color.dim(`scanning ${done}/${total} ${path.basename(file).slice(0, 40)}`.padEnd(70))}`,
            );
          },
        }),
  });

  if (!quiet) process.stderr.write(`\r${' '.repeat(70)}\r`);

  if (asJson) {
    console.log(renderJson(result, !args.flags.has('compact')));
  } else {
    console.log(
      renderHuman(result, {
        showSuppressed: args.flags.has('show-suppressed'),
        showCoverageMatrix: args.flags.has('coverage-matrix'),
        minSeverity,
        target: path.relative(process.cwd(), resolved) || '.',
      }),
    );
  }

  if (!failOn) return 0;
  const triggering = result.findings.filter(
    (f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[failOn],
  );
  return triggering.length > 0 ? 1 : 0;
}

/* ------------------------------------------------------------------- ast -- */

async function commandAst(args: Args): Promise<number> {
  const target = args.positional[0];
  if (!target) {
    console.error(color.red('error: ast needs a file.  usage: secureScan ast <file>'));
    return 2;
  }

  useNodeGrammars();
  const outcome = await parseFile(path.resolve(target));
  if (outcome.status === 'skipped') {
    console.error(color.red(`error: ${outcome.reason}`));
    return 2;
  }

  const file = outcome.file;
  console.log(
    color.dim(
      `${file.path}\n${file.language.displayName} (grammar: ${file.grammar}, detected by ${file.detectedBy})\n`,
    ),
  );
  console.log(
    dumpAst(file.root, {
      includeAnonymous: args.flags.has('anonymous'),
      maxDepth: Number(flagString(args, 'depth') ?? 12),
      maxLines: Number(flagString(args, 'max-lines') ?? 400),
    }),
  );

  if (file.parseIssues.length > 0) {
    console.log(color.yellow(`\n${file.parseIssues.length} parse issue(s):`));
    for (const issue of file.parseIssues) {
      console.log(color.dim(`  ${issue.kind} at ${issue.line}:${issue.column}  ${issue.text}`));
    }
  }
  return 0;
}

/* ----------------------------------------------------------------- rules -- */

function commandRules(args: Args): number {
  const explain = flagString(args, 'explain');

  if (explain) {
    const rule = ALL_RULES.find((r) => r.id === explain);
    if (!rule) {
      console.error(color.red(`error: no rule '${explain}'`));
      return 2;
    }
    console.log(`\n${color.bold(rule.name)}  ${color.dim(`(${rule.id})`)}`);
    console.log(color.dim(`${rule.cwe} · ${rule.owasp} · severity ${rule.severity}\n`));
    console.log(`${color.cyan('The vulnerability')}\n  ${wrapText(rule.explanation, 86, '  ')}\n`);
    console.log(`${color.yellow('What this rule cannot tell you')}\n  ${wrapText(rule.limitations, 86, '  ')}\n`);
    console.log(color.cyan('Per-language support'));
    for (const language of LANGUAGES) {
      const support = rule.support[language.id];
      const status = support?.status ?? 'not-implemented';
      const mark = status === 'implemented' ? color.green(g('dotFull')) : status === 'partial' ? color.yellow(g('dotHalf')) : color.gray(g('dotEmpty'));
      console.log(`  ${mark} ${language.displayName.padEnd(12)} ${color.dim(status)}`);
      console.log(`    ${color.dim(wrapText(support?.note ?? 'no pattern for this language', 82, '    '))}`);
    }
    console.log('');
    return 0;
  }

  const coverage = buildCoverageReport();
  console.log(`\n${color.bold(`${ALL_RULES.length} rules`)} ${color.dim('· run with --explain <id> for the full write-up')}\n`);
  for (const rule of ALL_RULES) {
    const cells = coverage.matrix.filter((c) => c.ruleId === rule.id);
    const marks = cells
      .map((c) =>
        c.status === 'implemented' ? color.green(g('dotFull')) : c.status === 'partial' ? color.yellow(g('dotHalf')) : color.gray('○'),
      )
      .join('');
    console.log(`  ${marks}  ${color.bold(rule.id.padEnd(20))} ${color.dim(`${rule.cwe} · ${rule.severity}`)}`);
    console.log(`         ${color.dim(rule.name)}`);
  }
  console.log(
    color.dim(
      `\n  legend: ${color.green(g('dotFull'))} implemented  ${color.yellow(g('dotHalf'))} partial  ${color.gray(g('dotEmpty'))} not implemented` +
        `\n  columns: ${LANGUAGES.map((l) => l.id).join(' ')}\n`,
    ),
  );
  return 0;
}

/* ---------------------------------------------------------------- doctor -- */

/**
 * A self-check. The nastiest failure a scanner can have is a query with a
 * typo'd node name: it compiles conceptually, matches nothing, and reports a
 * clean scan forever. `doctor` compiles every query against every grammar so
 * that failure is loud instead of silent.
 */
async function commandDoctor(): Promise<number> {
  useNodeGrammars();
  console.log(`\n${color.bold('NS-1 SecureScan self-check')}\n`);
  let failures = 0;

  try {
    validateRegistry();
    console.log(`  ${color.green(g('tick'))} rule registry satisfies the honesty contract`);
  } catch (error) {
    failures++;
    console.log(`  ${color.red(g('cross'))} ${(error as Error).message}`);
  }

  await initEngine();
  const { Query } = await import('web-tree-sitter');

  for (const language of LANGUAGES) {
    const grammars = [language.grammar, ...(language.dialects ?? []).map((d) => d.grammar)];
    for (const grammar of grammars) {
      try {
        const loaded = await getLanguage(grammar);
        for (const kind of ['calls', 'assignments'] as const) {
          new Query(loaded, SHAPE_QUERY_SOURCES[kind][language.id]);
        }
        console.log(
          `  ${color.green(g('tick'))} ${language.displayName.padEnd(12)} grammar '${grammar}' loads; shape queries compile`,
        );
      } catch (error) {
        failures++;
        console.log(
          `  ${color.red(g('cross'))} ${language.displayName.padEnd(12)} grammar '${grammar}': ${(error as Error).message}`,
        );
      }
    }
  }

  // Language detection sanity: every declared extension must map back correctly.
  for (const language of LANGUAGES) {
    const all = [...language.extensions, ...(language.dialects ?? []).flatMap((d) => d.extensions)];
    for (const ext of all) {
      const match = detectLanguage(`example${ext}`);
      if (match?.spec.id !== language.id) {
        failures++;
        console.log(`  ${color.red(g('cross'))} extension ${ext} does not resolve to ${language.id}`);
      }
    }
  }
  if (failures === 0) console.log(`  ${color.green(g('tick'))} all declared extensions resolve to a language`);

  console.log(
    failures === 0
      ? `\n  ${color.green('All checks passed.')}\n`
      : `\n  ${color.red(`${failures} check(s) failed.`)}\n`,
  );
  return failures === 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ main -- */

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.flags.has('ascii')) setAsciiMode(true);

  if (args.flags.has('version') || args.flags.has('v')) {
    console.log(buildCoverageReport().engine.version);
    return 0;
  }
  if (args.command === '' || args.flags.has('help') || args.flags.has('h')) {
    printHelp();
    return args.command === '' ? 2 : 0;
  }

  switch (args.command) {
    case 'scan':
      return commandScan(args);
    case 'ast':
      return commandAst(args);
    case 'rules':
      return commandRules(args);
    case 'doctor':
      return commandDoctor();
    default:
      console.error(color.red(`error: unknown command '${args.command}'`));
      printHelp();
      return 2;
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    console.error(color.red(`\ninternal error: ${(error as Error).message}`));
    if (process.env['NS1_DEBUG']) console.error((error as Error).stack);
    process.exitCode = 2;
  });
