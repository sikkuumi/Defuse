/**
 * HUMAN-READABLE REPORT
 *
 * Design brief: someone should be able to skim this in a terminal and know
 * three things without reading carefully -
 *   1. where the problem is,
 *   2. how bad it would be,
 *   3. HOW SURE WE ARE.
 *
 * Point 3 is the one other tools bury. It gets its own column here, on every
 * single line, and it gets a summary block that states the count of unverified
 * findings in plain words. If this report ever looks more confident than the
 * engine is, the report is wrong.
 */

import { SEVERITY_ORDER, type Finding, type FlowStep, type Severity } from '../core/finding.js';
import type { CoverageReport } from '../core/coverage.js';
import { scoreAnalysis } from '../core/score.js';
import type { ScanResult } from '../engine/scan.js';
import { RUNTIME_VERSION_RULE } from '../platform/runtime-version.js';
import { getRule } from '../rules/registry.js';
import { color, g, wrapText } from './colors.js';

const WIDTH = 92;

const SEVERITY_STYLE: Record<Severity, (text: string) => string> = {
  critical: (t) => color.bold(color.red(t)),
  high: (t) => color.red(t),
  medium: (t) => color.yellow(t),
  low: (t) => color.blue(t),
  info: (t) => color.gray(t),
};

function severityLabel(severity: Severity): string {
  return SEVERITY_STYLE[severity](severity.toUpperCase().padEnd(8));
}

function heading(title: string): string {
  const line = g('rule').repeat(Math.max(0, WIDTH - title.length - 3));
  return color.dim(`\n${g('rule')}${g('rule')} ${color.bold(title)} ${line}`);
}

export interface HumanReportOptions {
  readonly showSuppressed?: boolean;
  readonly showCoverageMatrix?: boolean;
  readonly minSeverity?: Severity;
  /**
   * Print everything: the gauge arithmetic, each finding's reasoning and
   * limits, OWASP and the full "not checked" list. Off by default because a
   * first-time tester read 200 lines for one finding and called it
   * overwhelming. Nothing is dropped - the short report names every gap in a
   * line and points here, and --json and --report always carry all of it.
   */
  readonly full?: boolean;
  /**
   * What the scan was actually pointed at, as resolved from the command line.
   *
   * This is here because of a real misread. `npm run scan --exclude tests`
   * looks like "scan everything except tests"; npm swallows `--exclude` as one
   * of its own config flags and forwards only `tests`, so the tool scanned the
   * fixture folder and NOTHING else. The report was correct - 75 findings in
   * files written to be vulnerable - and completely misleading, because the one
   * fact that would have explained it was the one fact not printed.
   *
   * A report that says how much it examined but never says WHAT is describing a
   * measurement without its units.
   */
  readonly target?: string;
}

/** Directory names that mean "these findings are probably meant to be here". */
const FIXTURE_DIRECTORY = /(^|[/\\])(tests?|fixtures?|specs?|__tests__|testdata|examples?)([/\\]|$)/i;

export function renderHuman(result: ScanResult, options: HumanReportOptions = {}): string {
  const out: string[] = [];
  const min = options.minSeverity ? SEVERITY_ORDER[options.minSeverity] : -1;
  const shown = result.findings.filter((f) => SEVERITY_ORDER[f.severity] >= min);
  const hiddenBySeverity = result.findings.length - shown.length;

  /* ---------------- header ---------------- */
  out.push('');
  out.push(
    `${color.bold('Defuse')} ${color.dim(`v${result.coverage.engine.version}`)}  ` +
      color.bgYellow(color.bold(` ${result.coverage.engine.analysisLabel} `)),
  );
  out.push(color.dim(`  target: ${result.target}`));

  /* ---------------- gauges ----------------
   * Same module the browser calls, so the terminal cannot show a different
   * number from the web page for the same scan. Rendered as bars rather than
   * dials for obvious reasons, but the READING is identical.               */
  const score = scoreAnalysis(result, result.stats.filesFound);
  const full = options.full ?? false;
  const present = Object.keys(result.byLanguage).sort();
  out.push(heading('Summary'));
  if (!score.examinedNothing) {
    /*
     * Plain sentences first. The gauges below are exact but a tester read
     * "82%/100%" next to "64%" next to "mean of 2 measured ratios" and could
     * not say what any of them meant. These lines use the same counts and say
     * them in words; --full keeps the arithmetic.
     */
    const flowCount = result.findings.filter((f) => f.confidence === 'flow-verified').length;
    const guessCount = result.findings.length - flowCount;
    out.push(
      `  ${color.red('proven  ')}  ${color.bold(String(flowCount))}  ` +
        color.dim('attacker input was traced into a dangerous call - every step is printed'),
    );
    out.push(
      `  ${color.yellow('possible')}  ${color.bold(String(guessCount))}  ` +
        color.dim('risky-looking code, but the input was not traced - check these by hand'),
    );
    out.push(
      `  ${'read'.padEnd(8)}  ${result.stats.filesParsed} of ` +
        `${result.stats.filesFound || result.stats.filesParsed} file(s)`,
    );
    for (const id of present) {
      const cells = result.coverage.matrix.filter((c) => c.language === id);
      const count = (s: string) => cells.filter((c) => c.status === s).length;
      const deep = result.coverage.taint.find((t) => t.language === id)?.implemented ?? false;
      out.push(
        `  ${'checked'.padEnd(8)}  ${id}: ${count('implemented')} of ${cells.length} bug types fully, ` +
          `${count('partial')} partly, ${count('not-implemented')} not at all` +
          color.dim(deep ? ' - with data-flow tracing' : ' - pattern matching only, no data-flow tracing'),
      );
    }
  }
  if (full && !score.examinedNothing) out.push(heading('Readings'));
  if (score.examinedNothing) {
    // Printed INSTEAD of the dials, not above them. Zeroes shown next to this
    // warning would still be read as zeroes.
    out.push(
      `  ${color.yellow(color.bold('NO READING.'))} ` +
        color.dim(
          wrapText(
            'The files parsed, but not one statement, call or assignment reached a ' +
              'rule - there was no code here to analyse. Every number below would be ' +
              'the absence of a result, not a result, so they are withheld. Check you ' +
              'pointed the scan at the right path.',
            WIDTH - 4,
            '  ',
          ),
        ),
    );
  } else if (full) {
    for (const reading of score.gauges) {
      const filled = Math.round((reading.value / reading.max) * 28);
      const bar = `${g('dotFull').repeat(filled)}${g('dotEmpty').repeat(28 - filled)}`;
      const tone =
        reading.id === 'verified-exposure'
          ? color.red
          : reading.id === 'unverified-surface'
            ? color.yellow
            : color.green;
      out.push(
      `  ${reading.label.padEnd(20)} ${tone(bar)} ` +
        `${color.bold(String(reading.value) + reading.unit)}${color.dim(`/${reading.max}${reading.unit}`)}` +
        (reading.capped ? color.yellow(`  PINNED - real total ${reading.rawTotal}`) : ''),
      );
      out.push(color.dim(`  ${' '.repeat(20)} ${reading.working.join('  ' + g('middot') + '  ')}`));
    }
  }
  if (full && !score.examinedNothing) {
    out.push('');
    out.push(
    color.dim(
      `  ${wrapText(
        'These three are never added together. Severity and confidence are ' +
          'different questions, and a single blended risk number cannot answer ' +
          'either one. Coverage tells you how much weight the other two carry.',
        WIDTH - 4,
        '  ',
      )}`,
    ),
    );
  }
  /*
   * SOURCES RECOGNISED - printed whatever the number, and loudest at zero.
   *
   * A scan that found no sources cannot produce a traced finding no matter how
   * good the tracer is, and "0 flow-verified" reads like a clean bill until you
   * know that. Elasticsearch's 3,999 Java files produced exactly this shape.
   */
  out.push('');
  if (score.sourcesFound === 0 && result.stats.filesParsed >= 25) {
    out.push(
      color.yellow(
        `  No attacker-controlled sources were recognised in ${result.stats.filesParsed} files.`,
      ),
    );
    out.push(
      color.dim(
        `    Every flow-verified finding starts at a source, so none could be produced here.`,
      ),
    );
    out.push(
      color.dim(
        `    Either this code takes no external input, or it uses a framework we do not`,
      ),
    );
    out.push(
      color.dim(
        `    model - sources are per-framework, and only the ones listed in the coverage`,
      ),
    );
    out.push(color.dim(`    section are recognised. Read "0 proven" as "could not begin".`));
  } else {
    out.push(
      color.dim(
        `  ${score.sourcesFound} attacker-controlled source(s) recognised - every traced finding starts at one of these.`,
      ),
    );
  }
  if (score.blindSpots.length > 0) {
    out.push('');
    out.push(color.dim(`  Where this scan stopped early:`));
    for (const spot of score.blindSpots) {
      out.push(color.dim(`    ${g('middot')} ${spot.count} ${spot.label}`));
    }
  }

  /* ---------------- findings ---------------- */
  if (shown.length === 0) {
    out.push(heading('Findings'));
    out.push(`  ${color.green('No findings from the rules that ran.')}`);
    out.push(
      color.dim(
        `  ${wrapText(
          'This is NOT a clean bill of health. It means the checks listed under ' +
            '"What this scan did not check" were not triggered. Read that section.',
          WIDTH - 4,
          '  ',
        )}`,
      ),
    );
  } else {
    out.push(heading(`Findings (${shown.length})`));
    let lastFile = '';
    for (const finding of shown) {
      if (finding.location.file !== lastFile) {
        lastFile = finding.location.file;
        out.push(`\n  ${color.underline(color.cyan(lastFile))}`);
      }
      out.push(renderFinding(finding, full));
    }
  }

  /* ---------------- the honesty block ----------------
   * The short report states both counts, with their meanings, in the summary
   * at the top; this block is the long form. */
  if (full) {
  out.push(heading('Confidence'));
  const signature = result.findings.filter((f) => f.confidence === 'signature-based').length;
  const flow = result.findings.filter((f) => f.confidence === 'flow-verified').length;
  out.push(
    `  ${color.yellow('signature-based')}  ${String(signature).padStart(4)}  ` +
      color.dim('pattern matched in the syntax tree; data flow NOT traced'),
  );
  out.push(
    `  ${color.green('flow-verified')}    ${String(flow).padStart(4)}  ` +
      color.dim('attacker data traced into the sink; every hop shown above'),
  );
  out.push('');
  out.push(
    `  ${wrapText(
      result.findings.length === 0
        ? score.examinedNothing
          ? 'Both counts are zero because nothing was analysed, not because nothing ' +
            'was found. A file that parses but contains no code produces exactly this ' +
            'output, and it means the scan had no subject - not that the subject is clean.'
          : `Nothing matched, out of ${result.stats.shapesExamined} code shape(s) actually ` +
            'examined. That is a real result rather than an empty one - but it covers only ' +
            'the rules that ran, listed under "What this scan did not check".'
        : flow > 0
        ? `${flow} finding(s) were confirmed by following the data itself - each one prints the ` +
            'full path so you can check it. The signature-based ones are pattern matches the ' +
            'tracer could NOT confirm: it does not resolve imports, so a value arriving from ' +
            'another file ends the trace, and a real bug can easily sit in that group. ' +
            'Unconfirmed is not the same as harmless.'
        : 'Every finding above is an unverified pattern match. The data-flow engine ran but ' +
            'could not confirm any of them - most often because the value arrives from another ' +
            'file, or from a source the dictionaries do not recognise. Treat them as leads.',
      WIDTH - 4,
      '  ',
    )}`,
  );

  /* ---------------- analysis depth, by language ----------------
   * Stated POSITIVELY, and only for languages actually in this scan.
   *
   * Two testers in a row wrote fixtures asserting "Go is signature-only, so a
   * flow-verified Go finding would be an overclaim" - and both were reading a
   * scope note that had been true months earlier. Nothing in the output
   * contradicted them, because the report only ever listed languages where
   * taint is MISSING. With every language implemented that list is empty, so the
   * report said nothing at all and left the reader's stale belief standing.
   *
   * A capability you only mention in the negative is one nobody can confirm.
   * The short report says it per language on the summary's "checked" lines. */
  if (present.length > 0) {
    out.push(heading('Analysis depth in this scan'));
    for (const id of present) {
      const cell = result.coverage.taint.find((t) => t.language === id);
      const deep = cell?.implemented ?? false;
      out.push(
        `  ${id.padEnd(12)} ${
          deep
            ? color.green('signature + data flow')
            : color.yellow('signature only - no flow verification in this language')
        }  ${color.dim(`${result.byLanguage[id]} file(s)`)}`,
      );
    }
    out.push('');
    out.push(
      color.dim(
        `  ${wrapText(
          'A flow-verified finding can only come from a language on the "signature + data ' +
            'flow" line. Where it says signature only, zero verified findings means the ' +
            'tracer never ran there - not that the code is clean.',
          WIDTH - 4,
          '  ',
        )}`,
      ),
    );
  }

  /* ---------------- OWASP coverage, all ten ----------------
   * Printed in full, both states, because the previous version printed only
   * the missing ones - and a list of seven gaps invites the reader to assume
   * the other three are handled. None of them is. See the note in coverage.ts. */
  const owasp = result.coverage.owaspCoverage;
  const none = owasp.filter((c) => c.state === 'none');
  out.push(heading(`OWASP Top 10 (2025) - ${none.length} of 10 have no rule at all`));
  out.push(
    color.dim(
      `  ${wrapText(
        'No category here is comprehensively covered - the three with rules are checked ' +
          'in part only, and what they leave out is named. Silence in a category with no ' +
          'rule is not a result: code full of those bugs looks exactly like code without.',
        WIDTH - 4,
        '  ',
      )}`,
    ),
  );
  out.push('');
  for (const category of owasp) {
    const mark =
      category.state === 'partial' ? color.yellow('PARTIAL') : color.red('NO RULE');
    out.push(`  ${mark}  ${color.bold(category.id)} ${category.title}`);
    if (category.weCheck) {
      out.push(color.dim(`           we check   ${category.weCheck} (${category.rules.join(', ')})`));
    }
    out.push(color.dim(`           ${category.state === 'partial' ? 'in scope  ' : 'e.g.      '}${wrapText(category.examples, WIDTH - 22, '                     ')}`));
    if (category.note) {
      out.push(color.dim(`           why       ${wrapText(category.note, WIDTH - 22, '                     ')}`));
    }
  }
  }

  /* ---------------- coverage / gaps ----------------
   * The short form still names every gap - by count, in plain words - so a
   * quiet scan can never read as a clean one. It only leaves out the list. */
  if (full || options.showCoverageMatrix) {
    out.push(renderCoverage(result.coverage, options.showCoverageMatrix ?? false));
  } else {
    const owaspNone = result.coverage.owaspCoverage.filter((c) => c.state === 'none').length;
    const here = result.coverage.gaps.filter((c) => present.includes(c.language));
    const partly = here.filter((c) => c.status === 'partial').length;
    const notAtAll = here.length - partly;
    out.push(heading('What this scan did NOT check'));
    out.push(
      `  ${wrapText(
        `OWASP Top 10: ${owaspNone} of 10 categories have no rule at all, and the other ` +
          `${10 - owaspNone} are checked only in part.` +
          (present.length > 0
            ? ` For the language(s) in this scan, ${notAtAll} rule/language pair(s) are not ` +
              `checked and ${partly} only partly.`
            : '') +
          ` The engine has ${result.coverage.engine.notImplemented.length} known limits. ` +
          'No findings means these rules found nothing - not that the code is safe.',
        WIDTH - 4,
        '  ',
      )}`,
    );
  }

  /* ---------------- scan health ---------------- */
  out.push(heading('Scan'));
  const bySeverity = countBySeverity(result.findings);
  if (options.target) {
    out.push(`  target ${color.bold(options.target)}`);
    if (FIXTURE_DIRECTORY.test(options.target)) {
      out.push(
        color.dim(
          '  NOTE: that path looks like a test, fixture or example folder. Files there are' +
            '\n        often deliberately vulnerable, so findings in them are expected rather' +
            "\n        than actionable. If you meant to skip them, the flag is attached with an" +
            '\n        equals sign and needs a path of its own:  scan . --exclude=tests' +
            '\n        (via npm, put it after a bare --:  npm run scan -- . --exclude=tests)',
        ),
      );
    }
  }
  out.push(
    `  files parsed ${color.bold(String(result.stats.filesParsed))}` +
      `   code shapes examined ${color.bold(String(result.stats.shapesExamined))}` +
      `   time ${color.bold(`${result.stats.durationMs}ms`)}`,
  );
  if (result.crossFile.enabled) {
    out.push(
      color.dim(
        `  cross-file: ${result.crossFile.importEdges} import edge(s) resolved ${g('middot')} ` +
          `${result.crossFile.resolved} call(s) followed into another file ${g('middot')} ` +
          `${result.crossFile.ambiguous} declined as ambiguous` +
          (result.crossFile.importsUnresolved > 0
            ? ` ${g('middot')} ${result.crossFile.importsUnresolved} import(s) pointed outside the scan`
            : ''),
      ),
    );
    /*
     * "NOTHING FOUND" AND "NOWHERE TO LOOK" ARE DIFFERENT ANSWERS.
     *
     * Someone scanned juice-shop's server.ts on its own - one file, 117 import
     * statements, every one of them pointing at a route file that was not in
     * the scan. The tool parsed it, examined 834 shapes, found 8 sources, and
     * reported nothing, which is CORRECT: server.ts is wiring, and the bugs are
     * in the files it imports. Scanning that repository's routes/ directory
     * finds seven, two flow-verified.
     *
     * The evidence was already in the report - `importEdges 0` - and it said
     * nothing about what that meant. A beginner read an empty findings list as
     * a clean bill of health, then as a broken tool. Both readings were the
     * report's fault, not theirs.
     *
     * This project prints what `--exclude` skipped for exactly this reason. An
     * import that led nowhere is the same kind of hole: a place the analysis
     * did not go, which the reader cannot see from the findings list.
     */
    if (result.crossFile.importEdges === 0 && result.crossFile.importsUnresolved >= 3) {
      out.push('');
      out.push(
        color.yellow(
          `  ${g('warn')} SCOPE WARNING: every one of the ${result.crossFile.importsUnresolved} ` +
            `local import(s) in this scan pointed at a file that was not included.`,
        ),
      );
      out.push(
        color.yellow(
          '     Nothing could be traced across a module boundary, so a quiet result here means',
        ),
      );
      out.push(
        color.yellow(
          '     "not looked at", not "not vulnerable". Point the scan at the project directory',
        ),
      );
      out.push(color.yellow('     rather than a single file if you meant to analyse the whole thing.'));
    }
  } else {
    out.push(color.yellow(`  cross-file analysis OFF (${result.crossFile.reason})`));
  }

  /**
   * Say when the scan traded time for memory.
   *
   * A scan that spills gives exactly the same answers, just more slowly - the
   * findings are checked to be byte-identical under a budget small enough to
   * evict almost everything. But "slow" with no explanation is the kind of
   * thing a user blames the tool for and never mentions, so the report says
   * which of the two things happened and what to change.
   */
  if (result.treeMemory.reparses > 0) {
    out.push(
      color.dim(
        `  memory: project larger than the ${(result.treeMemory.budgetBytes / 1048576).toFixed(0)}MB ` +
          `tree budget, so ${result.treeMemory.reparses} file(s) were parsed more than once. ` +
          `Same answers, slower scan - raise DEFUSE_TREE_BUDGET_MB to trade memory back for speed.`,
      ),
    );
  }
  // Cleared lines whose receipt rests on a function Defuse does not model.
  const onTrust = result.verifiedClean.filter((c) => (c.assumes?.length ?? 0) > 0).length;
  if (
    result.stats.flowsVerified > 0 ||
    result.stats.signaturesRetracted > 0 ||
    result.stats.signaturesProvedConstant > 0 ||
    result.stats.regionsProvedUnreachable > 0 ||
    result.stats.collectionReadsResolved > 0 ||
    result.stats.tracesStoppedAtNewData > 0
  ) {
    out.push(
      color.dim(
        `  data flow: ${result.stats.flowsVerified} verified ${g('middot')} ` +
          `${result.stats.signaturesUpgraded} guess(es) superseded by a proof ${g('middot')} ` +
          `${result.stats.signaturesRetracted} withdrawn as provably sanitised` +
          (onTrust > 0
            ? ` ${g('middot')} ${onTrust} cleared line(s) rest on a function Defuse does not model, taken to hand back ` +
              `what it was given (listed in --json under verifiedClean[].assumes)`
            : '') +
          (result.stats.signaturesProvedConstant > 0
            ? ` ${g('middot')} ${result.stats.signaturesProvedConstant} withdrawn as provably ` +
              `constant (listed in --json under verifiedClean, with the reason)`
            : '') +
          (result.stats.regionsProvedUnreachable > 0
            ? ` ${g('middot')} ${result.stats.regionsProvedUnreachable} branch(es) or case(s) not ` +
              `followed because a fixed condition means they cannot run (listed in --json under ` +
              `unreachableCodeSkipped)`
            : '') +
          (result.stats.collectionReadsResolved > 0
            ? ` ${g('middot')} ${result.stats.collectionReadsResolved} collection read(s) answered by key or position ` +
              `(listed in --json under collectionReadsResolved)`
            : '') +
          (result.stats.tracesStoppedAtNewData > 0
            ? ` ${g('middot')} ${result.stats.tracesStoppedAtNewData} trace(s) ended at a database or file read, ` +
              `which returns stored data rather than its input - not cleared, just not followed ` +
              `(listed in --json under tracesStoppedAtNewData)`
            : ''),
      ),
    );
  }
  const languageSummary = Object.entries(result.byLanguage)
    .map(([lang, count]) => `${lang} ${count}`)
    .join('  ');
  if (languageSummary) out.push(color.dim(`  languages: ${languageSummary}`));
  /*
   * Which PHP the project declares. Printed even when every declaration is
   * fine, because "no runtime finding" means something only if the reader can
   * see what was read - and printed as a note when nothing could be read.
   */
  const runtime = result.runtimeVersions;
  if (runtime && (runtime.declared.length > 0 || runtime.notes.length > 0)) {
    const shown = runtime.declared.slice(0, 5).map((d) => `${d.file}:${d.line} ${d.status}`);
    const more = runtime.declared.length > shown.length ? ` ${g('middot')} ${runtime.declared.length - shown.length} more in --json` : '';
    out.push(
      color.dim(
        `  php runtime (facts from php.net, checked ${runtime.factsChecked}): ` +
          (shown.length > 0 ? shown.join(` ${g('middot')} `) + more : 'no version declared'),
      ),
    );
    for (const note of runtime.notes) out.push(color.dim(`  note: ${note}`));
  }
  // Build the list FIRST, then decide what to print. The earlier version tried
  // to do both in one expression:
  //
  //     '  findings: ' + list.join('  ') || '  findings: none'
  //
  // `+` binds tighter than `||`, so JavaScript read that as
  // ('  findings: ' + '') || '  findings: none'. The left side is the non-empty
  // string '  findings: ', which is truthy, so the fallback never ran and a
  // clean scan printed a bare "findings:" with nothing after it.
  const severityLine = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .filter((s) => bySeverity[s] > 0)
    .map((s) => SEVERITY_STYLE[s](`${bySeverity[s]} ${s}`))
    .join('  ');
  out.push(`  findings: ${severityLine || color.green('none')}`);
  if (hiddenBySeverity > 0) {
    out.push(
      color.dim(
        `  ${hiddenBySeverity} finding(s) below the --min-severity threshold were hidden ` +
          `(they are still present in --json output)`,
      ),
    );
  }

  if (result.parseProblems.length > 0) {
    out.push(
      color.yellow(
        `  ${result.parseProblems.length} file(s) had parse errors — findings in them may be incomplete:`,
      ),
    );
    for (const problem of result.parseProblems.slice(0, 5)) {
      const first = problem.issues[0];
      out.push(color.dim(`    ${problem.file}${first ? `:${first.line}` : ''} ${first?.text ?? ''}`));
    }
    if (result.parseProblems.length > 5) {
      out.push(color.dim(`    ${g('ellipsis')} and ${result.parseProblems.length - 5} more`));
    }
  }

  if (result.suppressions.length > 0) {
    out.push(
      color.dim(
        `  ${result.suppressions.length} finding(s) suppressed by defuse:ignore comments` +
          (options.showSuppressed ? ':' : ' (use --show-suppressed to list them)'),
      ),
    );
    if (options.showSuppressed) {
      for (const s of result.suppressions) {
        out.push(color.dim(`    ${s.file}:${s.line}  ${s.ruleId}  — ${s.comment}`));
      }
    }
  }

  if (result.excluded.fileCount > 0 || result.excluded.patterns.length > 0) {
    // An exclusion the user asked for is still a blind spot. Print it next to
    // the results rather than letting a smaller number look like better news.
    const directories = result.excluded.directories;
    out.push(
      color.dim(
        `  --exclude (${result.excluded.patterns.join(', ')}) skipped ` +
          `${result.excluded.fileCount} file(s)` +
          (directories.length > 0
            ? ` and ${directories.length} whole director(ies): ${directories.slice(0, 6).join(', ')}` +
              (directories.length > 6 ? ` ${g('ellipsis')} +${directories.length - 6} more` : '')
            : '') +
          ' - not scanned, not counted',
      ),
    );
  }

  if (result.oversizedFiles.length > 0) {
    out.push(color.dim(`  ${result.oversizedFiles.length} file(s) skipped for size (>2MB)`));
  }

  if (!full) {
    out.push('');
    out.push(
      color.dim(
        '  Short report. --full adds the reasoning and limits on each finding, the OWASP table\n' +
          '  and every gap by name; --report=report.html writes all of it to one file.',
      ),
    );
  }
  out.push('');
  return out.join('\n');
}

/* Small helpers kept below the main function so the flow above reads in order. */

function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity]++;
  return counts;
}

function renderFinding(finding: Finding, full: boolean): string {
  const rule = getRule(finding.ruleId) ?? (finding.ruleId === RUNTIME_VERSION_RULE.id ? RUNTIME_VERSION_RULE : undefined);
  const indent = '                 ';
  const lines: string[] = [];
  // Pad BEFORE colouring: ANSI escape codes are invisible but count towards
  // String.length, so padding a coloured string misaligns every column.
  const position = color.dim(
    `${finding.location.startLine}:${finding.location.startColumn}`.padEnd(12),
  );
  const confidenceTag =
    finding.confidence === 'signature-based'
      ? color.yellow('[signature-based]')
      : color.green('[flow-verified]');

  lines.push(
    `  ${severityLabel(finding.severity)} ${position} ${color.bold(finding.message)}`,
  );
  lines.push(
    `           ${color.dim(finding.ruleId)} ${color.dim(g('middot'))} ${color.dim(finding.cwe)} ` +
      `${color.dim(g('middot'))} ${color.dim(finding.owasp)} ${confidenceTag}`,
  );
  lines.push(
    `           ${color.dim('code')}  ${color.gray(finding.location.snippet)}`,
  );
  if (full) {
    lines.push(`           ${color.dim('node')}  ${color.gray(finding.location.astNodePath)}`);
  }
  if (rule) lines.push(`           ${color.cyan('what')}  ${wrapText(rule.summary, WIDTH - 18, indent)}`);
  // A pattern match has no path to show, so its reasoning IS the evidence and
  // stays in the short report; a traced finding's evidence is the path itself.
  if (full || !finding.flowPath) {
    lines.push(`           ${color.cyan('why')}   ${wrapText(finding.reasoning, WIDTH - 18, indent)}`);
  }
  if (finding.flowPath) lines.push(renderFlowPath(finding.flowPath));
  if (rule) lines.push(`           ${color.green('fix')}   ${wrapText(rule.fix, WIDTH - 18, indent)}`);
  if (full) {
    lines.push(`           ${color.yellow('gap')}   ${color.dim(wrapText(finding.limitations, WIDTH - 18, indent))}`);
  } else if (!finding.flowPath) {
    lines.push(
      `           ${color.yellow('note')}  ${color.dim('not traced - this may be a false positive; --full says what was not checked')}`,
    );
  }
  return lines.join('\n');
}

/**
 * The receipt. A flow-verified finding is only worth more than a guess if you
 * can CHECK it, so every hop is printed with its own line number: where the
 * data came from, everything that happened to it, and where it ended up.
 * If any hop looks wrong to you, the finding is wrong - and that is the point.
 */
function renderFlowPath(path: readonly FlowStep[]): string {
  const style: Record<FlowStep['kind'], (t: string) => string> = {
    source: (t) => color.magenta(t),
    propagation: (t) => color.dim(t),
    sanitizer: (t) => color.green(t),
    sink: (t) => color.red(t),
  };
  const lines: string[] = [`           ${color.magenta('flow')}  ${color.dim(`traced source ${g('arrow')} sink:`)}`];
  // `a + b + c` is two concatenation hops on one line, and printing the same
  // sentence twice read as a glitch. Same line, kind and words -> one row, xN.
  // Display only: --json, SARIF and the HTML report keep every hop.
  const rows: { step: FlowStep; times: number }[] = [];
  for (const step of path) {
    const last = rows[rows.length - 1];
    if (
      last &&
      last.step.kind === step.kind &&
      last.step.location.startLine === step.location.startLine &&
      last.step.description === step.description
    ) {
      last.times++;
    } else {
      rows.push({ step, times: 1 });
    }
  }
  rows.forEach(({ step, times }, index) => {
    const marker =
      index === 0 ? g('cornerTop') : index === rows.length - 1 ? g('cornerBottom') : g('vertical');
    const where = `${step.location.startLine}`.padStart(4);
    const kind = style[step.kind](step.kind.padEnd(11));
    lines.push(
      `                 ${color.dim(marker)} ${color.dim(`L${where}`)} ${kind} ` +
        wrapText(step.description + (times > 1 ? ` (x${times})` : ''), WIDTH - 36, '                            '),
    );
  });
  return lines.join('\n');
}

function renderCoverage(coverage: CoverageReport, showMatrix: boolean): string {
  const out: string[] = [];
  out.push(heading('What this scan did NOT check'));

  out.push(color.dim('  Engine limits:'));
  for (const item of coverage.engine.notImplemented) {
    out.push(`    ${color.red(g('cross'))} ${item}`);
  }

  const missingTaint = coverage.taint.filter((t) => !t.implemented);
  if (missingTaint.length > 0) {
    out.push('');
    out.push(color.dim('  Languages with NO data-flow verification (signature matching only):'));
    for (const cell of missingTaint) {
      out.push(`    ${color.red(g('cross'))} ${cell.language.padEnd(12)} ${wrapText(cell.note, WIDTH - 20, '        ')}`);
    }
  }

  const partial = coverage.gaps.filter((c) => c.status === 'partial');
  const missing = coverage.gaps.filter((c) => c.status === 'not-implemented');

  if (partial.length > 0) {
    out.push('');
    out.push(color.dim(`  Rules with partial language coverage (${partial.length}):`));
    for (const cell of partial) {
      out.push(
        `    ${color.yellow(g('dotHalf'))} ${color.bold(cell.ruleId)}/${cell.language}: ` +
          wrapText(cell.note, WIDTH - 12, '        '),
      );
    }
  }

  if (missing.length > 0) {
    out.push('');
    out.push(
      color.dim(
        `  Rule/language combinations not implemented at all (${missing.length}): ` +
          missing.map((c) => `${c.ruleId}/${c.language}`).join(', '),
      ),
    );
  }

  if (coverage.unscannedExtensions.length > 0) {
    out.push('');
    out.push(
      color.dim(
        `  File types present but not scanned: ${coverage.unscannedExtensions.join(', ')}`,
      ),
    );
  }

  out.push('');
  out.push(
    color.dim(
      `  Coverage: ${coverage.counts.implemented} implemented ${g('middot')} ` +
        `${coverage.counts.partial} partial ${g('middot')} ${coverage.counts.notImplemented} ` +
        `not implemented (of ${coverage.counts.rules} rules x ${coverage.counts.languages} languages)`,
    ),
  );

  if (showMatrix) {
    out.push('');
    for (const cell of coverage.matrix) {
      const mark =
        cell.status === 'implemented'
          ? color.green(g('dotFull'))
          : cell.status === 'partial'
            ? color.yellow(g('dotHalf'))
            : color.gray(g('dotEmpty'));
      out.push(`    ${mark} ${cell.ruleId.padEnd(20)} ${cell.language.padEnd(12)} ${color.dim(cell.status)}`);
    }
  }

  return out.join('\n');
}
