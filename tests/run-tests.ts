/**
 * THE TEST RUNNER
 * ===============
 *
 * HOW THESE TESTS WORK - this is the part worth understanding, because it is
 * unusual and it is what keeps the rules honest as the project grows.
 *
 * There is no separate list of "expected results" to keep in sync with the
 * fixtures. Instead THE FIXTURE FILES CARRY THEIR OWN EXPECTATIONS, as comments:
 *
 *     // EXPECT sql-injection
 *     return db.query("SELECT * FROM users WHERE id = " + userId);
 *
 * The runner reads those comments, runs the real scanner over the real files,
 * and checks that each annotated line produced a finding of that rule - and,
 * for files marked `EXPECT-NONE`, that nothing fired at all.
 *
 * Why this design:
 *   - Adding a rule means adding a fixture. There is no second place to update,
 *     so tests cannot silently drift out of date.
 *   - A fixture is readable as documentation: it shows the vulnerable code AND
 *     what we claim to detect in it, side by side.
 *   - The safe/ files are as important as the vulnerable/ ones. A scanner that
 *     flags correct code teaches people to ignore it, so FALSE POSITIVES ARE
 *     TEST FAILURES here, exactly like missed detections.
 *
 * HOW TO READ THE OUTPUT:
 *   ✓ detected       we expected a finding on that line and got it
 *   ✗ MISSED         we expected a finding and got nothing  -> the rule is broken
 *   ✗ FALSE POSITIVE a safe file produced a finding          -> the rule is too eager
 *   ! unexpected     a vulnerable file produced an EXTRA finding nobody annotated.
 *                    Not a failure (vulnerable code often has more than one
 *                    problem) but it is printed so it can never pass unnoticed.
 *
 * RUN IT WITH:  npm test
 */

import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/engine/scan.js';
import { color, g } from '../src/report/colors.js';
import { ALL_RULES } from '../src/rules/registry.js';
import { LANGUAGES, detectLanguage } from '../src/parse/languages.js';
import { TAINT_COVERAGE_NOTES, TAINT_DICTIONARIES } from '../src/taint/dictionaries.js';
import { SINK_KIND_RULE } from '../src/taint/types.js';
import { ENGINE_CAPABILITIES, type Finding } from '../src/core/finding.js';
import { LICENCE_FILE_HEADING, LICENCE_SPDX } from '../src/core/licence.js';
import { scoreAnalysis, SEVERITY_WEIGHT } from '../src/core/score.js';
import { analyze } from '../src/core/analyze.js';
import { renderSarif } from '../src/report/sarif.js';
import { renderHuman } from '../src/report/human.js';
import {
  renderRuleMatrix,
  renderCounts,
  renderBenchmark,
  renderLabelSplit,
  readBlock,
  type BenchmarkResult,
  type LabelSplitResult,
} from '../src/report/coverage-table.js';
import { renderSite } from '../src/report/site.js';
import { looksLikeSql, matchKnownSecret, isTestPath } from '../src/rules/lib/strings.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// dist/tests -> project root -> tests/fixtures (fixtures are never compiled)
const FIXTURES = path.resolve(HERE, '../../tests/fixtures');

/**
 * `// EXPECT rule-id`            a finding must appear (either confidence)
 * `// EXPECT-FLOW rule-id`       a finding must appear AND be flow-verified
 * `// EXPECT-SIGNATURE rule-id`  a finding must appear AND must NOT claim proof
 * `// EXPECT-NONE`               this whole file must produce nothing
 * `// EXPECT-CLEAN rule-id`      NO finding here, AND the engine recorded a proof
 *                                that the line is clean - silence is not enough
 *
 * EXPECT-SIGNATURE closes a hole in this vocabulary that existed for the whole
 * project. The honesty contract has exactly one distinction at its centre -
 * signature-based guess versus flow-verified proof - and until now the tests
 * could only say "something fired" or "something fired WITH proof". There was
 * no way to write down "this line is a fair guess, and claiming proof for it
 * would be a lie", which is the assertion that actually protects the contract.
 *
 * It has a real subject. `out.println("<div>" + req.getContextPath() + "</div>")`
 * concatenates a method result into HTML: a signature rule cannot know that
 * value is a container constant and is right to flag it unverified. The tracer
 * claiming it as PROVEN attacker-controlled - which is what Jenkins got - is a
 * different kind of statement and a false one. Both facts are now assertable on
 * the same line.
 */
const EXPECT = /(?:\/\/|#|\/\*|\*)\s*EXPECT(-NONE|-FLOW|-SIGNATURE|-CLEAN)?\s*:?\s*([a-z0-9-]*)/i;

interface Expectation {
  readonly file: string;
  readonly line: number; // line the annotation sits on
  readonly ruleId: string;
  /** EXPECT-FLOW: the finding must carry a verified source-to-sink path. */
  readonly requireFlow: boolean;
  /** EXPECT-SIGNATURE: the finding must NOT carry one. Overclaim is a failure. */
  readonly forbidFlow: boolean;
  /**
   * EXPECT-CLEAN: NO finding for this rule here, AND a positive proved-clean
   * record for it. See the note on the vocabulary above main().
   */
  readonly requireClean: boolean;
}

interface FileExpectations {
  readonly file: string;
  readonly expectNone: boolean;
  readonly expectations: readonly Expectation[];
}

async function readExpectations(dir: string): Promise<FileExpectations[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const results: FileExpectations[] = [];

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const full = path.join(dir, entry.name);
    const lines = (await readFile(full, 'utf8')).split('\n');

    let expectNone = false;
    const expectations: Expectation[] = [];

    lines.forEach((text, index) => {
      const match = EXPECT.exec(text);
      if (!match) return;
      const modifier = (match[1] ?? '').toUpperCase();
      if (modifier === '-NONE') {
        expectNone = true;
        return;
      }
      if (match[2]) {
        expectations.push({
          file: full,
          line: index + 1,
          ruleId: match[2].toLowerCase(),
          requireFlow: modifier === '-FLOW',
          forbidFlow: modifier === '-SIGNATURE',
          requireClean: modifier === '-CLEAN',
        });
      }
    });

    results.push({ file: full, expectNone, expectations });
  }

  return results.sort((a, b) => a.file.localeCompare(b.file));
}

/**
 * An annotation sits ABOVE the vulnerable code, and a statement can wrap onto
 * the next line, so we accept a finding within a small window below it.
 */
const WINDOW = 3;

function findingsNear(
  findings: readonly Finding[],
  relativeFile: string,
  line: number,
  ruleId: string,
  requireFlow: boolean,
  forbidFlow = false,
): Finding[] {
  return findings.filter(
    (f) =>
      f.ruleId === ruleId &&
      f.location.file.endsWith(relativeFile) &&
      f.location.startLine > line &&
      f.location.startLine <= line + WINDOW &&
      (!requireFlow || f.confidence === 'flow-verified') &&
      (!forbidFlow || f.confidence !== 'flow-verified'),
  );
}

async function main(): Promise<number> {
  console.log(`\n${color.bold('Defuse — rule verification')}`);
  console.log(color.dim(`fixtures: ${FIXTURES}\n`));

  const vulnerable = await readExpectations(path.join(FIXTURES, 'vulnerable'));
  const safe = await readExpectations(path.join(FIXTURES, 'safe'));

  const result = await scan(FIXTURES, {});
  const findings = result.findings;

  let passed = 0;
  let failed = 0;
  /** Checks that could not run. Never folded into "passed". */
  let skipped = 0;
  const unexpected: Finding[] = [];

  /* ---- vulnerable fixtures: every annotation must be matched ---- */
  console.log(color.bold('  Detection tests (vulnerable fixtures)'));
  const claimed = new Set<Finding>();

  for (const file of vulnerable) {
    const short = path.basename(file.file);
    for (const expectation of file.expectations) {
      /*
       * EXPECT-CLEAN, AND WHY SILENCE WAS NOT GOOD ENOUGH TO ASSERT.
       *
       * The constant folder lets the SQL rule withdraw a guess when every value
       * spliced into the string is provably a literal on every path that runs.
       * The obvious way to test that is "nothing is reported here" - and that
       * assertion passes for a rule that crashed, a shape query that stopped
       * matching, or a file that failed to parse. Silence has too many causes
       * to be evidence of any one of them.
       *
       * So a withdrawal has to leave a receipt: a verifiedClean entry naming
       * this rule on this line. The report prints those as "proved clean", and
       * this is what stops that phrase from ever describing an accident.
       */
      if (expectation.requireClean) {
        const stillReported = findingsNear(findings, short, expectation.line, expectation.ruleId, false);
        const receipt = result.verifiedClean.find(
          (c) =>
            c.ruleId === expectation.ruleId &&
            c.file.endsWith(short) &&
            c.line > expectation.line &&
            c.line <= expectation.line + WINDOW,
        );
        if (stillReported.length === 0 && receipt) {
          passed++;
          console.log(
            `    ${color.green(g('tick'))} ${short.padEnd(14)} line ${String(expectation.line + 1).padStart(3)}  ` +
              `${color.dim(expectation.ruleId.padEnd(20))} ${color.green('proved clean')}`,
          );
        } else {
          failed++;
          for (const hit of stillReported) claimed.add(hit);
          console.log(
            `    ${color.red(`${g('cross')} NOT CLEAN`)} ${short.padEnd(14)} line ${String(expectation.line + 1).padStart(3)}  ` +
              `${color.red(expectation.ruleId)} ` +
              (stillReported.length > 0
                ? `is still reported (${stillReported[0]?.confidence}) - the guess was not withdrawn`
                : 'is silent but left NO proved-clean record - silence is not a proof'),
          );
        }
        continue;
      }
      const hits = findingsNear(
        findings,
        short,
        expectation.line,
        expectation.ruleId,
        expectation.requireFlow,
        expectation.forbidFlow,
      );
      if (hits.length > 0) {
        passed++;
        for (const hit of hits) claimed.add(hit);
        const label =
          hits[0]?.confidence === 'flow-verified'
            ? color.green('flow-verified')
            : color.yellow('signature');
        console.log(
          `    ${color.green(g('tick'))} ${short.padEnd(14)} line ${String(expectation.line + 1).padStart(3)}  ` +
            `${color.dim(expectation.ruleId.padEnd(20))} ${label}`,
        );
      } else {
        failed++;
        console.log(
          `    ${color.red(`${g('cross')} MISSED`)} ${short.padEnd(14)} line ${String(expectation.line + 1).padStart(3)}  ` +
            `${color.red(expectation.ruleId)} ` +
            (expectation.requireFlow
              ? 'was not FLOW-VERIFIED here'
              : expectation.forbidFlow
                ? 'either did not fire, or OVERCLAIMED - this line must be reported ' +
                  'as a signature guess, never as a proven flow'
                : 'did not fire'),
        );
      }
    }
  }

  // Anything else found in the vulnerable tree is reported, never ignored.
  for (const finding of findings) {
    if (claimed.has(finding)) continue;
    if (finding.location.file.includes(`vulnerable${path.sep}`)) unexpected.push(finding);
  }

  /* ---- safe fixtures: nothing at all may fire ---- */
  console.log(`\n${color.bold('  False-positive tests (safe fixtures)')}`);
  for (const file of safe) {
    const short = path.basename(file.file);
    const hits = findings.filter((f) => f.location.file.endsWith(short));
    if (hits.length === 0) {
      passed++;
      console.log(`    ${color.green(g('tick'))} ${short.padEnd(14)} clean, as required`);
    } else {
      failed++;
      for (const hit of hits) {
        console.log(
          `    ${color.red(`${g('cross')} FALSE POSITIVE`)} ${short}:${hit.location.startLine} ` +
            `${color.red(hit.ruleId)} — ${hit.message}`,
        );
        console.log(`        ${color.dim(hit.location.snippet)}`);
      }
    }
  }

  /* ---- rule coverage: is every rule exercised at all? ---- */
  console.log(`\n${color.bold('  Rule exercise check')}`);
  for (const rule of ALL_RULES) {
    const firedIn = new Set(
      findings.filter((f) => f.ruleId === rule.id).map((f) => path.basename(f.location.file)),
    );
    if (firedIn.size === 0) {
      failed++;
      console.log(`    ${color.red(g('cross'))} ${rule.id.padEnd(20)} never fired on any fixture`);
    } else {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} ${rule.id.padEnd(20)} fired in ${firedIn.size} fixture(s): ` +
          color.dim([...firedIn].join(', ')),
      );
    }
  }

  if (unexpected.length > 0) {
    console.log(`\n${color.bold('  Unannotated findings in vulnerable fixtures')} ${color.dim('(not failures)')}`);
    for (const finding of unexpected) {
      console.log(
        `    ${color.yellow('!')} ${path.basename(finding.location.file)}:${finding.location.startLine} ` +
          `${finding.ruleId} — ${finding.message}`,
      );
    }
  }

  /* ---- the honesty contract, Phase 3 edition ----
   * Phase 1 asserted that NOTHING claimed flow-verification. Now that the
   * tracer exists, the assertion changes shape but not spirit: a
   * flow-verified label must be BACKED BY EVIDENCE, and a signature-based one
   * must not pretend to have any.                                          */
  console.log(`\n${color.bold('  Honesty contract')}`);

  const verified = findings.filter((f) => f.confidence === 'flow-verified');
  const signature = findings.filter((f) => f.confidence === 'signature-based');

  const unbacked = verified.filter((f) => {
    const path = f.flowPath;
    if (!path || path.length < 2) return true;
    if (path[0]?.kind !== 'source') return true;
    if (path[path.length - 1]?.kind !== 'sink') return true;
    return path.some((step) => step.kind === 'sanitizer');
  });
  if (unbacked.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} all ${verified.length} flow-verified findings carry a complete ` +
        `source-to-sink path with no sanitiser on it`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} ${unbacked.length} flow-verified finding(s) cannot show a valid path`,
    );
  }

  const pretenders = signature.filter((f) => f.flowPath !== null);
  if (pretenders.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} all ${signature.length} signature-based findings report flowPath: null ` +
        `- no implied tracing`,
    );
  } else {
    failed++;
    console.log(`    ${color.red(g('cross'))} ${pretenders.length} signature finding(s) carry a flow path`);
  }

  // Every hop must point at a real line in the file it names.
  const brokenHops = verified.flatMap((f) =>
    (f.flowPath ?? []).filter((step) => step.location.startLine < 1 || !step.description.trim()),
  );
  if (brokenHops.length === 0) {
    passed++;
    console.log(`    ${color.green(g('tick'))} every hop in every path has a location and an explanation`);
  } else {
    failed++;
    console.log(`    ${color.red(g('cross'))} ${brokenHops.length} hop(s) are missing a location or a description`);
  }
  const missingReasoning = findings.filter(
    (f) => f.reasoning.trim().length < 20 || f.limitations.trim().length < 20,
  );
  if (missingReasoning.length === 0) {
    passed++;
    console.log(`    ${color.green(g('tick'))} every finding carries reasoning and stated limitations`);
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} ${missingReasoning.length} finding(s) lack reasoning or limitations`,
    );
  }

  /* ---- what the tracer actually achieved ---- */
  console.log(`\n${color.bold('  Data-flow engine')}`);
  console.log(
    `    ${color.green(g('tick'))} ${result.stats.flowsVerified} flow(s) verified source-to-sink; ` +
      `${result.stats.signaturesUpgraded} signature guess(es) superseded; ` +
      `${result.stats.signaturesRetracted} withdrawn as provably sanitised`,
  );
  passed++;

  // Cross-file resolution has to be asserted, not assumed. A silent failure
  // here looks exactly like "those fixtures are just clean".
  if (result.crossFile.enabled && result.crossFile.resolved > 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} ${result.crossFile.resolved} call(s) followed into another file ` +
        `across ${result.crossFile.importEdges} resolved import edge(s); ` +
        `${result.crossFile.ambiguous} declined as ambiguous`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} no cross-file call was followed - the import graph is not working`,
    );
  }

  // Findings whose path spans more than one file: the whole point of 3c.
  const multiFile = findings.filter(
    (f) => new Set((f.flowPath ?? []).map((s) => s.location.file)).size > 1,
  );
  if (multiFile.length > 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} ${multiFile.length} finding(s) have a path spanning two or more files`,
    );
  } else {
    failed++;
    console.log(`    ${color.red(g('cross'))} no finding spans more than one file`);
  }

  /* ---- an assumed hop must be on the FINDING, not only in the prose ----
   * `flow-verified` promises "traced, no sanitiser on the path". A hop through
   * a function we do not model makes "no sanitiser" an assumption instead of an
   * observation. The path step said so and the limitations text said so, but a
   * consumer filtering --json on confidence got the unqualified promise.
   *
   * So the names are a field now, and this check keeps the field honest: it must
   * agree exactly with the UNMODELLED hops in the path it came from.           */
  const flowFindings = findings.filter((f) => f.confidence === 'flow-verified');
  const mismatched = flowFindings.filter((f) => {
    const inPath = new Set(
      (f.flowPath ?? [])
        // Three wordings, one assumption: a function we cannot read, one the
        // trace stopped following at the depth limit, and one it stopped
        // re-entering. All three say "we assume it preserves the value", and all
        // three must be on the finding as a field, not only in the prose.
        .map(
          (step) =>
            /passed through `([^`]+)\(\)`, which (?:is NOT in our dictionary|we did NOT follow|resolves by name to a function already being followed)/.exec(
              step.description,
            )?.[1],
        )
        .filter((name): name is string => Boolean(name)),
    );
    const declared = new Set(f.unmodelledHops);
    return inPath.size !== declared.size || [...inPath].some((n) => !declared.has(n));
  });
  const withAssumptions = flowFindings.filter((f) => f.unmodelledHops.length > 0).length;
  if (mismatched.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} every flow-verified finding declares its unmodelled hops as a field ` +
        color.dim(`(${withAssumptions} of ${flowFindings.length} rest on at least one assumption)`),
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} ${mismatched.length} finding(s) have an unmodelled hop in the path ` +
        `that is missing from unmodelledHops - the caveat exists in prose only`,
    );
  }

  /* ---- a file a flow passes through is never "clean" ----
   * Findings are filed at the SINK, which is correct - that is where the
   * untrusted value gets executed. But in a cross-file flow the sink is often
   * innocent plumbing, and the file holding the line a developer must actually
   * edit gets no finding at all. If that file also contains a sanitised line,
   * a naive file list shows it GREEN: the file you have to fix, marked safe.
   *
   * `fileRoles` exists to make that state sayable. This check proves it is
   * populated - not that a UI draws it, but that the engine hands over the
   * fact, so both the terminal and the browser can. */
  const originOnly = result.fileRoles.filter(
    (role) => role.onPathOf > 0 && role.findingsReported === 0,
  );
  if (originOnly.length > 0) {
    passed++;
    const worst = originOnly.find((r) => r.verifiedCleanLines > 0) ?? originOnly[0]!;
    console.log(
      `    ${color.green(g('tick'))} ${originOnly.length} file(s) carry attacker data toward a finding ` +
        `filed elsewhere and are reported as such, not as clean ` +
        color.dim(`(e.g. ${path.basename(worst.file)}: on the path of ${worst.onPathOf}, ` +
          `${worst.verifiedCleanLines} clean line(s), 0 findings)`),
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} fileRoles reports no origin-only file, so a cross-file flow's ` +
        `starting file would be indistinguishable from an untouched one`,
    );
  }

  /* ---- the gauges ----
   * The readings are the most quotable thing this tool produces - a number
   * someone will paste into a ticket without the paragraph next to it. So the
   * arithmetic is checked here rather than trusted, and the one structural
   * rule (never merge them) is enforced rather than merely intended.      */
  console.log(`\n${color.bold('  Gauges')}`);
  const score = scoreAnalysis(result, result.stats.filesFound);

  // 1. Recompute both severity dials by hand from the finding list.
  const byHand = (confidence: string) =>
    result.findings
      .filter((f) => f.confidence === confidence)
      .reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  const verifiedGauge = score.gauges.find((x) => x.id === 'verified-exposure')!;
  const surfaceGauge = score.gauges.find((x) => x.id === 'unverified-surface')!;
  const expectVerified = byHand('flow-verified');
  const expectSurface = byHand('signature-based');
  if (verifiedGauge.rawTotal === expectVerified && surfaceGauge.rawTotal === expectSurface) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} both severity dials recompute by hand ` +
        color.dim(`(verified ${expectVerified}, unverified ${expectSurface})`),
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} dial arithmetic does not reproduce: verified ` +
        `${verifiedGauge.rawTotal} vs ${expectVerified}, unverified ${surfaceGauge.rawTotal} vs ${expectSurface}`,
    );
  }

  // 2. The two severity dials must PARTITION the findings - every finding
  //    counted exactly once, in exactly one of them. A finding that fell
  //    through both would quietly shrink the numbers.
  const partitioned = result.findings.filter(
    (f) => f.confidence === 'flow-verified' || f.confidence === 'signature-based',
  ).length;
  if (partitioned === result.findings.length) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} all ${result.findings.length} findings land in exactly one severity dial`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} ${result.findings.length - partitioned} finding(s) counted by neither dial`,
    );
  }

  // 3. THE STRUCTURAL RULE. Blending severity with confidence is the lie this
  //    project was built to avoid - finding.ts calls it out by name. So the
  //    scoring module must not grow a combined score, and must not be
  //    importable as one. Checked against the source, because a future edit
  //    that adds `overallRisk` would otherwise pass every other test here.
  const scoreSource = await readFile(path.resolve(HERE, '../../src/core/score.ts'), 'utf8');
  const merged = /export\s+(?:const|function|interface)\s+\w*(?:overall|combined|total|risk)\w*/i.exec(
    scoreSource,
  );
  if (!merged && score.gauges.length === 3) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} three separate readings, no combined risk score exported`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} ${merged ? `score.ts exports \`${merged[0]}\` - blending severity with confidence is the lie this tool exists to avoid` : `expected 3 gauges, got ${score.gauges.length}`}`,
    );
  }

  // 3b. The composition strip must add up to the dial it sits under. It is
  //     drawn as proportions, so a segment set that does not sum to the total
  //     would render a bar that looks right and means nothing.
  const badSegments = score.gauges
    .filter((x) => x.segments.length > 0)
    .filter((x) => {
      const sum = x.segments.reduce((t, seg) => t + seg.weight, 0);
      const shares = x.segments.reduce((t, seg) => t + seg.share, 0);
      return sum !== x.rawTotal || Math.abs(shares - 1) > 1e-9;
    });
  if (badSegments.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} every composition strip sums to its own dial ` +
        color.dim(
          score.gauges
            .filter((x) => x.segments.length)
            .map((x) => `${x.id}: ${x.segments.map((seg) => `${seg.count} ${seg.severity}`).join(' + ')}`)
            .join('; '),
        ),
    );
  } else {
    failed++;
    for (const bad of badSegments) {
      console.log(`    ${color.red(g('cross'))} ${bad.id} segments do not sum to ${bad.rawTotal}`);
    }
  }

  // 3c. "Nothing to measure" must not render as "measured zero".
  //
  // A one-byte file containing a single space parses cleanly, so it produced
  // 0 findings, 94% coverage and no blind spots - byte-identical to a scan of
  // ten lines of careful, correctly parameterised code. The dashboard could not
  // tell "we checked and found nothing" from "there was nothing to check",
  // which is the exact confusion this whole project exists to prevent.
  const emptyish = await analyze([{ path: 'blank.py', source: '   \n\n  \n' }]);
  const emptyScore = scoreAnalysis(emptyish, 1);
  const realish = await analyze([
    { path: 'ok.py', source: 'import hashlib\n\ndef d(x):\n    return hashlib.sha256(x).hexdigest()\n' },
  ]);
  const realScore = scoreAnalysis(realish, 1);
  const distinguishable =
    emptyScore.examinedNothing &&
    emptyScore.gauges.every((x) => x.noReading) &&
    !realScore.examinedNothing &&
    realScore.gauges.every((x) => !x.noReading) &&
    realScore.shapesExamined > 0;
  if (distinguishable) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} an unanalysable scan is flagged as "no reading", not as zero ` +
        color.dim(`(blank file: ${emptyScore.shapesExamined} shapes; real file: ${realScore.shapesExamined})`),
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} a file with no code (${emptyScore.shapesExamined} shapes) reports the ` +
        `same way as one with ${realScore.shapesExamined} - "nothing to check" is being shown as "checked, nothing found"`,
    );
  }

  // 4. A dial reading zero must not be phrased as safety.
  const claimsSafety = score.gauges.some((reading) =>
    /\b(safe|secure|clean bill|no (?:vulnerabilit|issue|bug))/i.test(reading.meaning),
  );
  if (!claimsSafety) {
    passed++;
    console.log(`    ${color.green(g('tick'))} no dial describes its reading as safety`);
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} a dial's meaning text implies safety - a low reading means we did not prove much, not that nothing is there`,
    );
  }

  /* ---- the page has to be readable and operable ----
   * These started as a one-off audit and are here permanently for the same
   * reason every other rule in this suite is: an intention decays, a check
   * does not. The audit found the CRITICAL label at 3.16:1 and a deck that
   * Tab could not reach at all - neither was noticeable by looking.       */
  console.log(`\n${color.bold('  Page accessibility')}`);
  const pageHtml = await readFile(path.resolve(HERE, '../../ui/index.html'), 'utf8');
  const appJs = await readFile(path.resolve(HERE, '../../ui/app.js'), 'utf8');

  const tokens = new Map(
    [...pageHtml.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{3,6})\s*;/g)].map((m) => [m[1]!, m[2]!]),
  );
  const toRgb = (hex: string): [number, number, number] => {
    let h = hex.replace('#', '');
    if (h.length === 3) h = [...h].map((c) => c + c).join('');
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)) as [number, number, number];
  };
  const channel = (c: number) => (c / 255 <= 0.04045 ? c / 255 / 12.92 : ((c / 255 + 0.055) / 1.055) ** 2.4);
  const luminance = (hex: string) => {
    const [r, gg, b] = toRgb(hex).map(channel) as [number, number, number];
    return 0.2126 * r + 0.7152 * gg + 0.0722 * b;
  };
  const contrast = (a: string, b: string) => {
    const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
    return (hi + 0.05) / (lo + 0.05);
  };

  // --crimson, --line and --focus are deliberately graphics-only: arcs, rules,
  // gutter marks and outlines, where 3.0 is the bar. Anything READ in crimson
  // uses --crimson-ink, and that is the list checked below.
  const INK = ['text', 'muted', 'faint', 'crimson-ink', 'amber', 'emerald'];
  const GROUNDS = ['canvas', 'panel', 'deep'];
  const tooFaint: string[] = [];
  for (const ink of INK) {
    for (const ground of GROUNDS) {
      const a = tokens.get(ink);
      const b = tokens.get(ground);
      if (!a || !b) continue;
      const ratio = contrast(a, b);
      if (ratio < 4.5) tooFaint.push(`--${ink} on --${ground} = ${ratio.toFixed(2)}:1`);
    }
  }
  // --brand is large display type only, so it answers to the 3.0 bar.
  const brand = tokens.get('brand');
  if (brand) {
    for (const ground of GROUNDS) {
      const ratio = contrast(brand, tokens.get(ground)!);
      if (ratio < 3) tooFaint.push(`--brand on --${ground} = ${ratio.toFixed(2)}:1`);
    }
  }
  if (tooFaint.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} every text colour clears WCAG AA on every background ` +
        color.dim(`(${INK.length} inks x ${GROUNDS.length} grounds, plus --brand at the large-text bar)`),
    );
  } else {
    failed++;
    for (const miss of tooFaint.slice(0, 6)) console.log(`    ${color.red(g('cross'))} ${miss}`);
  }

  // A modifier class must not also be a component name.
  //
  // `tile(…, 'flow')` put class="tile flow" on the flow-verified tile - and
  // `.flow` is ALSO the flow-path container, which sets `padding-left: 0` and a
  // top margin. So that one tile lost its left padding and sat 6px lower than
  // its three neighbours: the number pressed against the edge and the row
  // stopped lining up. Nothing errored; it just looked slightly wrong forever.
  //
  // The rule that prevents it: a modifier passed to a component helper must be
  // namespaced to that component, so it cannot collide with a bare class.
  const modifiers = [...appJs.matchAll(/tile\([^)]*?,\s*'([a-z][\w-]*)'\s*\)/g)].map((m) => m[1]!);
  const unNamespaced = modifiers.filter((cls) => !cls.startsWith('tile-'));
  if (unNamespaced.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} every tile modifier is namespaced ` +
        color.dim(`(${modifiers.join(', ') || 'none'})`),
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} bare modifier class(es) ${unNamespaced.join(', ')} ` +
        `- these can collide with a component of the same name`,
    );
  }

  // The OWASP taxonomy must be the current edition, and no category may claim
  // to be fully covered.
  //
  // Both halves were wrong at once: every rule declared `A0x:2021` after the
  // 2025 edition superseded it, and the coverage panel used a binary that let
  // three barely-touched categories read as handled. Naming a standard is a
  // claim like any other.
  const owasp = result.coverage.owaspCoverage;
  const staleEdition = [...ALL_RULES.map((r) => r.owasp), ...owasp.map((c) => c.id)].filter(
    (text) => /:20(1[0-9]|2[0-4])\b/.test(text),
  );
  const claimsFull = owasp.filter((c) => (c as { state: string }).state === 'full');
  const partialsWithoutScope = owasp.filter((c) => c.state === 'partial' && !c.weCheck);
  if (owasp.length === 10 && staleEdition.length === 0 && claimsFull.length === 0 && partialsWithoutScope.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} OWASP coverage names the current edition, all 10 categories, none claimed complete ` +
        color.dim(`(${owasp.filter((c) => c.state === 'none').length} with no rule, ${owasp.filter((c) => c.state === 'partial').length} partial)`),
    );
  } else {
    failed++;
    if (staleEdition.length) console.log(`    ${color.red(g('cross'))} superseded OWASP edition cited: ${[...new Set(staleEdition)].slice(0,3).join(', ')}`);
    if (claimsFull.length) console.log(`    ${color.red(g('cross'))} ${claimsFull.length} category claims full coverage - no category earns that`);
    if (partialsWithoutScope.length) console.log(`    ${color.red(g('cross'))} partial category without a stated scope: ${partialsWithoutScope[0]?.id}`);
    if (owasp.length !== 10) console.log(`    ${color.red(g('cross'))} expected 10 categories, got ${owasp.length}`);
  }

  // No unreadably small type. 11px is the floor for a tracked mono micro-label;
  // nothing sentence-shaped is allowed under 12.
  const tiny = [...pageHtml.matchAll(/([^{};\n]+)\{[^}]*font-size:\s*(\d+(?:\.\d+)?)px/g)]
    .filter((m) => Number(m[2]) < 11)
    .map((m) => `${m[1]!.trim().slice(0, 40)} at ${m[2]}px`);
  if (tiny.length === 0) {
    passed++;
    console.log(`    ${color.green(g('tick'))} no text below the 11px floor`);
  } else {
    failed++;
    for (const t of [...new Set(tiny)].slice(0, 6)) console.log(`    ${color.red(g('cross'))} ${t}`);
  }

  // Everything clickable must be a real control. A <div> with a click handler
  // is invisible to the keyboard, and the deck was built entirely from them.
  const handlerTargets = [...appJs.matchAll(/\.addEventListener\('click'/g)].length;
  // Each of the three deck controls must be emitted as a real <button>. A tag
  // name is the whole difference between "Tab reaches this" and "it does not".
  const bareDivHandlers = !['file', 'hop', 'row-head'].every((cls) =>
    new RegExp(`<button[^>]*class="(?:[^"]*\\s)?${cls}`).test(appJs),
  );
  const a11yBits = {
    'focus-visible style': pageHtml.includes(':focus-visible'),
    'reduced-motion honoured':
      pageHtml.includes('prefers-reduced-motion') && appJs.includes('prefers-reduced-motion'),
    'keyboard handler': appJs.includes("addEventListener('keydown'"),
    'no click-only divs': !bareDivHandlers,
  };
  const absent = Object.entries(a11yBits)
    .filter(([, ok]) => !ok)
    .map(([name]) => name);
  if (absent.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} deck is keyboard-operable ` +
        color.dim(`(${handlerTargets} handlers, all on real buttons; focus ring and reduced-motion present)`),
    );
  } else {
    failed++;
    console.log(`    ${color.red(g('cross'))} missing: ${absent.join(', ')}`);
  }

  /* ---- the browser bundle must stay a bundle of THIS engine ----
   * The whole promise of the web UI is that it runs the same code as the CLI.
   * The way that promise dies is quietly: someone imports a Node-only module
   * into the shared path, the browser build starts failing or diverging, and
   * nobody notices for a month. Two cheap greps make it loud instead.        */
  console.log(`\n${color.bold('  Browser bundle')}`);
  const bundleDir = path.resolve(HERE, '../../ui/engine');
  let bundleFiles: string[] = [];
  try {
    await stat(bundleDir);
    const walkBundle = async (dir: string): Promise<void> => {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walkBundle(full);
        else if (entry.name.endsWith('.js')) bundleFiles.push(full);
      }
    };
    await walkBundle(bundleDir);
  } catch {
    bundleFiles = [];
  }

  if (bundleFiles.length === 0) {
    // Counted, not just mentioned. A check that quietly disappears takes the
    // total down with it, and a smaller total reads like a smaller test suite
    // rather than an unrun check - which is the same lie this tool exists to
    // avoid, told about itself.
    skipped++;
    console.log(
      `    ${color.dim(`${g('middot')} SKIPPED: ui/engine is not built, so the browser bundle was not checked. ` +
        `Run \`npm run build:ui\` and re-run to include it.`)}`,
    );
  } else {
    const offenders: string[] = [];
    for (const file of bundleFiles) {
      const text = await readFile(file, 'utf8');
      if (/from '(node:|fs|path)'/.test(text)) offenders.push(`${path.basename(file)} imports Node`);
      if (/from 'web-tree-sitter'/.test(text)) {
        offenders.push(`${path.basename(file)} still has a bare specifier`);
      }
    }
    if (offenders.length === 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} ${bundleFiles.length} browser module(s): no Node imports, ` +
          `no unresolvable specifiers`,
      );
    } else {
      failed++;
      for (const offender of offenders.slice(0, 5)) {
        console.log(`    ${color.red(g('cross'))} ${offender}`);
      }
    }
  }

  /* ---- documentation drift ----
   * A tool whose entire pitch is "we do not misstate what we do" cannot have
   * its own docs claiming the wrong phase. Phase numbers went stale the moment
   * the taint engine shipped: rule notes still said "Phase 1 cannot follow
   * that" long after Phase 3 could.
   *
   * The fix is not to renumber them - it is to stop numbering. User-facing text
   * describes MECHANISMS ("the signature pass", "the tracer"), which stay true
   * across releases. This test enforces that, so the drift cannot come back.  */
  /* ---------------------------------------------------------------------
   * TEXT-SHAPE RECOGNISERS
   *
   * Every one of these cases is a real false positive this scanner produced
   * against its own source or a real query it must never stop catching. They
   * are unit-level on purpose: `looksLikeSql` is three lines of regex sitting
   * under two rules and the tracer, so a change here moves numbers in places
   * a fixture would not connect to the cause.
   * ------------------------------------------------------------------- */
  /*
   * ---- test-path conventions, THIRD TIME THIS CLASS HAS BITTEN ----
   *
   * Scanning cal.com (3,941 TypeScript files) produced 196 findings, and 138 of
   * them - 70% - were hardcoded-secret. The non-low ones were dominated by
   *
   *     apps/web/playwright/payment-apps.e2e.ts   access_token: "sk_test_randomString"
   *     packages/testing/src/lib/bookingScenario/bookingScenario.ts
   *
   * Both are test code. `isTestPath` recognised neither, for boring reasons:
   * `e2e` was matched only as a whole DIRECTORY segment, never as the `.e2e.ts`
   * filename suffix that Playwright actually uses; and `tests?` matches `test`
   * and `tests` but not `testing`.
   *
   * This is the same shape as the two lessons before it. elasticsearch proved
   * SOURCES are per-framework, not per-language. Jenkins proved ESCAPERS are
   * too. cal.com proves TEST-PATH CONVENTIONS are per-ecosystem - each list was
   * built from the repositories I had happened to be shown, and each looked
   * complete until a repository with different habits arrived.
   *
   * THE TRAP, which is why this is a table and not a wider regex: `latest.ts`
   * contains "test", `contest/`, `testimonials.ts` and `protester.js` all
   * contain it too, and treating any of them as test code would quietly
   * downrank real findings in application source. Every one of them is in the
   * MUST-NOT list below.
   */
  /*
   * ---- "nothing found" must not read as "nothing here" ----
   *
   * Someone scanned juice-shop's server.ts on its own: one file, 117 imports,
   * every one pointing at a route file outside the scan. The tool parsed it,
   * examined 834 shapes, found 8 sources and reported nothing - all correct,
   * because server.ts is wiring and the bugs live in what it imports. The same
   * repository's routes/ directory yields seven findings, two flow-verified.
   *
   * The report already held the evidence (`importEdges 0`) and said nothing
   * about what it meant, so an empty findings list read first as a clean bill
   * of health and then as a broken tool. Both readings were the report's fault.
   *
   * The warning only fires when NOTHING resolved, so a normal project scan with
   * a few unresolvable imports stays quiet - asserted in both directions here.
   */
  console.log(`\n${color.bold('  Scope warning')}`);
  {
    const base = {
      ...result,
      findings: [] as Finding[],
    } as unknown as Parameters<typeof renderHuman>[0];
    const withCrossFile = (importEdges: number, importsUnresolved: number) =>
      renderHuman({
        ...base,
        crossFile: {
          enabled: true,
          filesIndexed: 1,
          functionsIndexed: 9,
          importEdges,
          importsUnresolved,
          resolved: 0,
          ambiguous: 0,
        },
      } as unknown as Parameters<typeof renderHuman>[0]);

    const narrow = withCrossFile(0, 94);   // the juice-shop server.ts case
    const healthy = withCrossFile(12, 4);  // a normal project scan
    const noImports = withCrossFile(0, 0); // a self-contained file

    const problems: string[] = [];
    if (!narrow.includes('SCOPE WARNING')) {
      problems.push('a scan where NO import resolved did not warn');
    }
    if (healthy.includes('SCOPE WARNING')) {
      problems.push('a scan whose imports DID resolve warned anyway');
    }
    if (noImports.includes('SCOPE WARNING')) {
      problems.push('a scan with no local imports at all warned');
    }
    if (!narrow.includes('94')) {
      problems.push('the warning does not name how many imports led nowhere');
    }
    if (problems.length === 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} an empty result warns when nothing could be traced, ` +
          `and stays quiet when it could`,
      );
    } else {
      failed++;
      for (const p of problems) console.log(`    ${color.red(g('cross'))} ${p}`);
    }
  }

  console.log(`\n${color.bold('  Test-path conventions')}`);
  {
    const TEST_PATHS: readonly string[] = [
      // the two cal.com missed
      'apps/web/playwright/payment-apps.e2e.ts',
      'packages/testing/src/lib/bookingScenario/bookingScenario.ts',
      // conventions that already worked, kept so a rewrite cannot drop them
      'src/__tests__/auth.ts',
      'src/__mocks__/prisma.ts',
      'lib/pkce.test.ts',
      'lib/auth.spec.ts',
      'internal/db_test.go',
      'src/test/java/com/acme/FooTest.java',
      'e2e/checkout.ts',
      // other ecosystems' spellings
      'cypress/integration/login.cy.ts',
      'src/login.e2e-spec.ts',
      'tests/conftest.py',
      'src/FooTests.cs',
    ];
    const NOT_TEST_PATHS: readonly string[] = [
      // every one of these CONTAINS a test word and is application source
      'src/latest.ts',
      'src/contest/entry.ts',
      'components/testimonials.tsx',
      'lib/protester.js',
      'src/attestation/verify.ts',
      'packages/features/oauth/services/OAuthService.ts',
      'scripts/seed.ts',
      'src/greatest-hits.ts',
    ];
    const wrong: string[] = [];
    for (const p of TEST_PATHS) if (!isTestPath(p)) wrong.push(`missed test path: ${p}`);
    for (const p of NOT_TEST_PATHS) if (isTestPath(p)) wrong.push(`app source called a test: ${p}`);
    if (wrong.length === 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} ${TEST_PATHS.length} test conventions recognised, ` +
          `${NOT_TEST_PATHS.length} lookalikes in app source rejected`,
      );
    } else {
      failed++;
      for (const w of wrong) console.log(`    ${color.red(g('cross'))} ${w}`);
    }
  }

  console.log(`\n${color.bold('  Text-shape recognisers')}`);

  const SQL_MUST_MATCH: ReadonlyArray<readonly [string, string]> = [
    ['plain select', "SELECT * FROM users WHERE id = "],
    ['lowercase', 'select name from accounts where email = ?'],
    ['insert', 'INSERT INTO audit_log (actor, action) VALUES ('],
    ['update', "UPDATE users SET display_name = '"],
    ['delete', 'DELETE FROM sessions WHERE token = '],
    ['union injection', "' UNION ALL SELECT password FROM users --"],
    ['cte', 'WITH recent AS (SELECT id FROM orders) SELECT * FROM recent'],
    ['fragment', " WHERE username = '"],
    ['ddl', 'DROP TABLE IF EXISTS staging_users'],
  ];

  /* The prose below is this project's OWN text. Both blobs were reported as
   * SQL injection by the previous recogniser, which asked only whether a verb,
   * a clause and a keyword each appeared SOMEWHERE in the string. In the first
   * one the verb was "call" (from "a call into a third-party package") and the
   * clause was "where" (from "where imports resolve") - two different
   * sentences, sixty characters apart. */
  const SQL_MUST_NOT_MATCH: ReadonlyArray<readonly [string, string]> = [
    [
      'own flow-verified disclaimer',
      'FLOW-VERIFIED: the value was followed hop by hop, across function boundaries and - ' +
        'where imports resolve - across files. Only files included in this scan are resolved: ' +
        'a call into a third-party package, a dynamic import, or a name several modules define ' +
        'all end the trace.',
    ],
    [
      'own OWASP panel copy',
      'No category here is comprehensively covered. Where a rule exists it looks for one ' +
        'or two shapes drawn from that category, so treat a covered category as partly ' +
        'examined rather than cleared.',
    ],
    ['a greeting', 'Hello ' + 'name' + ', welcome back to the dashboard'],
    ['a file path', 'src/core/analyze.ts:421 set from the values above'],
    ['prose with one keyword', 'Update the table of contents before you commit this'],
  ];

  let sqlOk = true;
  for (const [label, text] of SQL_MUST_MATCH) {
    if (looksLikeSql(text)) continue;
    sqlOk = false;
    console.log(`    ${color.red(g('cross'))} looksLikeSql MISSED real SQL: ${label}`);
  }
  for (const [label, text] of SQL_MUST_NOT_MATCH) {
    if (!looksLikeSql(text)) continue;
    sqlOk = false;
    console.log(`    ${color.red(g('cross'))} looksLikeSql matched prose: ${label}`);
  }
  if (sqlOk) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} looksLikeSql: ${SQL_MUST_MATCH.length} queries matched, ` +
        `${SQL_MUST_NOT_MATCH.length} prose blobs rejected`,
    );
  } else failed++;

  /* Vendor documentation examples. AKIAIOSFODNN7EXAMPLE is the string AWS
   * prints in its own docs; reporting it as a hardcoded credential is not a
   * loud true positive, it is a false statement. */
  const SECRET_CASES: ReadonlyArray<readonly [string, boolean]> = [
    ['AKIAIOSFODNN7EXAMPLE', false],
    ['wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', false],
    ['const key = "AKIAIOSFODNN7EXAMPLE"; // inside a longer demo snippet', false],
    ['AKIA4KTQVBN2WZRJH7PL', true],
    ['ghp_16C7e42F292c6912E7710c838347Ae178B4a', true],
  ];
  let secretOk = true;
  for (const [value, shouldReport] of SECRET_CASES) {
    const reported = matchKnownSecret(value) !== null;
    if (reported === shouldReport) continue;
    secretOk = false;
    console.log(
      `    ${color.red(g('cross'))} matchKnownSecret(${value.slice(0, 28)}...) ` +
        `= ${reported}, expected ${shouldReport}`,
    );
  }
  if (secretOk) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} vendor doc examples are not credentials ` +
        `(${SECRET_CASES.length} cases, real-format keys still reported)`,
    );
  } else failed++;

  /* A finding that survives the safety proof must SAY WHAT SURVIVED. "Something
   * on this line is unescaped" sends the reader to re-audit a forty-line
   * template; naming `note` or `JSON.stringify(state)` ends the question in two
   * seconds. This check exists because the first version of the proof could
   * return "not proven" while recording no reason at all. */
  const partialEscape = findings.filter(
    (f) => f.ruleId === 'xss' && f.location.file.endsWith('partial-escape.js'),
  );
  const unnamed = partialEscape.filter((f) => !/could NOT prove safe: `/.test(f.reasoning));
  const stillClaimsBlind = partialEscape.filter((f) =>
    /No escaping or sanitiser call is visible/.test(f.reasoning),
  );
  if (partialEscape.length >= 4 && unnamed.length === 0 && stillClaimsBlind.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} every surviving XSS finding names the value it could ` +
        `not prove safe (${partialEscape.length} checked)`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} ${unnamed.length} finding(s) name nothing, ` +
        `${stillClaimsBlind.length} still claim no escaper is visible ` +
        `(of ${partialEscape.length})`,
    );
  }

  console.log(`\n${color.bold('  Test-file ranking')}`);
  /*
   * NOTHING ELSE IN THIS SUITE CAN CATCH A REGRESSION HERE.
   *
   * Every fixture lives under tests/, so every fixture finding is a test-file
   * finding - which means if the policy were deleted tomorrow, all 174 other
   * checks would still pass and the only symptom would be a pandas scan going
   * back to 65 criticals. So the policy gets a check of its own: the SAME source
   * at two paths, asserting the finding survives and only its rank moves.
   */
  const rankSource = 'import pickle\ndef f(fh):\n    return pickle.load(fh)\n';
  const inSrc = await analyze([{ path: 'src/app/loader.py', source: rankSource }]);
  const inTest = await analyze([{ path: 'src/app/tests/test_loader.py', source: rankSource }]);
  const srcHit = inSrc.findings.find((f) => f.ruleId === 'unsafe-deserialization');
  const testHit = inTest.findings.find((f) => f.ruleId === 'unsafe-deserialization');
  if (srcHit?.severity === 'critical' && testHit?.severity === 'medium') {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} the same finding ranks critical in src/ and medium ` +
        `under tests/ - kept, not dropped`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} expected critical in src/ and medium under tests/, got ` +
        `${srcHit?.severity ?? 'nothing'} and ${testHit?.severity ?? 'nothing'}`,
    );
  }
  // A traced path is deliberately NOT downgraded - isTestPath is a filename
  // guess and pandas ships pandas/_testing/. Assert that exemption holds.
  const flowSource =
    'const express = require("express");\n' +
    'const app = express();\n' +
    'app.get("/x", (req, res) => {\n' +
    '  const { exec } = require("child_process");\n' +
    '  exec("ls " + req.query.dir);\n' +
    '});\n';
  const flowInTest = await analyze([{ path: 'tests/routes.test.js', source: flowSource }]);
  const traced = flowInTest.findings.find((f) => f.verified);
  if (traced && traced.severity === 'critical') {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} a flow-verified finding under tests/ keeps full severity`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} flow-verified finding under tests/ was ` +
        `${traced ? `downgraded to ${traced.severity}` : 'not produced at all'}`,
    );
  }

  console.log(`\n${color.bold('  SARIF export')}`);
  /*
   * SARIF IS WHERE THE HONESTY LABEL IS EASIEST TO LOSE.
   *
   * The format has no field meaning "we did not verify this one". In CI nobody
   * reads a terminal, and a red annotation looks equally certain whether we
   * proved the flow or pattern-matched a line. So the two things that carry the
   * distinction across get asserted rather than assumed: the label opens every
   * message, and a codeFlow exists if and ONLY if the finding was traced.
   *
   * The document SHAPE is checked by the compiler (report/sarif.ts is typed as
   * Sarif.Log), so these checks are about meaning, not structure.
   */
  const sarifText = renderSarif(result, false);
  let sarifOk = true;
  const sarifProblems: string[] = [];
  try {
    const log = JSON.parse(sarifText) as {
      runs: Array<{
        results: Array<{
          ruleId: string;
          message: { text: string };
          codeFlows?: unknown[];
          properties?: { confidence?: string };
        }>;
      }>;
    };
    const rows = log.runs[0]?.results ?? [];
    if (rows.length !== result.findings.length) {
      sarifProblems.push(`${rows.length} SARIF results for ${result.findings.length} findings`);
    }
    for (const [index, row] of rows.entries()) {
      const finding = result.findings[index];
      if (!finding) continue;
      const hasFlow = Array.isArray(row.codeFlows) && row.codeFlows.length > 0;
      if (finding.verified !== hasFlow) {
        sarifProblems.push(
          `${row.ruleId}: verified=${finding.verified} but codeFlow=${hasFlow}`,
        );
      }
      const expected = finding.verified ? '[flow-verified]' : '[signature-based, UNVERIFIED]';
      if (!row.message.text.startsWith(expected)) {
        sarifProblems.push(`${row.ruleId}: message does not open with ${expected}`);
      }
      if (row.properties?.confidence !== finding.confidence) {
        sarifProblems.push(`${row.ruleId}: properties.confidence disagrees with the finding`);
      }
    }
  } catch (error) {
    sarifOk = false;
    sarifProblems.push(`SARIF output is not parseable JSON: ${(error as Error).message}`);
  }
  if (sarifOk && sarifProblems.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} every SARIF result carries its confidence label, and a ` +
        `codeFlow exists exactly when the flow was traced (${result.findings.length} checked)`,
    );
  } else {
    failed++;
    for (const hit of sarifProblems.slice(0, 4)) console.log(`    ${color.red(g('cross'))} ${hit}`);
  }

  /*
   * ---- keyed mutators declare a way back out ----
   *
   * A keyed mutator narrows taint: after `req.setAttribute(k, dirty)`, only the
   * declared readers see the taint again and every other method on `req` comes
   * back clean. That is a SILENCING mechanism, and the one thing it must never
   * be is silently incomplete - a keyed mutator with no reader would file taint
   * into a compartment nothing can ever open, quietly losing every real flow
   * through it.
   *
   * So the pairing is checked rather than remembered:
   *   - a keyed mutator must also be an ordinary mutator (it still dirties)
   *   - declaring keyed mutators without readers is a taint black hole
   *   - a method cannot be both, or taint would round-trip through itself
   */
  /*
   * ---- every tracer finding passes the retraction gate ----
   *
   * THE FOURTH TIME THIS EXACT SPLIT HAS COST A FIX.
   *
   * `checkTaintAtSink` carries a comment saying it was factored out "so a
   * second kind of sink cannot get half of this right". Two more emission
   * sites then grew their own inline copies of the sanitised check anyway, so
   * teaching the factored one about validation guards fixed the fixture and
   * left DVWA's `exec/impossible.php` still reported - it reaches its sink
   * through a path that had never heard of the new rule.
   *
   * Same shape as the Go `digest.Write` false positive, the command-injection
   * aliasing miss, and the WordPress escaper fix that appeared not to work: a
   * reason to stay quiet taught in one place and missed in another. A comment
   * asking future edits to route through one function is a wish. This is the
   * check.
   */
  console.log(`\n${color.bold('  Retraction gate')}`);
  {
    const tracerSource = await readFile(path.resolve(HERE, '../../src/taint/tracer.ts'), 'utf8');
    const emissions = (tracerSource.match(/results\.push\(/g) ?? []).length;
    const gates = (tracerSource.match(/retracted\(taint/g) ?? []).length;
    if (emissions > 0 && gates >= emissions) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} all ${emissions} tracer finding sites sit behind a retraction gate`,
      );
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} ${emissions} results.push site(s) but only ${gates} retracted() ` +
          `gate(s) - a finding can be emitted without checking sanitisers or guards`,
      );
    }
  }

  console.log(`\n${color.bold('  Keyed mutators')}`);
  {
    const problems: string[] = [];
    let checkedLanguages = 0;
    for (const [language, dict] of Object.entries(TAINT_DICTIONARIES)) {
      const keyed = dict.keyedMutators ?? [];
      if (keyed.length === 0) continue;
      checkedLanguages++;
      const readers = dict.keyedReaders ?? [];
      const mutators = dict.mutators ?? [];
      if (readers.length === 0) {
        problems.push(`${language}: keyedMutators declared with no keyedReaders - taint would be lost`);
      }
      for (const name of keyed) {
        if (!mutators.includes(name)) {
          problems.push(`${language}: \`${name}\` is a keyed mutator but not a mutator`);
        }
        if (readers.includes(name)) {
          problems.push(`${language}: \`${name}\` is both a keyed writer and a keyed reader`);
        }
      }
    }
    if (problems.length === 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} every keyed mutator dirties its object and declares a reader ` +
          `(${checkedLanguages} language(s))`,
      );
    } else {
      failed++;
      for (const problem of problems) console.log(`    ${color.red(g('cross'))} ${problem}`);
    }
  }

  console.log(`\n${color.bold('  Sink scoping')}`);
  /*
   * THE CLASS, NOT THE INSTANCE.
   *
   * Six separate false positives this month were one bug wearing six names:
   *
   *     document.write      matched process.stdout.write        (VS Code)
   *     Map.get             matched as an outbound HTTP request (VS Code)
   *     RegExp.exec         matched as a shell command          (gitea)
   *     super.execute()     matched as a SQL query              (WebGoat)
   *     esc_html() output   matched as unescaped HTML           (WordPress)
   *     fmt.Sprintf callee  matched as a spliced-in value       (gitea)
   *
   * Every one was found by scanning a large repository, reading a finding that
   * made no sense, and fixing THAT ENTRY. The class was audited once, printed
   * in a table, and walked past - the `exec` bug was visible in that table
   * before it produced a critical flow-verified claim about a regular
   * expression in browser code.
   *
   * So the rule gets written down here instead of remembered: a sink method
   * whose NAME is one that unrelated APIs also use must say something about the
   * receiver. Not "should" - the suite fails. A new sink entry added next year
   * with a generic name is red on the day it is written, which is the only
   * moment the author knows what they meant.
   *
   * A content check (does the text look like SQL / like HTML?) is NOT accepted
   * as a substitute. It narrows the value, not the object, and the six above
   * were all wrong about the OBJECT.
   */
  const GENERIC_METHOD_NAMES = new Set([
    // Names that belong to many unrelated APIs. Kept deliberately short and
    // evidence-led: each of these is a method on at least three standard types
    // in the languages this tool parses.
    'get', 'set', 'put', 'post', 'add', 'append', 'prepend', 'insert',
    'write', 'read', 'run', 'call', 'exec', 'execute', 'query', 'send',
    'load', 'save', 'open', 'close', 'text', 'html', 'url', 'js',
    'request', 'response', 'format', 'parse', 'process', 'handle',
    'apply', 'invoke', 'render', 'update', 'create', 'delete', 'remove',
    'find', 'filter', 'map', 'join', 'split', 'replace', 'emit', 'raw',
  ]);
  const unscopedGenerics: string[] = [];
  for (const [lang, dictionary] of Object.entries(TAINT_DICTIONARIES)) {
    if (lang === 'typescript') continue; // shares JavaScript's object
    for (const sink of dictionary.callSinks ?? []) {
      const scoped =
        !!sink.requiredReceivers?.length ||
        !!sink.bareOnly ||
        !!sink.allowedReceivers?.length ||
        !!sink.receiverPattern;
      if (scoped) continue;
      for (const method of sink.methods) {
        if (GENERIC_METHOD_NAMES.has(method.toLowerCase())) {
          unscopedGenerics.push(`${lang}/${sink.kind}: \`${method}\` has no receiver constraint`);
        }
      }
    }
  }
  if (unscopedGenerics.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} no sink matches a generic method name without saying ` +
        `something about the receiver`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} ${unscopedGenerics.length} sink method(s) match a common ` +
        `name with no receiver constraint:`,
    );
    for (const hit of unscopedGenerics.slice(0, 12)) {
      console.log(`      ${color.red(g('middot'))} ${hit}`);
    }
  }

  /*
   * A CONSTRAINT CAN BE PRESENT AND STILL BE WRONG.
   *
   * The sink-scoping check above asks whether a generic method name says
   * anything about its receiver. It cannot ask whether what it says is TRUE.
   *
   * Keycloak found the difference. Java's XSS sink was scoped - it had a
   * receiver pattern - and the pattern contained `\bout\b`, so
   * `System.out.println(...)` matched and four console writes were reported as
   * "reaches an HTTP response body written without escaping", flow-verified, at
   * high severity. Same shape as process.stdout.write read as document.write,
   * and fmt.Fprintf(buf) read as page output. Three languages, one mistake.
   *
   * So every XSS destination pattern is tested against the places output goes
   * that are NOT a page. A console is not a browser in any language, and a
   * pattern that cannot tell them apart is not a constraint.
   */
  console.log(`\n${color.bold('  Destination patterns')}`);
  const NOT_A_PAGE = [
    'System.out', 'System.err', 'os.Stdout', 'os.Stderr',
    'process.stdout', 'process.stderr', 'console', 'logger', 'buf',
  ];
  const leaks: string[] = [];
  for (const [lang, dictionary] of Object.entries(TAINT_DICTIONARIES)) {
    if (lang === 'typescript') continue;
    for (const sink of dictionary.callSinks ?? []) {
      if (sink.kind !== 'xss') continue;
      const pattern = sink.receiverPattern ?? sink.writerArgPattern;
      if (!pattern) continue;
      for (const destination of NOT_A_PAGE) {
        if (pattern.test(destination)) {
          leaks.push(`${lang} ${JSON.stringify(sink.methods).slice(0, 40)} matches \`${destination}\``);
        }
      }
    }
  }
  if (leaks.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} no XSS destination pattern matches a console, a log or a ` +
        `buffer (${NOT_A_PAGE.length} checked per sink)`,
    );
  } else {
    failed++;
    for (const leak of leaks.slice(0, 6)) console.log(`    ${color.red(g('cross'))} ${leak}`);
  }

  console.log(`\n${color.bold('  Documentation drift')}`);
  const phaseMention = /\bPhase\s*\d/i;
  const userFacingText: Array<{ where: string; text: string }> = [];
  for (const rule of ALL_RULES) {
    userFacingText.push({ where: `${rule.id}.explanation`, text: rule.explanation });
    userFacingText.push({ where: `${rule.id}.limitations`, text: rule.limitations });
    for (const [language, support] of Object.entries(rule.support)) {
      if (support) userFacingText.push({ where: `${rule.id}/${language}`, text: support.note });
    }
  }
  for (const language of LANGUAGES) {
    userFacingText.push({ where: `languages/${language.id}`, text: language.notes });
    userFacingText.push({
      where: `taint-coverage/${language.id}`,
      text: TAINT_COVERAGE_NOTES[language.id],
    });
  }
  for (const finding of findings) {
    userFacingText.push({ where: `finding/${finding.ruleId}`, text: finding.limitations });
    userFacingText.push({ where: `finding/${finding.ruleId}`, text: finding.reasoning });
  }
  // The capability block is printed on EVERY scan and shown on the web page, so
  // it is the most-read text we produce - and it was the one place this check
  // did not look. It was hiding a stale "Phase 5." when that was noticed.
  const engine = ENGINE_CAPABILITIES;
  userFacingText.push({ where: 'engine/analysisLabel', text: engine.analysisLabel });
  for (const line of engine.implemented) {
    userFacingText.push({ where: 'engine/implemented', text: line });
  }
  for (const line of engine.notImplemented) {
    userFacingText.push({ where: 'engine/notImplemented', text: line });
  }
  for (const [key, text] of Object.entries(engine.meaningOfConfidence)) {
    userFacingText.push({ where: `engine/confidence/${key}`, text });
  }
  // The banner once read "PHASE 3C" while package.json read "0.5.0-phase2" -
  // two numbers for one build, both printed to the user. One source of truth.
  const manifest = JSON.parse(
    // dist/tests -> project root, the same hop FIXTURES makes above.
    await readFile(path.resolve(HERE, '../../package.json'), 'utf8'),
  ) as { version: string };
  if (manifest.version === ENGINE_CAPABILITIES.version) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} engine version matches package.json (${manifest.version})`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} engine reports ${ENGINE_CAPABILITIES.version} but package.json says ${manifest.version}`,
    );
  }

  /* The check above only sees text a fixture actually triggered. A rule branch
   * no fixture exercises can carry stale text for months - and did: the
   * sql-injection assignment branch still said "that is Phase 3 work" long
   * after Phase 3 shipped, because no fixture reached it.
   *
   * So also read the SOURCE of every rule and report module and look inside its
   * string literals. Comments are left alone on purpose: they record why the
   * code looks like it does, and build history is legitimate there. Only text
   * that can reach a user is held to the rule. */
  /*
   * `tests` is in this list because of a bug this very check should have
   * caught and did not. The suite printed
   *
   *     all five languages exercised: go, java, javascript, php, python, typescript
   *
   * - five, listing six - for a whole day after PHP was added. The drift rules
   * scanned every rule's metadata and never the code that PRINTS, so the one
   * file whose entire job is checking for stale claims was the one file making
   * one. A checker exempt from its own check is not a checker.
   */
  /*
   * '.' IS IN THIS LIST BECAUSE cli.ts WAS NOT.
   *
   * The help text printed "in all five languages" for weeks after PHP shipped -
   * the first thing `defuse --help` says, to every user. The five
   * subdirectories below were scanned; src/cli.ts sits at the ROOT of src/ and
   * was walked by nothing.
   *
   * Fourth time a hand-written language claim has gone stale, and the third
   * time the fix was "the checker was not looking there". Naming '.' rather
   * than adding 'cli' means a new top-level file is covered on the day it is
   * written instead of on the day it is wrong.
   */
  const sourceDirs = ['.', 'rules', 'report', 'core', 'taint', 'parse'];
  const literal = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
  const inSource: string[] = [];
  for (const dir of [...sourceDirs, 'tests']) {
    const base =
      dir === 'tests' ? path.resolve(HERE, '../../tests') : path.resolve(HERE, '../../src', dir);
    // '.' means the src/ root only - its subdirectories are listed separately
    // and walking them twice would double-report the same literal.
    const shallow = dir === '.';
    const walkDir = async (at: string): Promise<void> => {
      for (const entry of await readdir(at, { withFileTypes: true })) {
        const full = path.join(at, entry.name);
        if (entry.isDirectory()) {
          if (!shallow) await walkDir(full);
          continue;
        }
        if (entry.name.endsWith('.ts')) {
          const text = await readFile(full, 'utf8');
          // Strip comments first so build-history notes are not flagged.
          const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
          for (const match of code.matchAll(literal)) {
            const value = match[2] ?? '';
            if (phaseMention.test(value) || /\b(three|four|five|six|seven|eight)\s+languages?\b/i.test(value)) {
              inSource.push(`${dir}/${entry.name}: ${value.slice(0, 60)}`);
            }
          }
        }
      }
    };
    await walkDir(base);
  }
  if (inSource.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} no string literal in src/{${sourceDirs.join(',')}} or tests/ ` +
        `names a phase number or a hard-coded language count`,
    );
  } else {
    failed++;
    for (const hit of inSource.slice(0, 6)) console.log(`    ${color.red(g('cross'))} ${hit}`);
  }

  /*
   * THE SAME DRIFT, IN THE ONE DIRECTORY THE DRIFT CHECK NEVER READ.
   *
   * The browser UI's landing card said
   *
   *     JavaScript \u00b7 TypeScript \u00b7 Python \u00b7 Java \u00b7 Go
   *
   * for weeks after PHP shipped - the front page of the tool advertising five
   * of its six languages, to every person who opened it. Third time a
   * hand-written language list has gone stale, and the check above, which
   * exists precisely for this, walks src/{rules,report,core,taint,parse} and
   * tests/ and has never once looked at ui/.
   *
   * A checker exempt from its own check is not a checker - that sentence is
   * already written above this one about a different directory, which is the
   * whole lesson: fixing the instance is not fixing the class.
   *
   * ui/engine/ is skipped because it is compiled from src/ and the rules above
   * already cover its sources.
   */
  const languageNames = LANGUAGES.map((l) => l.displayName);
  const partialLists: string[] = [];
  for (const rel of ['index.html', 'app.js', 'worker.js']) {
    const full = path.resolve(HERE, '../../ui', rel);
    let text: string;
    try {
      text = await readFile(full, 'utf8');
    } catch {
      continue; // ui/ is optional in a source-only checkout
    }
    // Strip comments - build-history notes are allowed to name an old list.
    const code = text
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    for (const [index, line] of code.split('\n').entries()) {
      /*
       * ESCAPED, because a display name is not a regular expression.
       *
       * This line built `/\bC++\b/` the moment C++ was added and crashed the
       * whole runner with "Nothing to repeat". It had been correct for six
       * languages by luck - every one of their names happened to be plain
       * letters. A word boundary next to `+` does not mean what it looks like
       * either, so the boundary is only applied where the name actually starts
       * and ends with a word character.
       */
      const named = languageNames.filter((name) => {
        const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const left = /^\w/.test(name) ? '\\b' : '';
        const right = /\w$/.test(name) ? '\\b' : '';
        return new RegExp(`${left}${escaped}${right}`).test(line);
      });
      if (named.length >= 2 && named.length < languageNames.length) {
        partialLists.push(`ui/${rel}:${index + 1} lists ${named.join(', ')} - missing ${languageNames.filter((n) => !named.includes(n)).join(', ')}`);
      }
    }
  }
  if (partialLists.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} no file in ui/ writes a partial language list ` +
        `(${languageNames.length} languages, derived at runtime)`,
    );
  } else {
    failed++;
    for (const hit of partialLists.slice(0, 4)) console.log(`    ${color.red(g('cross'))} ${hit}`);
  }

  const stale = userFacingText.filter((entry) => phaseMention.test(entry.text));
  if (stale.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} no user-facing text names a phase number ` +
        `(${userFacingText.length} strings checked)`,
    );
  } else {
    failed++;
    for (const entry of [...new Set(stale.map((s) => s.where))].slice(0, 8)) {
      console.log(`    ${color.red(g('cross'))} ${entry} mentions a phase number - describe the mechanism instead`);
    }
  }

  /*
   * A COUNT WRITTEN IN PROSE IS A COUNT THAT GOES STALE.
   *
   * Adding PHP made the report say "Taint analysis in ALL FIVE languages"
   * while listing six, and name only five in the parsing line. Nobody had
   * lied - the sentence was true when it was written and nothing forced it to
   * stay true. That is the same failure mode as the phase numbers above, so it
   * gets the same treatment: the text is generated from LANGUAGES, and this
   * check makes sure nobody hand-writes it back.
   */
  const ALL_LANGUAGE_NAMES = LANGUAGES.map((l) => l.displayName);
  const spelledNumbers = /\b(three|four|five|six|seven|eight)\s+languages?\b/i;
  const countClaims = userFacingText.filter((entry) => spelledNumbers.test(entry.text));
  const missingLanguage = ALL_LANGUAGE_NAMES.filter(
    (name) => !ENGINE_CAPABILITIES.implemented.some((line) => line.includes(name)),
  );
  if (countClaims.length === 0 && missingLanguage.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} no user-facing text hard-codes a language count, ` +
        `and all ${ALL_LANGUAGE_NAMES.length} languages are named in the capability list`,
    );
  } else {
    failed++;
    for (const entry of countClaims.slice(0, 4)) {
      console.log(
        `    ${color.red(g('cross'))} ${entry.where} spells out a language count - ` +
          `derive it from LANGUAGES instead`,
      );
    }
    for (const name of missingLanguage) {
      console.log(`    ${color.red(g('cross'))} ${name} is supported but named nowhere in ENGINE_CAPABILITIES`);
    }
  }

  /* ---- parsing health across every language ---- */
  console.log(`\n${color.bold('  Parser health')}`);
  if (result.parseProblems.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} ${result.stats.filesParsed} fixture files parsed with zero errors`,
    );
  } else {
    failed++;
    for (const problem of result.parseProblems) {
      console.log(`    ${color.red(g('cross'))} ${path.basename(problem.file)}: ${problem.issues[0]?.text}`);
    }
  }
  const languagesSeen = Object.keys(result.byLanguage).sort();
  const expectedLanguages = ['go', 'java', 'javascript', 'python', 'typescript'];
  const missing = expectedLanguages.filter((l) => !languagesSeen.includes(l));
  if (missing.length === 0) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} all ${languagesSeen.length} languages exercised: ` +
        `${languagesSeen.join(', ')}`,
    );
  } else {
    failed++;
    console.log(`    ${color.red(g('cross'))} no fixture exercised: ${missing.join(', ')}`);
  }

  /*
   * EVERY LANGUAGE THAT CLAIMS DATA FLOW MUST PROVE IT, AND MUST ALSO PROVE
   * IT CAN STAY QUIET.
   *
   * This check exists because the same hole was found twice in two days.
   *
   * TypeScript had six fixture findings and every one was signature-based, so
   * not a single TypeScript value had ever been traced from a source to a sink
   * - while the coverage note said data flow was "identical to JavaScript".
   * When it was finally tested, one construct had been broken since the day
   * the language was added.
   *
   * C++ had the mirror image: five flow-verified findings and no safe fixture
   * at all, so nothing asserted the engine stays quiet on correct C++. A rule
   * that fires on everything passes every positive test ever written.
   *
   * Both were invisible because the suite counted checks, not coverage. One
   * check per language, so a gap names the language it is in rather than
   * hiding inside a total.
   *
   * A language needs BOTH halves. A proven finding shows the tracer reaches
   * the end; a silent file shows it knows when to stop. Either alone is half a
   * language's evidence.
   */
  console.log(`\n${color.bold('  Per-language evidence')}`);
  {
    const taintLanguages = Object.keys(TAINT_DICTIONARIES).sort();
    const provenIn = new Map<string, string>();
    for (const finding of findings) {
      if (finding.confidence !== 'flow-verified') continue;
      const match = detectLanguage(finding.location.file);
      if (match && !provenIn.has(match.spec.id)) {
        provenIn.set(match.spec.id, path.basename(finding.location.file));
      }
    }
    const silentIn = new Map<string, string>();
    for (const expectation of safe) {
      if (!expectation.expectNone) continue;
      const match = detectLanguage(expectation.file);
      if (match && !silentIn.has(match.spec.id)) {
        silentIn.set(match.spec.id, path.basename(expectation.file));
      }
    }

    for (const language of taintLanguages) {
      const proven = provenIn.get(language);
      const silent = silentIn.get(language);
      if (proven && silent) {
        passed++;
        console.log(
          `    ${color.green(g('tick'))} ${language.padEnd(11)} proven in ${proven}, ` +
            `silent in ${silent}`,
        );
      } else {
        failed++;
        const lacks = !proven
          ? 'no fixture ever produces a FLOW-VERIFIED finding here - the tracer is unproven in this language'
          : 'no safe fixture - nothing asserts the engine stays quiet on correct code';
        console.log(`    ${color.red(g('cross'))} ${language.padEnd(11)} ${lacks}`);
      }
    }
  }

  /*
   * ---- the README's own numbers ----
   *
   * FIFTH DRIFT BUG. The capabilities text, the test-suite output, ui/index.html
   * and src/cli.ts have each gone stale in turn, and each time the fix was to
   * derive the number instead of writing it down. The README was the one place
   * still writing it down: it claimed 112 checks while the suite ran 198.
   *
   * A README that overstates is only embarrassing. A README that UNDERSTATES is
   * worse than it looks, because "112 checks" is the number a client reads as
   * the evidence behind every claim in the document. Either way it is a figure
   * about this tool that this tool was not checking, which is the whole disease.
   *
   * This check runs LAST and counts itself: the total it compares against is
   * `passed + failed + 1`, which is the same number the summary line prints
   * below whether this check passes or fails.
   */
  /*
   * ---- the README's DERIVED BLOCKS ----
   *
   * A NARROW INSTRUMENT TRUSTED AS A BROAD ONE.
   *
   * The check below this one has guarded the README's test-count line for some
   * time, and it passed the whole while. Pointing a fresh reader at the repo
   * found what it was not looking at:
   *
   *     README said   5 rules       registry ships  8
   *     README said   5 languages   languages.ts    6, PHP absent entirely
   *     README said   "Not SARIF"   report/sarif.ts is a SARIF 2.1.0 exporter
   *     README said   13.8% recall  the scorer measures 76.4%
   *
   * Every one had been true when written. The check-count assertion was the
   * right idea applied to exactly one sentence, and passing it was read as
   * "the README is consistent" rather than "the README is consistent about the
   * one line I taught it to read".
   *
   * So the counts, the coverage matrix and the benchmark table are generated
   * now, and this regenerates them and compares. Prose outside the blocks stays
   * hand-written on purpose - narrative is not derivable and should not pretend
   * to be. The fix when this fails is `npm run sync:readme`.
   */
  console.log(`\n${color.bold('  README derived blocks')}`);
  const readmePath = path.resolve(HERE, '../../README.md');
  {
    const markdown = await readFile(readmePath, 'utf8');
    const resultPath = path.resolve(HERE, '../../docs/benchmark-result.json');
    const expected: Array<[string, string]> = [
      ['rule-matrix', renderRuleMatrix()],
      ['counts', renderCounts()],
    ];
    let benchmarkNote = '';
    try {
      const result = JSON.parse(await readFile(resultPath, 'utf8')) as BenchmarkResult;
      expected.push(['benchmark', renderBenchmark(result)]);
      if (result.engineVersion !== ENGINE_CAPABILITIES.version) {
        benchmarkNote =
          ` (measured on ${result.engineVersion}, engine is now ` +
          `${ENGINE_CAPABILITIES.version} - re-run \`npm run benchmark\`)`;
      }
    } catch {
      benchmarkNote = ' (docs/benchmark-result.json missing - run `npm run benchmark`)';
    }

    /*
     * THE LABEL SPLIT IS GUARDED TOO.
     *
     * It was added as a derived block and left out of this list for exactly
     * one commit, which is one commit longer than a figure should be able to
     * drift unwatched. The block quotes the number the whole product rests on
     * - what the green label is actually worth - so it is the last one that
     * should be allowed to go quietly stale.
     */
    const splitPath = path.resolve(HERE, '../../docs/label-split-result.json');
    try {
      const split = JSON.parse(await readFile(splitPath, 'utf8')) as LabelSplitResult;
      expected.push(['label-split', renderLabelSplit(split)]);
      if (split.engineVersion !== ENGINE_CAPABILITIES.version) {
        benchmarkNote +=
          ` (label split measured on ${split.engineVersion}, engine is now ` +
          `${ENGINE_CAPABILITIES.version} - re-run \`npm run label-split\`)`;
      }
    } catch {
      benchmarkNote += ' (docs/label-split-result.json missing - run `npm run label-split`)';
    }

    const stale: string[] = [];
    for (const [name, body] of expected) {
      const actual = readBlock(markdown, name);
      if (actual === null) stale.push(`block "${name}" is missing from README.md`);
      else if (actual !== body.trim()) stale.push(`block "${name}" disagrees with the registry`);
    }
    if (stale.length === 0 && benchmarkNote === '') {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} ${expected.length} generated blocks match the registry ` +
          `and the recorded benchmark`,
      );
    } else {
      failed++;
      for (const problem of stale) console.log(`    ${color.red(g('cross'))} ${problem}`);
      if (benchmarkNote) console.log(`    ${color.red(g('cross'))} benchmark${benchmarkNote}`);
      console.log(`      ${color.dim('fix: npm run sync:readme')}`);
    }
  }

  /* ------------------------------------------------------------------ *
   * THE COVERAGE MATRIX MUST NOT CONTRADICT THE ENGINE.
   *
   * There are two independent paths to a finding, and only one of them reads
   * the rule support table:
   *
   *   the SIGNATURE pass  ->  rulesForLanguage(), which SKIPS any rule whose
   *                           support entry says not-implemented
   *   the TAINT pass      ->  reaches a rule by id through SINK_KIND_RULE, and
   *                           never consults support at all
   *
   * So a language can be listed in a taint dictionary while every rule declares
   * it unsupported, and the scan will then print flow-verified findings
   * underneath a coverage line saying that rule is NOT IMPLEMENTED for that
   * language. That is exactly what happened when C and C++ were added: six
   * verified command injections in a C file, and `command-injection/c` in the
   * not-implemented list on the same screen.
   *
   * It is the worst class of bug this project can ship, because the thing being
   * wrong is the honesty report itself. This check ties the two halves together:
   * if a dictionary has a sink of kind K for language L, the rule that kind maps
   * to must admit it covers L.
   * ------------------------------------------------------------------ */
  /*
   * THE LANDING PAGE IS A DERIVED ARTEFACT TOO.
   *
   * docs/index.html quotes precision, recall and the coverage gap. A marketing
   * page is the likeliest thing in any project to keep a figure the code moved
   * past, and this one belongs to a tool whose entire claim is that it does not
   * say more than it knows. So it is generated from the same measurement files
   * the README reads, and regenerated here for comparison.
   *
   * The fix when this fails is `npm run build:site`.
   */
  console.log(`\n${color.bold('  Generated site')}`);
  {
    const sitePath = path.resolve(HERE, '../../docs/index.html');
    try {
      const [onDisk, benchmark, split] = await Promise.all([
        readFile(sitePath, 'utf8'),
        readFile(path.resolve(HERE, '../../docs/benchmark-result.json'), 'utf8'),
        readFile(path.resolve(HERE, '../../docs/label-split-result.json'), 'utf8'),
      ]);
      const expected = renderSite(
        JSON.parse(benchmark) as BenchmarkResult,
        JSON.parse(split) as LabelSplitResult,
      );
      if (onDisk === expected) {
        passed++;
        console.log(
          `    ${color.green(g('tick'))} docs/index.html matches the recorded measurements`,
        );
      } else {
        failed++;
        console.log(
          `    ${color.red(g('cross'))} docs/index.html is stale - a figure on the landing ` +
            `page disagrees with docs/*.json`,
        );
        console.log(`      ${color.dim('fix: npm run build:site')}`);
      }
    } catch {
      skipped++;
      console.log(
        `    ${color.dim('·')} SKIPPED: docs/index.html not built yet - run \`npm run build:site\`.`,
      );
    }
  }

  /*
   * THE LANDING PAGE MUST NOT CALL ANYBODY.
   *
   * It used to load its typefaces from fonts.googleapis.com, which meant the
   * homepage of a security tool handed a third party every visitor's IP address
   * and user agent before it had drawn a pixel. The fonts are served from this
   * origin now, and this check is here so nobody can quietly put that back by
   * pasting in an analytics snippet or a CDN link.
   *
   * Only things the browser fetches BY ITSELF count. An <a href> to GitHub is a
   * link a person chooses to follow, not a request the page makes, so anchors
   * are removed before looking.
   */
  console.log(`\n${color.bold('  Landing page network calls')}`);
  {
    try {
      const html = await readFile(path.resolve(HERE, '../../docs/index.html'), 'utf8');
      const withoutAnchors = html.replace(/<a\b[^>]*>/gi, '<a>');
      const auto: string[] = [];
      const patterns = [
        /<link\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi,
        /\bsrc\s*=\s*["']([^"']+)["']/gi,
        /url\(\s*["']?([^"')]+)["']?\s*\)/gi,
        /@import\s+["']([^"']+)["']/gi,
      ];
      for (const pattern of patterns) {
        for (const match of withoutAnchors.matchAll(pattern)) {
          const url = (match[1] ?? '').trim();
          if (/^(https?:)?\/\//i.test(url)) auto.push(url);
        }
      }
      if (auto.length === 0) {
        passed++;
        console.log(
          `    ${color.green(g('tick'))} docs/index.html fetches nothing from another origin`,
        );
      } else {
        failed++;
        console.log(
          `    ${color.red(g('cross'))} docs/index.html would call ${auto.length} external ` +
            `resource(s) on load: ${[...new Set(auto)].join(', ')}`,
        );
        console.log(
          `      ${color.dim('a visitor should not be announced to a third party by our own homepage')}`,
        );
      }
    } catch {
      skipped++;
      console.log(
        `    ${color.dim('·')} SKIPPED: docs/index.html not built yet - run \`npm run build:site\`.`,
      );
    }
  }


  /*
   * A FULLY-QUALIFIED JAVA REFERENCE IS AN EDGE TOO.
   *
   * This cannot be a fixture. The fixture directories are flat, and two Java
   * files in one directory are same-package, which resolves without an import
   * and so cannot express the bug at all. It needs two packages, so it needs a
   * tree, so it gets a temporary one.
   *
   * What it guards: `new a.b.C(x)` names another file as precisely as an import
   * does and used to produce no edge, so the call was never followed. That was
   * every one of the 69 cases the OWASP benchmark scored as a complete miss.
   * Fixing it took recall from 89.3% to 94.1% with the real false positives
   * unchanged at three.
   *
   * The benchmark would catch a regression here, but only when somebody runs
   * it against a 2,740-file corpus. This runs in milliseconds, on every commit.
   */
  console.log(`\n${color.bold('  Cross-file by qualified name')}`);
  {
    const tree = await mkdtemp(path.join(os.tmpdir(), 'defuse-qualified-'));
    try {
      await mkdir(path.join(tree, 'app', 'helpers'), { recursive: true });
      await mkdir(path.join(tree, 'app', 'web'), { recursive: true });
      await writeFile(
        path.join(tree, 'app', 'helpers', 'RequestWrapper.java'),
        [
          'package app.helpers;',
          'import javax.servlet.http.HttpServletRequest;',
          'public class RequestWrapper {',
          '    private HttpServletRequest request;',
          '    public RequestWrapper(HttpServletRequest request) { this.request = request; }',
          '    public String getTheParameter(String p) { return request.getParameter(p); }',
          '}',
        ].join('\n'),
      );
      // No import line anywhere - the class is named in full, inline.
      await writeFile(
        path.join(tree, 'app', 'web', 'Echo.java'),
        [
          'package app.web;',
          'import javax.servlet.http.*;',
          'public class Echo extends HttpServlet {',
          '    public void doPost(HttpServletRequest request, HttpServletResponse response)',
          '            throws Exception {',
          '        app.helpers.RequestWrapper w = new app.helpers.RequestWrapper(request);',
          '        String bar = w.getTheParameter("x");',
          '        response.getWriter().print(bar);',
          '    }',
          '}',
        ].join('\n'),
      );
      const crossFile = await scan(tree, {});
      const traced = crossFile.findings.filter(
        (f) => f.ruleId === 'xss' && f.confidence === 'flow-verified',
      );
      if (traced.length > 0) {
        passed++;
        console.log(
          `    ${color.green(g('tick'))} taint followed into a class named by its full ` +
            `package path, with no import statement`,
        );
      } else {
        failed++;
        console.log(
          `    ${color.red(g('cross'))} a class referenced as \`a.b.C\` built no cross-file ` +
            `edge - the call was not followed, so the flow is invisible`,
        );
      }
    } finally {
      await rm(tree, { recursive: true, force: true });
    }
  }

  /*
   * THE CONSTANT FOLDER MUST TERMINATE, AND THE SUITE COULD NOT SAY SO.
   *
   * Resolving a name folds whatever it was assigned; folding that can hit
   * another name. `a = b + 1; b = a + 1` is a loop, and the recursion had
   * nothing to stop it - the depth cap reset to zero on every hop through a
   * name, so it could never be reached.
   *
   * It survived a green suite, a 1,210-case benchmark and 175 generated
   * programs, and then fell over on a 10KB file: DVWA ships a packed sha256 as
   * one 10,417-character line with hundreds of one-letter names assigned from
   * each other. 1.1MB of source, 7GB of free memory, out of memory anyway.
   *
   * WHY NOTHING CAUGHT IT. Fixtures are small and readable on purpose, and
   * BenchmarkJava's generated cases are about forty lines each - neither
   * corpus contains code written by a minifier, and a blow-up that needs
   * hundreds of mutually-defined names in one scope cannot happen in either.
   * The corpus check found it, which is what a corpus check is for, but a
   * corpus that has to be cloned first is not a thing CI runs on every commit.
   *
   * So the shape comes in here, small enough to keep and nasty enough to hang.
   * A BUDGET RATHER THAN AN ASSERTION, because the failure is non-termination:
   * an assertion about the answer never gets to run. If this ever stops
   * finishing quickly, the answer stopped mattering.
   */
  console.log(`\n${color.bold('  Constant folder terminates')}`);
  {
    const names = Array.from({ length: 60 }, (_unused, index) => `n${index}`);
    // Every name defined from the next one, and the last from the first.
    const cycle = names.map(
      (name, index) => `  var ${name} = ${names[(index + 1) % names.length]} + 1;`,
    );
    /*
     * The same cycle, spelled as STRINGS, for the signature rules' constant
     * proof - which learned to follow `bar = baz` into another name, and so
     * grew its own copy of exactly the loop this check exists for.
     */
    const stringCycle = names.map(
      (name, index) => `  var s${name} = s${names[(index + 1) % names.length]};`,
    );
    const source = [
      "const db = require('./db');",
      'function packed(req) {',
      ...cycle,
      `  var bar = ${names[0]} > 3 ? 'constant' : req.query.p;`,
      '  db.query("SELECT * FROM t WHERE x = \'" + bar + "\'");',
      '}',
      'function stringLoop() {',
      ...stringCycle,
      `  db.query("SELECT * FROM t WHERE x = '" + s${names[0]} + "'");`,
      '}',
    ].join('\n');

    const tree = await mkdtemp(path.join(os.tmpdir(), 'defuse-folder-'));
    try {
      await writeFile(path.join(tree, 'packed.js'), source);
      const budgetMs = 10_000;
      const started = Date.now();
      /*
       * Caught, because the first thing this failure does is take the runner
       * down with it. Removing both guards and running this check produced
       * "Maximum call stack size exceeded" and no result line at all - a
       * crashed suite rather than a failed check, which reports the wrong
       * thing in CI and buries which check was running when it happened.
       */
      let crashed: string | null = null;
      let loopResult: Awaited<ReturnType<typeof scan>> | null = null;
      try {
        loopResult = await scan(tree, {});
      } catch (error) {
        crashed = error instanceof Error ? error.message : String(error);
      }
      const took = Date.now() - started;
      /*
       * TIME ALONE DID NOT CATCH IT, AND THAT WAS MEASURED.
       *
       * With the constant proof's cycle guard deleted, the string loop did not
       * hang - it overflowed the stack in a millisecond, analyze.ts caught the
       * crashing rule, recorded it, and dropped the finding. The scan finished
       * fast with NOTHING reported. A check that only timed it passed. So the
       * loop must still be REPORTED, and no rule may have thrown to get there.
       */
      const ruleThrew = (loopResult?.parseProblems ?? []).flatMap((p) => p.issues).find((i) =>
        /threw/.test(i.text),
      );
      const loopReported = (loopResult?.findings ?? []).some(
        (f) => f.ruleId === 'sql-injection' && f.location.startLine > names.length + 5,
      );
      if (crashed === null && (ruleThrew || !loopReported)) {
        crashed = ruleThrew
          ? `a rule threw (${ruleThrew.text}) and its finding was dropped`
          : 'the string loop was not reported - a rule crashed or gave up silently';
      }
      if (crashed !== null) {
        failed++;
        console.log(
          `    ${color.red(g('cross'))} ${names.length} mutually-defined names crashed the ` +
            `scan: ${crashed} - the folder is recursing through the cycle`,
        );
      } else if (took < budgetMs) {
        passed++;
        console.log(
          `    ${color.green(g('tick'))} ${names.length} mutually-defined names folded in ` +
            `${took}ms - a cycle costs nothing, rather than everything`,
        );
      } else {
        failed++;
        console.log(
          `    ${color.red(g('cross'))} took ${took}ms for ${names.length} names - the ` +
            `resolution depth is resetting again, or the cycle guard is not holding`,
        );
      }
    } finally {
      await rm(tree, { recursive: true, force: true });
    }
  }

  console.log(`\n${color.bold('  Coverage matrix vs engine')}`);
  {
    const contradictions: string[] = [];
    for (const [language, dictionary] of Object.entries(TAINT_DICTIONARIES)) {
      if (!dictionary) continue;
      const kinds = new Set<string>([
        ...dictionary.callSinks.map((sink) => sink.kind),
        ...dictionary.assignSinks.map((sink) => sink.kind),
        ...(dictionary.receiverSinks ?? []).map((sink) => sink.kind),
      ]);
      for (const kind of kinds) {
        const ruleId = SINK_KIND_RULE[kind as keyof typeof SINK_KIND_RULE];
        const rule = ALL_RULES.find((candidate) => candidate.id === ruleId);
        if (!rule) {
          contradictions.push(`${language}: sink kind "${kind}" maps to unknown rule "${ruleId}"`);
          continue;
        }
        const support = rule.support[language as keyof typeof rule.support];
        if (!support || support.status === 'not-implemented') {
          contradictions.push(
            `${ruleId}/${language}: the taint dictionary has a "${kind}" sink, so the engine ` +
              `CAN report this - but support says ${support?.status ?? 'nothing'}`,
          );
        }
      }
    }

    if (contradictions.length === 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} every language with a taint sink is declared supported ` +
          `by the rule that sink reports as`,
      );
    } else {
      failed++;
      for (const problem of contradictions.slice(0, 6)) {
        console.log(`    ${color.red(g('cross'))} ${problem}`);
      }
      if (contradictions.length > 6) {
        console.log(`      ${color.dim(`... and ${contradictions.length - 6} more`)}`);
      }
    }
  }

  /* ------------------------------------------------------------------ *
   * LICENCE - three places, one claim.
   *
   * The licence is stated in src/core/licence.ts, in package.json, in the
   * LICENSE file and in the README. Four copies of a legal fact is four chances
   * to be telling somebody something untrue, and this project's record with
   * duplicated facts is bad enough to be a policy: the README claimed 112
   * checks while 207 ran, and claimed 13.8% recall for about twenty versions
   * after that stopped being true.
   *
   * A wrong check count embarrasses the author. A wrong licence misleads
   * whoever relied on it, which is worse, so it gets a test.
   * ------------------------------------------------------------------ */
  console.log(`\n${color.bold('  Licence')}`);
  {
    const packageJson = JSON.parse(
      await readFile(path.resolve(HERE, "../../package.json"), 'utf8'),
    ) as { license?: string };

    if (packageJson.license === LICENCE_SPDX) {
      passed++;
      console.log(`    ${color.green(g('tick'))} package.json says ${LICENCE_SPDX}`);
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} package.json says "${packageJson.license ?? '(nothing)'}" ` +
          `but the engine says ${LICENCE_SPDX}`,
      );
    }

    let licenceText = '';
    try {
      licenceText = await readFile(path.resolve(HERE, "../../LICENSE"), 'utf8');
    } catch {
      /* absent - reported below */
    }
    // Length is checked as well as the heading: a LICENSE file that starts
    // correctly and was then truncated is the failure this would otherwise miss,
    // and the AGPL is ~34,000 characters.
    if (licenceText.startsWith(LICENCE_FILE_HEADING) && licenceText.length > 30000) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} LICENSE holds the full ${LICENCE_FILE_HEADING} ` +
          `(${licenceText.length.toLocaleString()} characters)`,
      );
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} LICENSE is missing, truncated, or is not the ` +
          `${LICENCE_FILE_HEADING} (${licenceText.length} characters)`,
      );
    }

    // The README is where a human looks first, so it has to agree too.
    const readmeText = await readFile(readmePath, 'utf8');
    if (readmeText.includes(LICENCE_SPDX)) {
      passed++;
      console.log(`    ${color.green(g('tick'))} README names ${LICENCE_SPDX}`);
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} README never names ${LICENCE_SPDX} - a reader has ` +
          `no way to learn the terms without opening LICENSE`,
      );
    }

    /**
     * The packaged tarball must contain the source, not only the build output.
     *
     * This is a licence requirement rather than a nicety. Shipping compiled
     * dist/ under the AGPL obliges the distributor to provide the Corresponding
     * Source - the form a person would actually modify, which is the
     * TypeScript. The `files` field shipped dist/src and not src until this
     * check was written.
     */
    const files = (JSON.parse(await readFile(path.resolve(HERE, "../../package.json"), 'utf8')) as {
      files?: string[];
    }).files ?? [];
    const missing = ['src', 'LICENSE'].filter((entry) => !files.includes(entry));
    if (missing.length === 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} the published package ships its own source and licence`,
      );
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} package.json "files" omits ${missing.join(' and ')} - ` +
          `a copyleft licence on a package that ships no source is not a licence anyone can obey`,
      );
    }
  }

  /* ------------------------------------------------------------------ *
   * TREE MEMORY - the redesign must not have moved an answer.
   *
   * Syntax trees are now freed during a scan and the file parsed again if
   * something needs it later (src/parse/tree-store.ts). That is the kind of
   * change that can be wrong in a way no accuracy figure notices: a node
   * located at the wrong offset in a re-parsed tree would produce a confident
   * proof through the wrong function, and precision and recall would barely
   * move.
   *
   * So the fixture tree is scanned twice - once with room for every tree, once
   * with a budget small enough that nearly every one is evicted - and the two
   * finding lists must be identical.
   *
   * The FIRST check is the one that makes the second mean anything. A budget
   * that never actually evicts would let the comparison pass while testing
   * nothing at all, which is exactly how a test ends up guarding an empty room.
   * ------------------------------------------------------------------ */
  console.log(`\n${color.bold('  Tree memory')}`);
  {
    const previousBudget = process.env['DEFUSE_TREE_BUDGET_MB'];
    process.env['DEFUSE_TREE_BUDGET_MB'] = '1';
    const squeezed = await scan(FIXTURES, {});
    if (previousBudget === undefined) delete process.env['DEFUSE_TREE_BUDGET_MB'];
    else process.env['DEFUSE_TREE_BUDGET_MB'] = previousBudget;

    const memory = squeezed.treeMemory;
    if (memory.evictions > 0 && memory.reparses > 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} a 1MB budget really does evict ` +
          `(${memory.evictions} evictions, ${memory.reparses} re-parses) - ` +
          `so the comparison below is a real test`,
      );
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} a 1MB budget evicted ${memory.evictions} trees and ` +
          `re-parsed ${memory.reparses} files - nothing was exercised, so the ` +
          `identity check below proves nothing`,
      );
    }

    // detectedAt is wall-clock and differs between any two scans.
    const comparable = (findings: readonly Finding[]) =>
      JSON.stringify(
        findings.map(({ detectedAt: _ignored, ...rest }) => rest),
      );
    if (comparable(result.findings) === comparable(squeezed.findings)) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} ${squeezed.findings.length} findings are identical ` +
          `whether trees are held or re-parsed`,
      );
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} findings differ between a held-tree scan ` +
          `(${result.findings.length}) and a re-parsed one (${squeezed.findings.length}) - ` +
          `a re-parsed tree is not being read the same way`,
      );
    }

    const relocationsFailed = squeezed.crossFile.enabled
      ? squeezed.crossFile.relocationsFailed
      : 0;
    if (relocationsFailed === 0) {
      passed++;
      console.log(
        `    ${color.green(g('tick'))} every indexed function was found again in its ` +
          `re-parsed tree`,
      );
    } else {
      failed++;
      console.log(
        `    ${color.red(g('cross'))} ${relocationsFailed} function(s) could not be located ` +
          `in a re-parsed tree - the resolution was declined, but a deterministic ` +
          `parse should never need that escape hatch`,
      );
    }
  }

  console.log(`\n${color.bold('  README self-consistency')}`);
  const readmeClaim = /`npm test`\s*[—-]\s*([\d,]+)\s*checks/.exec(await readFile(readmePath, 'utf8'));
  const totalWithThisCheck = passed + failed + 1;
  const claimedCount = readmeClaim?.[1] ? Number(readmeClaim[1].replace(/,/g, '')) : NaN;
  if (claimedCount === totalWithThisCheck) {
    passed++;
    console.log(
      `    ${color.green(g('tick'))} README says ${claimedCount} checks, and ${totalWithThisCheck} ran`,
    );
  } else {
    failed++;
    console.log(
      `    ${color.red(g('cross'))} README claims ${readmeClaim?.[1] ?? '(no number found)'} checks, ` +
        `but ${totalWithThisCheck} ran - update the "npm test" line in README.md`,
    );
  }

  /* ---- summary ---- */
  const total = passed + failed;
  console.log(
    `\n  ${failed === 0 ? color.green(color.bold(`ALL ${total} CHECKS PASSED`)) : color.red(color.bold(`${failed} of ${total} CHECKS FAILED`))}` +
      (skipped > 0 ? color.yellow(color.bold(`  ${skipped} SKIPPED`)) : '') +
      color.dim(`   (${result.stats.filesParsed} files, ${result.stats.durationMs}ms)\n`),
  );
  return failed === 0 ? 0 : 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    console.error(color.red(`test runner failed: ${(error as Error).message}`));
    console.error((error as Error).stack);
    process.exitCode = 2;
  });
