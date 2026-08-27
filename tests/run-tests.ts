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

import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/engine/scan.js';
import { color, g } from '../src/report/colors.js';
import { ALL_RULES } from '../src/rules/registry.js';
import { LANGUAGES } from '../src/parse/languages.js';
import { TAINT_COVERAGE_NOTES } from '../src/taint/dictionaries.js';
import { ENGINE_CAPABILITIES, type Finding } from '../src/core/finding.js';
import { scoreAnalysis, SEVERITY_WEIGHT } from '../src/core/score.js';
import { analyze } from '../src/core/analyze.js';
import { looksLikeSql, matchKnownSecret } from '../src/rules/lib/strings.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// dist/tests -> project root -> tests/fixtures (fixtures are never compiled)
const FIXTURES = path.resolve(HERE, '../../tests/fixtures');

/**
 * `// EXPECT rule-id`       a finding must appear (either confidence)
 * `// EXPECT-FLOW rule-id`  a finding must appear AND be flow-verified
 * `// EXPECT-NONE`          this whole file must produce nothing
 */
const EXPECT = /(?:\/\/|#|\/\*|\*)\s*EXPECT(-NONE|-FLOW)?\s*:?\s*([a-z0-9-]*)/i;

interface Expectation {
  readonly file: string;
  readonly line: number; // line the annotation sits on
  readonly ruleId: string;
  /** EXPECT-FLOW: the finding must carry a verified source-to-sink path. */
  readonly requireFlow: boolean;
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
): Finding[] {
  return findings.filter(
    (f) =>
      f.ruleId === ruleId &&
      f.location.file.endsWith(relativeFile) &&
      f.location.startLine > line &&
      f.location.startLine <= line + WINDOW &&
      (!requireFlow || f.confidence === 'flow-verified'),
  );
}

async function main(): Promise<number> {
  console.log(`\n${color.bold('NS-1 SecureScan — rule verification')}`);
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
      const hits = findingsNear(
        findings,
        short,
        expectation.line,
        expectation.ruleId,
        expectation.requireFlow,
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
            (expectation.requireFlow ? 'was not FLOW-VERIFIED here' : 'did not fire'),
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
        .map((step) => /passed through `([^`]+)\(\)`, which is NOT in our dictionary/.exec(step.description)?.[1])
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
  const sourceDirs = ['rules', 'report', 'core', 'taint', 'parse'];
  const literal = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
  const inSource: string[] = [];
  for (const dir of sourceDirs) {
    const base = path.resolve(HERE, '../../src', dir);
    const walkDir = async (at: string): Promise<void> => {
      for (const entry of await readdir(at, { withFileTypes: true })) {
        const full = path.join(at, entry.name);
        if (entry.isDirectory()) await walkDir(full);
        else if (entry.name.endsWith('.ts')) {
          const text = await readFile(full, 'utf8');
          // Strip comments first so build-history notes are not flagged.
          const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
          for (const match of code.matchAll(literal)) {
            if (phaseMention.test(match[2] ?? '')) {
              inSource.push(`${dir}/${entry.name}: ${(match[2] ?? '').slice(0, 60)}`);
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
      `    ${color.green(g('tick'))} no string literal in src/{${sourceDirs.join(',')}} names a phase number`,
    );
  } else {
    failed++;
    for (const hit of inSource.slice(0, 6)) console.log(`    ${color.red(g('cross'))} ${hit}`);
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

  /* ---- parsing health across all five languages ---- */
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
    console.log(`    ${color.green(g('tick'))} all five languages exercised: ${languagesSeen.join(', ')}`);
  } else {
    failed++;
    console.log(`    ${color.red(g('cross'))} no fixture exercised: ${missing.join(', ')}`);
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
