/**
 * THE GAUGES
 * ==========
 *
 * Three needles. They are never added together, and this file will not let
 * them be - there is no `overallScore` export, and there never should be.
 *
 * WHY THAT MATTERS. The comment at the top of finding.ts says it best:
 *
 *   "Severity = how bad is this if it turns out to be real? Deliberately
 *    separate from confidence, which is how sure are we it's real?
 *    Conflating those two numbers is the single most common lie in SAST
 *    tooling: a tool shows one 'risk' bar and you cannot tell whether it
 *    means 'probably harmless but catastrophic if not' or 'definitely real
 *    but minor'."
 *
 * A single 0-500 risk dial IS that bar. So the dial got split along the exact
 * line the project already draws:
 *
 *   VERIFIED EXPOSURE    severity, over findings we PROVED reach a sink
 *   UNVERIFIED SURFACE   severity, over findings we only pattern-matched
 *   ANALYSIS COVERAGE    how much of the code we could actually reason about
 *
 * Two of those are the same weights over two different confidence levels, kept
 * side by side so you can see the shape of what is proven against the shape of
 * what is merely suspected. Reading them together is the point; averaging them
 * would destroy it.
 *
 * Every reading carries its own arithmetic in `working`, so the number can be
 * CHECKED rather than believed. That is the whole standard here: a score you
 * cannot recompute by hand is a vibe with a decimal point on it.
 */

import type { Finding, Severity } from './finding.js';
import type { AnalysisResult } from './analyze.js';

/**
 * How much one finding contributes, by severity.
 *
 * These are a judgement, not a measurement, and calling them anything else
 * would be the first lie. What makes them defensible is that they are FIXED,
 * PUBLISHED and applied identically to both severity gauges - so while the
 * absolute number is arbitrary, every comparison made with it is real: two
 * criticals always outweigh three mediums, in both directions, in both shells.
 */
export const SEVERITY_WEIGHT: Readonly<Record<Severity, number>> = {
  critical: 25,
  high: 15,
  medium: 7,
  low: 3,
  info: 1,
};

/** The top of the severity dials. A sum past this is reported, not hidden. */
export const GAUGE_MAX = 500;

export interface GaugeReading {
  readonly id: 'verified-exposure' | 'unverified-surface' | 'analysis-coverage';
  readonly label: string;
  /** Where the needle sits. Already clamped to [0, max]. */
  readonly value: number;
  readonly max: number;
  readonly unit: '' | '%';
  /** One line under the needle: what it means, and what it does NOT mean. */
  readonly meaning: string;
  /** The arithmetic. Anyone can recompute the value from these lines. */
  readonly working: readonly string[];
  /**
   * The raw total before clamping. Equal to `value` unless the scan blew past
   * the top of the dial, in which case the dial is pinned and this is the
   * truth. A pinned needle that quietly stops counting is a lie by omission.
   */
  readonly rawTotal: number;
  readonly capped: boolean;
  /**
   * True when there was nothing to measure, as distinct from measuring zero.
   *
   * These are not the same fact and must never be drawn the same way. A scan of
   * an empty file and a scan of ten lines of careful, correctly parameterised
   * code both produced "0 findings, 94% coverage, no blind spots" - identical
   * dashboards for "we checked and found nothing" and "there was nothing to
   * check". The second is a result; the first is the absence of one.
   */
  readonly noReading: boolean;
  /**
   * What the total is MADE OF, largest severity first.
   *
   * A single needle throws this away, and on real code it throws away almost
   * everything: across the corpus the severity dials sit between 0% and 24% of
   * their scale, so the arc is a stub and the stub is all you get. "75" cannot
   * tell you whether that is three criticals or twenty-five lows, and those are
   * different afternoons.
   *
   * Empty for the coverage gauge, which is a ratio and has no composition.
   */
  readonly segments: readonly {
    readonly severity: Severity;
    readonly count: number;
    readonly weight: number;
    /** Share of this gauge's own total, 0-1. Zero when the total is zero. */
    readonly share: number;
  }[];
}

export interface ScoreReport {
  readonly gauges: readonly GaugeReading[];
  /**
   * Nothing in this scan could be analysed - no statement, call or assignment
   * ever reached a rule. Every reading below is vacuous when this is true, and
   * any surface showing them has to say so rather than printing zeroes.
   */
  readonly examinedNothing: boolean;
  /** Code constructs the rules actually looked at. The denominator of trust. */
  readonly shapesExamined: number;
  /**
   * Places this scan is known to have stopped early. Not a gauge, because a
   * count of blind spots is not a measurement of risk - but printed beside the
   * gauges, because it is what tells you how much of the dial to trust.
   */
  readonly blindSpots: readonly { readonly label: string; readonly count: number }[];
  /**
   * How many attacker-controlled SOURCES the tracer recognised in this scan.
   *
   * Reported ALWAYS, including - especially - when it is zero, which is why it
   * cannot live in blindSpots above: that list drops anything with a count of
   * zero, and zero is the interesting reading here.
   *
   * Elasticsearch is why. 3,999 Java files, a REST API over the network, and
   * zero flow-verified findings. It contains 0 `@RequestParam` and 0
   * `getParameter()` - it has its own REST layer, which the dictionaries do not
   * model, so there was never a source to start a trace from. "0 flows proven"
   * read like good news and was actually "we could not begin".
   *
   * Every flow number in a report is downstream of this one.
   */
  readonly sourcesFound: number;
}

function weigh(findings: readonly Finding[]): { total: number; bySeverity: Map<Severity, number> } {
  const bySeverity = new Map<Severity, number>();
  let total = 0;
  for (const finding of findings) {
    bySeverity.set(finding.severity, (bySeverity.get(finding.severity) ?? 0) + 1);
    total += SEVERITY_WEIGHT[finding.severity];
  }
  return { total, bySeverity };
}

const ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function showWorking(bySeverity: Map<Severity, number>, total: number): string[] {
  const lines = ORDER.filter((s) => bySeverity.get(s)).map((s) => {
    const n = bySeverity.get(s) ?? 0;
    return `${n} ${s} x ${SEVERITY_WEIGHT[s]} = ${n * SEVERITY_WEIGHT[s]}`;
  });
  if (lines.length === 0) return ['nothing in this category'];
  if (lines.length > 1) lines.push(`total = ${total}`);
  return lines;
}

function severityGauge(
  id: 'verified-exposure' | 'unverified-surface',
  label: string,
  meaning: string,
  findings: readonly Finding[],
  examinedNothing: boolean,
): GaugeReading {
  const { total, bySeverity } = weigh(findings);
  const working = showWorking(bySeverity, total);
  if (total > GAUGE_MAX) {
    working.push(`past the top of the dial by ${total - GAUGE_MAX} - needle pinned at ${GAUGE_MAX}`);
  }
  const segments = ORDER.filter((s) => bySeverity.get(s)).map((severity) => {
    const count = bySeverity.get(severity) ?? 0;
    const weight = count * SEVERITY_WEIGHT[severity];
    return { severity, count, weight, share: total > 0 ? weight / total : 0 };
  });

  return {
    id,
    label,
    value: Math.min(total, GAUGE_MAX),
    max: GAUGE_MAX,
    unit: '',
    meaning,
    working,
    rawTotal: total,
    capped: total > GAUGE_MAX,
    noReading: examinedNothing,
    segments,
  };
}

/**
 * How much of the analysis actually completed.
 *
 * This is the gauge no other scanner shows, and it is the one that tells you
 * how to read the other two. A verified-exposure of 0 means something very
 * different at 95% coverage than at 30%: the first is reassuring, the second
 * means we barely looked.
 *
 * It is an average of the ratios we can genuinely compute, and each one is
 * listed in `working` so an average that hides a bad component cannot pass
 * unnoticed. Ratios we cannot compute are OMITTED rather than assumed to be
 * 100% - an unmeasured thing is not a passing thing.
 */
function coverageGauge(result: AnalysisResult, filesFound: number, examinedNothing: boolean): GaugeReading {
  const working: string[] = [];
  const parts: number[] = [];

  const found = filesFound || result.stats.filesParsed;
  if (found > 0) {
    const rate = result.stats.filesParsed / found;
    parts.push(rate);
    working.push(`files read: ${result.stats.filesParsed}/${found} = ${Math.round(rate * 100)}%`);
  }

  const { rules, languages, implemented, partial } = result.coverage.counts;
  const cells = rules * languages;
  if (cells > 0) {
    // A partial rule counts as half. It does something; it does not do the job.
    const rate = (implemented + partial * 0.5) / cells;
    parts.push(rate);
    working.push(
      `rules available: ${implemented} full + ${partial} partial of ${cells} = ${Math.round(rate * 100)}%`,
    );
  }

  if (result.crossFile.enabled) {
    const attempts = result.crossFile.resolved + result.crossFile.ambiguous;
    if (attempts > 0) {
      const rate = result.crossFile.resolved / attempts;
      parts.push(rate);
      working.push(
        `cross-file calls followed: ${result.crossFile.resolved}/${attempts} = ${Math.round(rate * 100)}%`,
      );
    } else {
      working.push('cross-file calls followed: none attempted, so not counted');
    }
  } else {
    working.push('cross-file resolution was OFF, so it is not counted here');
  }

  // Stated first, because it is the denominator everything else divides into.
  // "94% of the analysis completed" is not a useful sentence when the analysis
  // had nothing to run on.
  working.unshift(`code constructs examined: ${result.stats.shapesExamined}`);

  const value = parts.length > 0 ? Math.round((parts.reduce((a, b) => a + b, 0) / parts.length) * 100) : 0;
  if (parts.length > 1) working.push(`mean of ${parts.length} measured ratios = ${value}%`);

  return {
    id: 'analysis-coverage',
    label: 'Analysis coverage',
    value,
    max: 100,
    unit: '%',
    meaning: examinedNothing
      ? 'Nothing in this scan could be analysed - not one statement, call or ' +
        'assignment reached a rule. There is no coverage figure to give, because ' +
        'there was nothing to cover. This is not a clean result; it is no result.'
      : 'How much of the analysis actually completed. This is not a security score - ' +
        'it is how much weight the other two dials can carry. Low coverage with no ' +
        'findings means we barely looked, not that the code is fine.',
    working,
    rawTotal: value,
    capped: false,
    noReading: examinedNothing,
    // A ratio has no composition to show. Empty rather than faked.
    segments: [],
  };
}

/**
 * Build all three readings.
 *
 * `filesFound` comes from the walker (Node) or the drop handler (browser), so
 * it is passed in rather than read off the result - the analyzer only ever
 * sees the files that made it that far.
 */
export function scoreAnalysis(result: AnalysisResult, filesFound = 0): ScoreReport {
  const verified = result.findings.filter((f) => f.confidence === 'flow-verified');
  const signature = result.findings.filter((f) => f.confidence === 'signature-based');
  // Not one statement, call or assignment reached a rule. Parsing a file is not
  // the same as analysing it: a file of whitespace parses perfectly.
  const examinedNothing = result.stats.shapesExamined === 0;

  const gauges: GaugeReading[] = [
    severityGauge(
      'verified-exposure',
      'Verified exposure',
      'Severity weight of findings where attacker data was TRACED into the sink. ' +
        'Every point here is backed by a printed path. Zero means no flow was proven - ' +
        'it does not mean none exists.',
      verified,
      examinedNothing,
    ),
    severityGauge(
      'unverified-surface',
      'Unverified surface',
      'The same weights over findings we only pattern-matched. Deliberately a ' +
        'separate needle: these may be real or may be false positives, and averaging ' +
        'them into the proven ones would hide which is which.',
      signature,
      examinedNothing,
    ),
    coverageGauge(result, filesFound, examinedNothing),
  ];

  // These are SCAN-WIDE counts, not a tally of what appears in the findings
  // above. A trace can pass through an unmodelled function and then never reach
  // a sink, so this number is legitimately larger than the unmodelled hops you
  // can see in the printed paths. Saying "3" while the paths show 2 looks like
  // an error until the label admits which population it is counting.
  const blindSpots = [
    {
      label: 'expressions too deeply nested to walk (generated or minified code)',
      count: result.traceLimits.astTruncations,
    },
    { label: 'call chains cut at the depth limit', count: result.traceLimits.depthTruncations },
    { label: 'recursive calls not re-entered', count: result.traceLimits.recursionStops },
    {
      label: 'unmodelled functions stepped through (scan-wide, not only on reported paths)',
      count: result.traceLimits.unmodelledHops,
    },
    {
      label: 'cross-file calls declined as ambiguous',
      count: result.crossFile.enabled ? result.crossFile.ambiguous : 0,
    },
    { label: 'files that did not fully parse', count: result.parseProblems.length },
  ].filter((spot) => spot.count > 0);

  return {
    gauges,
    examinedNothing,
    shapesExamined: result.stats.shapesExamined,
    blindSpots,
    sourcesFound: result.traceLimits.sourcesFound,
  };
}
