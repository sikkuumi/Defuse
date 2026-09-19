/**
 * THE README, DERIVED FROM THE REGISTRY.
 * =====================================
 *
 * WHY THIS FILE EXISTS.
 *
 * Pointing a fresh reader at this repository produced a list of things the
 * README asserts that the code contradicts:
 *
 *     README says   5 rules        registry ships   8
 *     README says   5 languages    languages.ts     6   (PHP absent entirely)
 *     README says   "Not SARIF"    src/report/sarif.ts is a SARIF 2.1.0 exporter
 *     README says   13.8% recall   the scorer measures 76.4%
 *
 * Every one of those was true when it was written. The project simply moved and
 * the prose did not, because the prose was a hand-maintained restatement of
 * facts the registry already knew.
 *
 * THIS IS THE FOURTH TIME THIS EXACT CLASS HAS BITTEN, and the previous three
 * are recorded elsewhere in this codebase: sources built from the frameworks we
 * had been shown (elasticsearch), escapers likewise (Jenkins), test-path
 * conventions likewise (cal.com). The pattern is always a list maintained by
 * hand that looks complete until reality moves.
 *
 * What makes this instance the sharpest is where the stale list was. There IS a
 * documentation-drift check in the suite, and it passed the whole time - because
 * it greps the README for exactly one regex, the `npm test - N checks` line.
 * A narrow instrument was trusted as a broad one. The checker itself was the
 * hand-maintained list.
 *
 * So: the counts and the matrix are now GENERATED from ALL_RULES and LANGUAGES,
 * the benchmark table is generated from the scorer's own output file, and
 * `npm test` fails when the README disagrees with either. Prose that restates a
 * fact the program knows is a bug waiting for a quiet afternoon.
 */
import { ALL_RULES } from '../rules/registry.js';
import { LANGUAGES, type LanguageId } from '../parse/languages.js';
import type { SupportStatus } from '../rules/contract.js';

/** Opening and closing markers for a generated block in a markdown file. */
export const BLOCK_START = (name: string): string => `<!-- derived:${name} -->`;
export const BLOCK_END = '<!-- /derived -->';

const MARK: Record<SupportStatus, string> = {
  implemented: '●',
  partial: '◐',
  'not-implemented': '○',
};

const SHORT: Partial<Record<LanguageId, string>> = {
  javascript: 'JS',
  typescript: 'TS',
  python: 'PY',
  java: 'JAVA',
  php: 'PHP',
  go: 'GO',
};

const columnLabel = (id: LanguageId): string => SHORT[id] ?? id.toUpperCase();

/**
 * The rule × language coverage matrix.
 *
 * `Rule.support` is already a per-language honesty declaration with a REQUIRED
 * note on every entry, printed at the end of every scan. The README's table was
 * a second copy of it, kept by hand, and it is the copy that went stale.
 */
export function renderRuleMatrix(): string {
  const languages = LANGUAGES.map((l) => l.id);
  const header = `| Rule | CWE | OWASP | ${languages.map(columnLabel).join(' | ')} |`;
  const divider = `|---|---|---|${languages.map(() => ':--:').join('|')}|`;
  const rows = ALL_RULES.map((rule) => {
    const cells = languages.map((id) => MARK[rule.support[id]?.status ?? 'not-implemented']);
    return `| \`${rule.id}\` | ${rule.cwe} | ${rule.owasp} | ${cells.join(' | ')} |`;
  });
  return [
    header,
    divider,
    ...rows,
    '',
    '● implemented  ◐ partial  ○ not implemented',
    '',
    `${ALL_RULES.length} rules across ${languages.length} languages. This table is generated from`,
    '`ALL_RULES` and `LANGUAGES` by `npm run sync:readme`, and `npm test` fails if it',
    'drifts - the counts in it are not maintained by hand.',
  ].join('\n');
}

/** One sentence naming the current totals, for use in running prose. */
export function renderCounts(): string {
  const names = LANGUAGES.map((l) => l.displayName);
  return (
    `**${ALL_RULES.length} rules** across **${names.length} languages** ` +
    `(${names.join(', ')}).`
  );
}

export interface BenchmarkResult {
  readonly scored: number;
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly tn: number;
  readonly precision: string;
  readonly recall: string;
  readonly missedByCategory: Record<string, number>;
  readonly filesParsed: number;
  readonly parseErrors: number;
  readonly durationMs: number;
  /** False positives carrying BenchmarkJava's constant-branch decoy. */
  readonly decoyFalsePositives: number;
  readonly decoyShare: string;
  readonly engineVersion: string;
  readonly measuredAt: string;
}

/**
 * The OWASP BenchmarkJava table.
 *
 * This one cannot be derived from the registry, because it is a MEASUREMENT
 * rather than a declaration - so it is derived from the measurement instead.
 * `npm run benchmark` writes docs/benchmark-result.json, this renders it, and
 * the test compares the README against it. The loop closes: you cannot change
 * the engine's score without the README either following or failing the build.
 *
 * The stale figures this replaced were 64.5% precision / 13.8% recall. They
 * were honestly measured and then left behind by the Spring and JAX-RS source
 * bindings and by declaredTypes(), which took recall to 76.4% and cost
 * precision on the way - a real trade the old table could not show.
 */
export function renderBenchmark(result: BenchmarkResult): string {
  /*
   * THE HEADLINE IS DERIVED TOO, and that is the point of this function.
   *
   * The first version of this block generated the TABLE and left the sentence
   * underneath it hand-written. That sentence read "Recall is low and that is
   * the honest headline" - an interpretation of the OLD numbers, which went
   * stale in the very commit that fixed the table it sat beneath. Deriving the
   * facts and hand-keeping their meaning just moves the drift one line down.
   *
   * So the weak side is computed. More false positives than false negatives
   * means precision is where the tool is worst; the reverse means recall is.
   * Whichever it is, the README says it because the arithmetic said it.
   */
  const precisionIsWeaker = result.fp > result.fn;
  const ratio = (Math.max(result.fp, result.fn) / Math.max(1, Math.min(result.fp, result.fn)))
    .toFixed(1);
  const headline = precisionIsWeaker
    ? `**Precision is the weaker side.** ${result.fp} false positives against ` +
      `${result.fn} false negatives - ${ratio}x as many - so the cost of this engine ` +
      `is triage time, not missed bugs.`
    : `**Recall is the weaker side.** ${result.fn} false negatives against ` +
      `${result.fp} false positives - ${ratio}x as many - so the cost of this engine ` +
      `is missed bugs, not triage time.`;

  return [
    '| | cases | TP | FP | FN | TN | precision | recall |',
    '|---|--:|--:|--:|--:|--:|--:|--:|',
    `| **overall** | **${result.scored}** | **${result.tp}** | **${result.fp}** | ` +
      `**${result.fn}** | **${result.tn}** | **${result.precision}** | **${result.recall}** |`,
    '',
    `${result.filesParsed} files, ${result.parseErrors} parse errors, ` +
      `${(result.durationMs / 1000).toFixed(1)} seconds, on engine ${result.engineVersion} ` +
      `(${result.measuredAt}).`,
    '',
    headline,
    '',
    `Missed by category: ` +
      Object.entries(result.missedByCategory)
        .map(([k, v]) => `${k} ${v}`)
        .join(', ') +
      `. Of the ${result.fp} false positives, **${result.decoyFalsePositives} ` +
      `(${result.decoyShare})** carry BenchmarkJava's constant-branch decoy - the ` +
      `\`if ((7 * 42) - num > 200)\` shape that needs constant folding plus branch ` +
      `feasibility to see through, which the limitations list says this engine does ` +
      `not do. The remainder are ours.`,
    '',
    'Every number above is generated by `npm run benchmark` into',
    '`docs/benchmark-result.json` - including the sentence naming the weaker side,',
    'because an interpretation kept by hand goes stale exactly like a figure does.',
  ].join('\n');
}

/** Replace the contents of one `<!-- derived:name -->` block. */
export interface LabelSplitTier {
  readonly label: string;
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly precision: string;
  readonly recall: string;
  readonly decoyFalsePositives: number;
  readonly decoyShare: string;
  readonly nonDecoyFalsePositives: number;
}

export interface LabelSplitResult {
  readonly scored: number;
  readonly findingsByConfidence: Record<string, number>;
  readonly tiers: readonly LabelSplitTier[];
  readonly engineVersion: string;
  readonly measuredAt: string;
}

/**
 * THE BLOCK THAT SCORES THE LABELS SEPARATELY.
 *
 * `renderBenchmark` reports one precision figure covering both labels mixed
 * together. That figure is an average across two populations this whole tool
 * exists to keep apart - the same blending it refuses to do inside a single
 * finding, done one level up in the report about itself.
 *
 * So this renders the split, and like the benchmark block it derives its own
 * interpretation rather than leaving a hand-written sentence to go stale
 * underneath it. Two sentences are computed:
 *
 *   - whether the green label is actually worth more than the amber one, and
 *     by how much. If a change ever made them equal, this block would say so
 *     in the README rather than waiting for someone to notice.
 *
 *   - how much of the green tier's error is BenchmarkJava's synthetic decoy
 *     rather than a real mistake. Quoting the decoy-excluded figure alone
 *     would be picking the flattering number; quoting only the blended one
 *     hides that the benchmark's traps dominate what is left.
 */
export function renderLabelSplit(result: LabelSplitResult): string {
  const pct = (s: string): number => Number.parseFloat(s);
  const verified = result.tiers.find((t) => t.label.startsWith('flow-verified'));
  const signature = result.tiers.find((t) => t.label.startsWith('signature-only'));

  const rows = result.tiers.map(
    (t) =>
      `| \`${t.label}\` | ${t.tp} | ${t.fp} | ${t.fn} | **${t.precision}** | ${t.recall} | ` +
      `${t.decoyFalsePositives} (${t.decoyShare}) |`,
  );

  const lines: string[] = [
    '| tier | TP | FP | FN | precision | recall | FPs that are decoys |',
    '|---|--:|--:|--:|--:|--:|--:|',
    ...rows,
    '',
    `${Object.entries(result.findingsByConfidence)
      .map(([k, v]) => `${v} \`${k}\``)
      .join(', ')} findings, on engine ${result.engineVersion} (${result.measuredAt}).`,
    '',
  ];

  if (verified && signature) {
    const gap = pct(verified.precision) - pct(signature.precision);
    lines.push(
      gap > 0
        ? `**The green label is worth ${gap.toFixed(1)} points.** \`flow-verified\` runs ` +
          `${verified.precision} against \`signature-based\` at ${signature.precision}. The ` +
          `gap is the whole claim this tool makes; it is measured here rather than asserted.`
        : `**The labels are not separating.** \`flow-verified\` runs ${verified.precision} ` +
          `against \`signature-based\` at ${signature.precision}, so the green label is ` +
          `currently buying nothing. That is a defect, not a footnote.`,
    );
    lines.push('');

    const real = verified.tp + verified.nonDecoyFalsePositives;
    const excl = real === 0 ? 0 : (verified.tp / real) * 100;
    lines.push(
      `Of the ${verified.fp} false positives still carrying the green label, ` +
        `**${verified.decoyFalsePositives} (${verified.decoyShare})** are BenchmarkJava's ` +
        `constant-branch decoy - a path that genuinely exists inside a branch that cannot ` +
        `run - leaving **${verified.nonDecoyFalsePositives}** that are ordinary mistakes. ` +
        `Set the decoys aside and \`flow-verified\` precision is **${excl.toFixed(1)}%**. ` +
        `Both figures are printed because neither alone is the truth: the first is ` +
        `contaminated by synthetic traps, the second requires excluding cases, and a ` +
        `reader deserves to see the size of that choice rather than inherit it.`,
    );
  }

  return lines.join('\n');
}

export function replaceBlock(markdown: string, name: string, body: string): string {
  const start = BLOCK_START(name);
  const from = markdown.indexOf(start);
  if (from === -1) throw new Error(`README has no block named "${name}"`);
  const to = markdown.indexOf(BLOCK_END, from);
  if (to === -1) throw new Error(`block "${name}" is not closed with ${BLOCK_END}`);
  return (
    markdown.slice(0, from + start.length) + '\n' + body + '\n' + markdown.slice(to)
  );
}

/** Read the current contents of one block, for comparison. */
export function readBlock(markdown: string, name: string): string | null {
  const start = BLOCK_START(name);
  const from = markdown.indexOf(start);
  if (from === -1) return null;
  const to = markdown.indexOf(BLOCK_END, from);
  if (to === -1) return null;
  return markdown.slice(from + start.length, to).trim();
}
