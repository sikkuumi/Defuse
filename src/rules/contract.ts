/**
 * THE RULE CONTRACT
 * =================
 *
 * A "rule" is one thing Defuse knows how to look for. This file defines the shape
 * every rule must have. Nothing else in the codebase knows what SQL injection
 * is - the engine just runs whatever satisfies this interface.
 *
 * ARCHITECTURAL DECISION (this is the big one - it shapes Phases 3 and 5):
 *
 * Rules do NOT write tree-sitter queries and rules do NOT walk the AST.
 * Instead, the engine lowers every language's syntax tree into a handful of
 * language-neutral SHAPES - right now `CallSite` and `Assignment` - and a rule
 * is a plain function that inspects a shape and says yes or no.
 *
 * Why:
 *   - A rule written once works for all five languages. `db.query(...)` in JS,
 *     `cursor.execute(...)` in Python and `stmt.executeQuery(...)` in Java all
 *     arrive at the rule as the same CallSite object with a different
 *     `calleeName`. The rule needs a name list per language, not a rewrite.
 *   - Adding language number six means teaching the SHAPE LAYER one new query.
 *     Every existing rule gains that language for free.
 *   - Phase 3's taint engine needs exactly these shapes anyway (a "source" is a
 *     CallSite, a "sink" is a CallSite, propagation happens through
 *     Assignments). Building them now means Phase 3 is an addition, not a
 *     rewrite.
 *
 * The escape hatch: a rule may declare `status: 'partial'` or
 * `'not-implemented'` for a language the shape layer cannot express. That is a
 * documented gap, printed in every report. It is never silence.
 */

import type { Node } from 'web-tree-sitter';
import type { Severity } from '../core/finding.js';
import type { LanguageId } from '../parse/languages.js';
import type { ParsedFile } from '../parse/parser.js';

/**
 * A function/method call, normalised across languages.
 *
 *   JS      db.query(sql)           receiverText "db"      calleeName "query"
 *   Python  cursor.execute(sql)     receiverText "cursor"  calleeName "execute"
 *   Java    stmt.executeQuery(sql)  receiverText "stmt"    calleeName "executeQuery"
 *   Go      db.Query(sql)           receiverText "db"      calleeName "Query"
 */
export interface CallSite {
  readonly kind: 'call';
  /** The whole call expression - what a finding points at. */
  readonly node: Node;
  /** The method or function name only, no dots. */
  readonly calleeName: string;
  /** Text before the dot, e.g. "db", "child_process", "Runtime.getRuntime()". */
  readonly receiverText: string;
  /** Full callee text, e.g. "crypto.createHash". */
  readonly calleeText: string;
  /** Argument expressions, already stripped of commas and parentheses. */
  readonly args: readonly Node[];
}

/**
 * A value being stored somewhere, normalised across languages. Covers
 * variable declarations, plain assignments, object/dict literal entries and
 * keyword arguments - anywhere a name gets bound to a value.
 */
export interface Assignment {
  readonly kind: 'assignment';
  readonly node: Node;
  /** Full left-hand side text, e.g. "el.innerHTML", "config.apiKey". */
  readonly targetText: string;
  /** Last segment of the target, e.g. "innerHTML", "apiKey". */
  readonly targetName: string;
  /** The value expression. */
  readonly value: Node;
}

export type Shape = CallSite | Assignment;

/** Everything a rule is allowed to know while deciding. */
export interface RuleContext {
  readonly file: ParsedFile;
  readonly language: LanguageId;
  /** Convenience: source text of a node, whitespace-collapsed. */
  readonly text: (node: Node) => string;
  /**
   * Record that this rule examined a line and can PROVE it is not the bug the
   * shape suggests - so the guess it would have made is withdrawn, not dropped.
   *
   * A rule that declines to report leaves no trace, and that was fine while
   * declining meant "these are plain literals". Once a rule can decline because
   * of REASONING - a branch that cannot run, a condition fixed at compile time -
   * the reasoning has to be visible, because reasoning can be wrong. Receipts
   * appear in --json as verifiedClean entries with the reason attached, are
   * counted in the terminal summary, and show as "proved clean" in the UI.
   *
   * Optional so a caller that builds its own context is not broken by it.
   */
  readonly noteClean?: (ruleId: string, node: Node, reason: string) => void;
}

/**
 * What a rule returns when it decides something is worth reporting.
 * Note there is NO confidence field: a rule cannot set its own confidence.
 * The engine stamps a rule's result as signature-based; only the taint engine,
 * which can produce a source-to-sink path, may emit flow-verified. A rule that wanted
 * to claim more would have to change the engine, in a commit, in review.
 */
export interface RuleHit {
  /** Node to point the finding at. Usually the shape's node or a sub-node. */
  readonly node: Node;
  /** One line for the terminal. */
  readonly message: string;
  /** Why this matched, in plain language. Shown to the user. Required. */
  readonly reasoning: string;
  /** Optional per-hit override of the rule's general limitations text. */
  readonly limitations?: string;
  /** Optional severity override (e.g. a confirmed AWS key beats a generic one). */
  readonly severity?: Severity;
}

export type SupportStatus = 'implemented' | 'partial' | 'not-implemented';

export interface LanguageSupport {
  readonly status: SupportStatus;
  /**
   * REQUIRED for every language, including implemented ones. For 'partial' and
   * 'not-implemented' this must say exactly what is missing. This text is
   * printed in the coverage section of every scan, so a gap can never be silent.
   */
  readonly note: string;
}

export interface Rule {
  /** Stable machine id, kebab-case. Used in --json, tests and suppressions. */
  readonly id: string;
  readonly name: string;
  /** CWE identifier - the industry's shared catalogue of weakness types. */
  readonly cwe: string;
  /** OWASP Top 10 (2025) category. */
  readonly owasp: string;
  readonly severity: Severity;
  /**
   * 2-4 sentences explaining the VULNERABILITY (not the detection code) to
   * someone who has never heard of it. Printed by `defuse rules --explain`.
   */
  readonly explanation: string;
  /**
   * What this rule structurally cannot determine. Copied onto every finding it
   * produces unless the hit overrides it. Required - a rule with no stated
   * limitations is a rule pretending to be certain.
   */
  readonly limitations: string;
  /**
   * Per-language honesty declaration. REQUIRED FOR EVERY LANGUAGE.
   *
   * This was `Partial<Record<...>>` with "missing language = not-implemented"
   * as the default, and that default caused the worst kind of bug this project
   * can have: the tool contradicting itself about its own coverage.
   *
   * Adding C and C++ silently marked all eight existing rules not-implemented
   * for them. rulesForLanguage() then filtered those rules out, so their
   * SIGNATURE matchers never ran on a C file at all - while the taint engine,
   * which reaches rules by id and never consults this table, went on producing
   * flow-verified `command-injection` findings in C. The report printed six of
   * them directly underneath a line saying command-injection/c was NOT
   * IMPLEMENTED.
   *
   * A silent default is what made that possible. Requiring every language
   * turns the next language addition into a compile error per rule, which is
   * exactly what the taint dictionaries already do - nineteen of them, each a
   * real decision someone had to make on purpose.
   */
  readonly support: Record<LanguageId, LanguageSupport>;
  /** Which shapes this rule wants to see. Engine only calls matching ones. */
  readonly shapes: readonly Shape['kind'][];
  /** The decision. Return null for "not interesting". */
  readonly check: (shape: Shape, ctx: RuleContext) => RuleHit | null;
}

/** Helper so a rule can narrow a Shape without repeating the same three lines. */
export function asCall(shape: Shape): CallSite | null {
  return shape.kind === 'call' ? shape : null;
}

export function asAssignment(shape: Shape): Assignment | null {
  return shape.kind === 'assignment' ? shape : null;
}
