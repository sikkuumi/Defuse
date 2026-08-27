/**
 * THE COVERAGE LEDGER - "no silent gaps"
 * ======================================
 *
 * Most scanners tell you what they FOUND. Almost none tell you what they did
 * not LOOK for. That asymmetry is how a clean report comes to mean "we are
 * secure" when it actually means "we ran five checks on two of your six
 * languages".
 *
 * This module turns the per-rule, per-language declarations in the rule files
 * into a ledger that is printed at the end of EVERY scan - clean or not. If a
 * rule is partial, the report says which part. If a language went unscanned,
 * the report says so and says why.
 *
 * A gap you can read is a decision. A gap you cannot read is a lie by omission.
 */

import { ALL_RULES } from '../rules/registry.js';
import type { SupportStatus } from '../rules/contract.js';
import { LANGUAGES, type LanguageId } from '../parse/languages.js';
import { TAINT_COVERAGE_NOTES, TAINT_DICTIONARIES } from '../taint/dictionaries.js';
import { ENGINE_CAPABILITIES } from './finding.js';

export interface CoverageCell {
  readonly ruleId: string;
  readonly ruleName: string;
  readonly language: LanguageId;
  readonly status: SupportStatus;
  readonly note: string;
}

/** Which languages the data-flow engine can actually verify flows in. */
export interface TaintCoverageCell {
  readonly language: LanguageId;
  readonly implemented: boolean;
  readonly note: string;
}

export interface CoverageReport {
  readonly engine: typeof ENGINE_CAPABILITIES;
  /**
   * Data-flow coverage is reported SEPARATELY from rule coverage, because a
   * language can have every rule implemented and still get no flow
   * verification at all - which is exactly the situation Java and Go are in.
   * Folding the two together would let "5/5 rules implemented" imply a depth
   * of analysis that does not exist there.
   */
  readonly taint: readonly TaintCoverageCell[];
  /** Every rule x language combination, including the ones we do not do. */
  readonly matrix: readonly CoverageCell[];
  /** Only the cells a reader must act on: partial and not-implemented. */
  readonly gaps: readonly CoverageCell[];
  readonly counts: {
    readonly rules: number;
    readonly languages: number;
    readonly implemented: number;
    readonly partial: number;
    readonly notImplemented: number;
  };
  /** Languages present in the scanned tree that we have no support for at all. */
  readonly unscannedExtensions: readonly string[];
  /**
   * OWASP categories this engine has NO rule for. Not a gap within a rule -
   * the absence of the rule entirely.
   *
   * The report already listed limits inside the checks it runs, and partial
   * language coverage per rule. It never said which whole classes of bug it
   * does not look for. So a Java scan that stays silent on XXE and insecure
   * deserialization reads exactly like a Java scan where those things are fine,
   * and there was nothing anywhere in the output to tell the two apart.
   *
   * That is the same failure as a green tick on an unread file, one level up.
   */
  readonly owaspCoverage: readonly CategoryCoverage[];
}

export interface CategoryCoverage {
  readonly id: string;
  readonly title: string;
  /**
   * Never 'full'. No category in this list is comprehensively checked, and a
   * state the data can never reach should not exist in the type.
   */
  readonly state: 'none' | 'partial';
  /** Rule ids that land in this category. Empty when state is 'none'. */
  readonly rules: readonly string[];
  /** What we DO check here. Only set when state is 'partial'. */
  readonly weCheck?: string;
  /** What a reader would plausibly expect here - covered or not. */
  readonly examples: string;
  /** Why it is absent, when the reason is structural rather than just "not yet". */
  readonly note?: string;
}

/**
 * THE OWASP TOP 10, 2025 EDITION.
 *
 * Two corrections live in this block, and both were caught by someone asking
 * "is that actually true?" of a panel built to be trusted.
 *
 * 1. THE EDITION WAS STALE. Every rule declared `A0x:2021`, and the coverage
 *    panel counted against the 2021 taxonomy. The 2025 edition superseded it -
 *    the numbering moved (Injection is A05 now, not A03), Software Supply Chain
 *    Failures arrived as its own category, and A10 is a new entry entirely. A
 *    tool that names a standard has to name the current one.
 *
 * 2. "COVERED" WAS A LIE OF ROUNDING. The first version of this list was a
 *    binary: a category counted as covered if ANY rule declared it. Three did,
 *    so the panel read "7 of 10 have no rule" - which invites the reader to
 *    conclude the other three are handled. They are not. Injection has one rule
 *    each for SQL, command and XSS, and none for LDAP, XPath, NoSQL, ORM,
 *    template or header injection. Cryptographic Failures is a single weak-hash
 *    check. Authentication Failures is hardcoded credentials and nothing else.
 *
 *    So there is no `covered: true` state here, because nothing earns it. Every
 *    category is either untouched or PARTLY touched, and a partly-touched one
 *    has to say what it leaves out - otherwise the count does the same
 *    overstating the old binary did, one step further in.
 */
const OWASP_2025: readonly {
  id: string;
  title: string;
  examples: string;
  note?: string;
}[] = [
  {
    id: 'A01:2025',
    title: 'Broken Access Control',
    examples: 'path traversal, missing authorisation checks, insecure direct object references',
    note: 'Whether a check is MISSING needs a model of who may do what, which no syntax tree carries.',
  },
  {
    id: 'A02:2025',
    title: 'Security Misconfiguration',
    examples: 'XXE (XML parser left with external entities enabled), debug mode on, permissive CORS',
    note: 'XXE is an ABSENCE rule - the bug is a hardening call that was never written. Every rule here detects a presence, which is a different shape.',
  },
  {
    id: 'A03:2025',
    title: 'Software Supply Chain Failures',
    examples: 'known-vulnerable dependency versions, unpinned or compromised packages',
    note: 'Needs a lockfile and an advisory database, not a syntax tree.',
  },
  {
    id: 'A04:2025',
    title: 'Cryptographic Failures',
    examples: 'weak ciphers, missing TLS, weak randomness, unsalted hashes',
  },
  {
    id: 'A05:2025',
    title: 'Injection',
    examples: 'SQL, command, XSS, LDAP, XPath, NoSQL, ORM, template and header injection',
  },
  {
    id: 'A06:2025',
    title: 'Insecure Design',
    examples: 'missing rate limits, unsafe workflows',
    note: 'A design flaw is not a code pattern; static analysis cannot see it.',
  },
  {
    id: 'A07:2025',
    title: 'Authentication Failures',
    examples: 'hardcoded credentials, weak session handling, missing MFA, credential stuffing',
  },
  {
    id: 'A08:2025',
    title: 'Software or Data Integrity Failures',
    examples: 'insecure deserialization (ObjectInputStream, pickle, unserialize), unsigned updates',
  },
  {
    id: 'A09:2025',
    title: 'Security Logging and Alerting Failures',
    examples: 'absent audit logging, secrets written to logs, no alerting on abuse',
  },
  {
    id: 'A10:2025',
    title: 'Mishandling of Exceptional Conditions',
    examples: 'swallowed errors, fail-open error paths, information leaked through error messages',
  },
];

/** What we DO check inside a category we only partly touch. */
const PARTIAL_NOTES: Record<string, string> = {
  'A04:2025': 'weak hash algorithms only',
  'A05:2025': 'SQL, command and XSS only',
  'A07:2025': 'hardcoded credentials in source only',
  // This category used to be listed as unreachable, on the reasoning that
  // deserialization is "structurally unlike a taint chain". That was wrong, and
  // a Gemini-written test file proved it: `unserialize(base64_decode($_COOKIE
  // ['session']))` is an ordinary source-to-sink flow with a source the engine
  // already tracked. The claim was an assumption dressed up as an analysis.
  'A08:2025': 'deserialization of untrusted input only - unsigned updates and CI/CD integrity are not checked',
};

export function buildCoverageReport(unscannedExtensions: readonly string[] = []): CoverageReport {
  const matrix: CoverageCell[] = [];

  for (const rule of ALL_RULES) {
    for (const language of LANGUAGES) {
      const support = rule.support[language.id];
      matrix.push({
        ruleId: rule.id,
        ruleName: rule.name,
        language: language.id,
        status: support?.status ?? 'not-implemented',
        note:
          support?.note ??
          'NOT IMPLEMENTED: this rule has no pattern for this language, so files in ' +
            'this language were parsed but never checked for this weakness.',
      });
    }
  }

  const counts = {
    rules: ALL_RULES.length,
    languages: LANGUAGES.length,
    implemented: matrix.filter((c) => c.status === 'implemented').length,
    partial: matrix.filter((c) => c.status === 'partial').length,
    notImplemented: matrix.filter((c) => c.status === 'not-implemented').length,
  };

  const taint: TaintCoverageCell[] = LANGUAGES.map((language) => ({
    language: language.id,
    implemented: TAINT_DICTIONARIES[language.id] !== undefined,
    note: TAINT_COVERAGE_NOTES[language.id],
  }));

  return {
    engine: ENGINE_CAPABILITIES,
    taint,
    matrix,
    gaps: matrix.filter((c) => c.status !== 'implemented'),
    counts,
    unscannedExtensions: [...unscannedExtensions].sort(),
    // Computed from the registry, so adding a rule quietly removes its category
    // from this list and nobody has to remember to update prose.
    owaspCoverage: OWASP_2025.map((category) => {
      const rules = ALL_RULES.filter((rule) => rule.owasp.startsWith(category.id)).map((r) => r.id);
      const partial = PARTIAL_NOTES[category.id];
      return {
        id: category.id,
        title: category.title,
        state: rules.length > 0 ? ('partial' as const) : ('none' as const),
        rules,
        ...(rules.length > 0 && partial ? { weCheck: partial } : {}),
        examples: category.examples,
        ...(category.note ? { note: category.note } : {}),
      };
    }),
  };
}
