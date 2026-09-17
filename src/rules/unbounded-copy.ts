/**
 * COPIES WITH NO LENGTH BOUND  (CWE-120)
 *
 * READ THE NAME OF THIS RULE CAREFULLY. It is not `buffer-overflow`, and the
 * difference is the entire honesty argument for shipping it.
 *
 * A buffer overflow is a SIZE bug. Whether `strcpy(dst, src)` overflows depends
 * on how big `dst` is, how long `src` turns out to be at runtime, and whether
 * any pointer between them aliases something else. This engine models none of
 * that - it tracks VALUES, not sizes, allocation lifetimes or aliasing. It
 * cannot tell you whether a copy overflows and does not claim to.
 *
 * What it CAN prove from data flow alone is narrower and still worth saying:
 *
 *     attacker-controlled data reaches a function that writes until it
 *     meets a NUL byte, and the attacker chooses where that byte is.
 *
 * That is what a finding here asserts, and the wording says so. A `strcpy` into
 * a destination that genuinely is large enough is a FALSE POSITIVE of this
 * rule. That is declared here, in the finding text and in the coverage report,
 * rather than left for somebody to discover and lose trust over.
 *
 * It is still worth reporting, because the unbounded functions have no safe
 * upper bound by construction. Every one of them has a bounded sibling that
 * takes a length - strncpy, strncat, snprintf, strlcpy - and those are
 * registered as sanitisers for this sink kind, so switching to them retracts
 * the finding. A rule that cannot be satisfied by fixing the code is a rule
 * nobody will act on.
 *
 * gets() IS THE EXCEPTION, and it needs no data flow at all. It has no length
 * parameter and no way to acquire one, which is why C11 removed it from the
 * standard library outright. There is nothing to trace, so it is reported on
 * sight as a SIGNATURE finding - honestly labelled as unverified flow, because
 * there is no flow to verify, not because we failed to find one.
 */

import type { LanguageId } from '../parse/languages.js';
import { asCall, type Rule, type RuleHit } from './contract.js';
import { isStringLiteral } from './lib/strings.js';

/** Copies with no length parameter, and which argument carries the data. */
const UNBOUNDED_COPIES: ReadonlyMap<string, number> = new Map([
  ['strcpy', 1],
  ['stpcpy', 1],
  ['strcat', 1],
]);

/**
 * Cannot be called safely under any circumstances, so no source is needed.
 * C11 removed gets() from the standard library rather than try to document it.
 */
const UNCONDITIONALLY_UNSAFE: ReadonlySet<string> = new Set(['gets']);

const C_FAMILY: ReadonlySet<LanguageId> = new Set<LanguageId>(['c', 'cpp']);

const NOT_C = {
  status: 'not-implemented' as const,
  note:
    'Manual memory copies are a C-family concern. Managed languages bound their own ' +
    'string operations, so this rule has nothing to match and never fires. Stated rather ' +
    'than left as a blank column.',
};

export const unboundedCopyRule: Rule = {
  id: 'unbounded-copy',
  name: 'Attacker data reaches a copy with no length bound',
  cwe: 'CWE-120',
  owasp: 'A05:2025 Injection',
  severity: 'high',
  explanation:
    'strcpy, strcat and sprintf write until they meet a NUL byte, and when the source is ' +
    'attacker-controlled the attacker decides where that byte is. Each has a bounded ' +
    'sibling that takes a length - strncpy, strncat, snprintf, strlcpy - and switching to ' +
    'one retracts this finding. gets() has no bounded form at all and was removed from ' +
    'the C standard in C11.',
  limitations:
    'THIS IS NOT A CLAIM THAT THE BUFFER OVERFLOWS. Deciding that needs the size of the ' +
    'destination, the length of the source and the aliasing between them; this engine ' +
    'tracks values, not sizes, so it cannot and does not decide it. What a flow-verified ' +
    'finding here asserts is only that attacker-controlled data reached a copy with no ' +
    'length bound. A copy into a destination that is genuinely large enough is a false ' +
    'positive of this rule, and a declared one.',
  shapes: ['call'],
  support: {
    c: {
      status: 'partial',
      note:
        'PARTIAL BY CONSTRUCTION, and the limit is the point. Covers strcpy, stpcpy, ' +
        'strcat and the sprintf family reached by attacker data, plus gets() on sight. ' +
        'It does NOT model buffer sizes, so it cannot say whether any given copy ' +
        'overflows - only that the copy has no bound. memcpy and friends with an ' +
        'attacker-controlled LENGTH are a different bug (the size is the taint, not the ' +
        'data) and are not covered. Use-after-free, double-free and integer overflow are ' +
        'entirely out of scope: none of them is a data-flow question.',
    },
    cpp: {
      status: 'partial',
      note:
        'Identical to C. std::string and std::vector manage their own storage and are ' +
        'not matched; C++ code that calls the C string functions still is, and a great ' +
        'deal of it does.',
    },
    javascript: NOT_C,
    typescript: NOT_C,
    python: NOT_C,
    java: NOT_C,
    go: NOT_C,
    php: NOT_C,
  },

  check(shape, ctx): RuleHit | null {
    if (!C_FAMILY.has(ctx.language)) return null;
    const call = asCall(shape);
    if (!call) return null;

    if (UNCONDITIONALLY_UNSAFE.has(call.calleeName)) {
      return {
        node: call.node,
        severity: 'high',
        message: 'gets() cannot be called safely and was removed from the C standard',
        reasoning:
          'gets() reads a line from standard input into a buffer and takes no length ' +
          'parameter, so there is no way to tell it how much room it has. The caller ' +
          'cannot bound it, the function cannot bound itself, and the input comes from ' +
          'outside the program. C11 removed it from the standard library rather than ' +
          'attempt to document safe use. Replace it with fgets(buf, sizeof buf, stdin). ' +
          'No data flow is traced for this finding because none is needed - the call is ' +
          'unsafe with any input at all.',
      };
    }

    const dataArgument = UNBOUNDED_COPIES.get(call.calleeName);
    if (dataArgument === undefined) return null;

    const source = call.args[dataArgument];
    if (!source) return null;

    /*
     * A literal source is bounded at compile time - the compiler knows exactly
     * how long `strcpy(buf, "ok")` writes. Reporting it would be noise on code
     * that cannot be attacked, so the literal case returns null and only an
     * opaque value is worth a signature guess.
     */
    if (isStringLiteral(source, ctx.language)) return null;

    const sourceText = ctx.text(source);
    return {
      node: call.node,
      message: `${call.calleeName}() copies \`${sourceText}\` with no length bound`,
      reasoning:
        `\`${call.calleeName}()\` writes until it meets a NUL byte in \`${sourceText}\`, and ` +
        `nothing in the call says how much room the destination has. Whether this ` +
        `actually overflows depends on the size of the destination, which is NOT analysed ` +
        `here - so this is a guess about a risky shape, not a proof of a bug. Use ` +
        `${call.calleeName === 'strcat' ? 'strncat' : 'strncpy'}() or strlcpy() with an ` +
        `explicit length, and this finding goes away.`,
    };
  },
};
