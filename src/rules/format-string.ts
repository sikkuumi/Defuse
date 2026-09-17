/**
 * FORMAT STRING INJECTION  (CWE-134)
 *
 * WHAT THE BUG IS.
 *
 *     printf(name);            // `name` came from the user
 *
 * looks like printing a string and is not. printf reads its first argument as a
 * FORMAT, so whoever controls that string controls the conversions too:
 *
 *     %x %x %x %x     walks up the stack and prints whatever is sitting there
 *     %s              treats a stack value as a pointer - crash, or a leak
 *     %n              WRITES the number of bytes printed so far to a pointer
 *                     argument, which turns a logging call into an arbitrary
 *                     memory write
 *
 * That last conversion is why this is not a cosmetic bug. It is the standard
 * route from "the program logs a username" to "the attacker runs code".
 *
 * WHY THIS RULE IS THE BEST ARGUMENT FOR POINTING A TAINT ENGINE AT C.
 *
 * Most famous C bugs are SIZE bugs - is this buffer big enough, is this integer
 * about to wrap - and answering those needs an analysis of sizes, allocations
 * and aliasing that this engine does not have. The unbounded-copy rule next
 * door is careful to claim much less than its name suggests for exactly that
 * reason.
 *
 * A format string bug needs none of it. The entire question is "is this ONE
 * argument attacker-controlled?", which is the only question this engine
 * answers, and it answers it with a printed path. So a flow-verified finding
 * here means precisely what it says, with no hedge underneath it.
 *
 * THE TRAP THIS RULE MUST NOT FALL INTO.
 *
 *     printf(name)             dangerous
 *     printf("%s", name)       correct
 *
 * Same function, one extra argument - the identical shape as a parameterised
 * SQL query versus a concatenated one. A rule that fired on "printf with a
 * tainted argument" would report the FIX as the bug, which this project treats
 * as worse than a miss: it teaches people that hardening does not help. Only
 * the format argument counts, and its index differs per function, so the table
 * below is the whole rule.
 */

import type { LanguageId } from '../parse/languages.js';
import { asCall, type Rule, type RuleHit } from './contract.js';
import { isStringLiteral } from './lib/strings.js';

/**
 * Function name -> which argument is the FORMAT.
 *
 * Getting an index wrong here does not just miss a bug, it reports correct
 * code, so each one is written out rather than inferred from the name.
 */
const FORMAT_ARGUMENT: ReadonlyMap<string, number> = new Map([
  ['printf', 0],
  ['vprintf', 0],
  ['fprintf', 1],
  ['sprintf', 1],
  ['vfprintf', 1],
  ['vsprintf', 1],
  ['dprintf', 1],
  ['asprintf', 1],
  ['syslog', 1],
  ['snprintf', 2],
  ['vsnprintf', 2],
]);

const C_FAMILY: ReadonlySet<LanguageId> = new Set<LanguageId>(['c', 'cpp']);

const NOT_C = {
  status: 'not-implemented' as const,
  note:
    'Format string injection is a C-family bug. Other languages either take the format ' +
    'as a constant by construction or have no %n equivalent, so there is nothing here to ' +
    'match and this rule never fires. Stated rather than left as a blank column.',
};

export const formatStringRule: Rule = {
  id: 'format-string',
  name: 'Attacker-controlled format string',
  cwe: 'CWE-134',
  owasp: 'A05:2025 Injection',
  severity: 'high',
  explanation:
    'A format string is a small program: %x reads, %s dereferences, and %n WRITES. When ' +
    'the format itself comes from the user, they are writing that program. The fix is ' +
    'always the same shape and always cheap - make the format a constant and pass the ' +
    'value as data: printf("%s", name) instead of printf(name).',
  limitations:
    'A signature-based finding here means only that the format argument is not a literal ' +
    'in this call - it may be a constant defined elsewhere, which we cannot see because ' +
    'the preprocessor is not run and constants are not folded. A flow-verified finding ' +
    'means the value was traced from an attacker-controlled source into the format ' +
    'position, and that claim carries its path.',
  shapes: ['call'],
  support: {
    c: {
      status: 'implemented',
      note:
        'Covers the printf family (printf, fprintf, sprintf, snprintf, dprintf, asprintf, ' +
        'syslog and their v- variants), with the format argument index recorded per ' +
        'function so that the correct form - a constant format with the value passed as ' +
        'data - is never reported. A format built by a macro is missed: the preprocessor ' +
        'is not run.',
    },
    cpp: {
      status: 'implemented',
      note:
        'Identical to C. std::format and iostreams are type-safe and cannot carry this ' +
        'bug, so they are deliberately not matched; C++ code that calls printf still can, ' +
        'and still does.',
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

    const index = FORMAT_ARGUMENT.get(call.calleeName);
    if (index === undefined) return null;

    const formatArgument = call.args[index];
    // No argument in the format position at all - nothing to say about it.
    if (!formatArgument) return null;

    /*
     * A literal format is the SAFE form and the whole point of the fix. It is
     * checked first and returns null, so `printf("%s", name)` can never be
     * reported however dirty `name` is.
     */
    if (isStringLiteral(formatArgument, ctx.language)) return null;

    const argumentText = ctx.text(formatArgument);
    return {
      node: call.node,
      message: `${call.calleeName}() is called with a non-constant format string (\`${argumentText}\`)`,
      reasoning:
        `The format argument of \`${call.calleeName}()\` is \`${argumentText}\`, which is not a ` +
        `string literal. A format string is executable: \`%x\` reads values off the stack, ` +
        `\`%s\` dereferences one as a pointer, and \`%n\` writes to memory. If that value ` +
        `can be influenced by a user, this is a memory-write primitive rather than a print ` +
        `statement. The fix is to make the format constant and pass the value as data: ` +
        `\`${call.calleeName}(${index === 0 ? '' : '..., '}"%s", ${argumentText})\`.`,
    };
  },
};
