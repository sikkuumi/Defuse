/**
 * STRING BUILDING ANALYSIS
 * ========================
 *
 * Almost every injection bug in this tool's catalogue has the same skeleton:
 * a string was ASSEMBLED at runtime and then handed to something that treats
 * strings as instructions (a database, a shell, a browser).
 *
 * So the one question we ask over and over is: "was this expression a fixed
 * piece of text, or was it stitched together from parts?" This file answers it
 * for all five languages, and it is the piece of shared machinery that lets one
 * rule cover JavaScript, Python, Java and Go at once.
 *
 * VOCABULARY YOU'LL NEED:
 *
 *   Sanitisation - cleaning or neutralising untrusted input before use. For SQL
 *     the real fix is not cleaning at all but PARAMETERISATION: you hand the
 *     database the query and the values separately, so the values can never be
 *     read as commands. For HTML it means escaping < > & " so text is displayed
 *     rather than executed.
 *
 *   Interpolation - languages' built-in "put this value inside this string"
 *     syntax: `${x}` in JS, f"{x}" in Python, fmt.Sprintf("%s", x) in Go.
 *     To a database or a shell it is identical to concatenation. Feeling
 *     modern does not make it safe.
 *
 * PHASE 1 HONESTY NOTE: knowing a string was built dynamically does NOT mean
 * the parts came from an attacker. `"SELECT * FROM " + TABLE_NAME` with a
 * hard-coded constant is fine. We cannot tell the difference without data-flow
 * analysis, which is Phase 3. That is exactly why these findings are labelled
 * signature-based, and why every one of them says so in its `limitations`.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../../parse/languages.js';

/** Node types that ARE a string literal, per language. */
const STRING_LITERAL_TYPES: Record<LanguageId, readonly string[]> = {
  javascript: ['string', 'template_string'],
  typescript: ['string', 'template_string'],
  python: ['string', 'concatenated_string'],
  java: ['string_literal', 'text_block'],
  go: ['interpreted_string_literal', 'raw_string_literal'],
  // PHP's `string` is single-quoted (never interpolates). `encapsed_string` is
  // double-quoted and CAN interpolate, which is why it appears in both this
  // list and INTERPOLATION_TYPES - isStringLiteral checks for a spliced-in
  // value before calling it a literal.
  php: ['string', 'encapsed_string', 'heredoc'],
};

/** Node types that mean "a value was spliced into this string". */
const INTERPOLATION_TYPES = new Set([
  'template_substitution', // JS/TS  `... ${x} ...`
  'interpolation', // Python f"...{x}..."
  // PHP splices a variable straight into a double-quoted string with no wrapper
  // node: "id = $id" holds a `variable_name` child directly. The name exists
  // only in the PHP grammar, so listing it here cannot affect another language.
  'variable_name', // PHP  "... $x ..." and "... {$x} ..."
]);

/** Node types holding the plain-text chunks inside a string literal. */
const STRING_CONTENT_TYPES = new Set([
  'string_fragment',
  'string_content',
  'interpreted_string_literal_content',
  'raw_string_literal_content',
]);

/** Function names that build a string from a template plus values. */
const FORMAT_FUNCTIONS = new Set([
  'format', // Python "..."​.format(), Java String.format
  'sprintf',
  'Sprintf', // Go fmt.Sprintf
  'Sprintln',
  'Fprintf',
  'printf',
  'Printf',
  'join', // "".join([...]) and String.join
  'concat',
  'append', // Java StringBuilder.append chains
  'valueOf',
]);

export type BuildMechanism =
  | 'literal' // a fixed string, nothing spliced in
  | 'concatenation' // built with + (or % in Python)
  | 'interpolation' // built with `${}` / f-strings
  | 'format-call' // built with Sprintf / .format() / String.format
  | 'opaque'; // a variable or call - we cannot see the text at all

export interface StringExpression {
  /** True when the text is not fully known at write time. */
  readonly isDynamic: boolean;
  readonly mechanism: BuildMechanism;
  /** The fixed parts we could read, joined. Empty when the whole thing is opaque. */
  readonly literalText: string;
  /** The expressions spliced in. Reported so a human can judge them. */
  readonly dynamicParts: readonly string[];
}

/**
 * Node types that can be the TOP of a string-building expression.
 *
 * This gate exists because of a false positive found by pointing the scanner at
 * its own source code. `analyzeStringExpression` walks a whole subtree and
 * concatenates every string literal it finds. Handed an object literal like
 *
 *     export const sqlInjectionRule: Rule = {
 *       name: 'SQL query assembled from a built string',
 *       explanation: '... the query and the values ... update ... table ...',
 *       ...
 *     };
 *
 * it happily merged prose from a dozen unrelated fields into one blob, and
 * `looksLikeSql()` found "select", "from" and "where" scattered through it.
 * The scanner reported its own rule definitions as SQL injection.
 *
 * The lesson generalises: an analysis is only as good as the SCOPE it runs on.
 * Before asking "does this text look like SQL?", make sure the thing you are
 * looking at is a single string expression - not a container full of unrelated
 * strings that happen to sit next to each other.
 */
const STRING_EXPRESSION_TYPES: Record<LanguageId, readonly string[]> = {
  javascript: ['string', 'template_string', 'binary_expression', 'call_expression'],
  typescript: ['string', 'template_string', 'binary_expression', 'call_expression'],
  python: ['string', 'concatenated_string', 'binary_operator', 'call'],
  java: ['string_literal', 'text_block', 'binary_expression', 'method_invocation'],
  go: [
    'interpreted_string_literal',
    'raw_string_literal',
    'binary_expression',
    'call_expression',
  ],
  php: [
    'string',
    'encapsed_string',
    'heredoc',
    'binary_expression', // PHP concatenates with `.`
    'function_call_expression',
    'member_call_expression',
  ],
};

/**
 * True when this node could plausibly evaluate to a string that was assembled.
 * Object literals, arrays, functions and class bodies return false - they are
 * containers, not strings, even though they contain strings.
 */
export function isStringBuildingExpression(node: Node, language: LanguageId): boolean {
  return STRING_EXPRESSION_TYPES[language].includes(node.type);
}

export function isStringLiteral(node: Node, language: LanguageId): boolean {
  const types = STRING_LITERAL_TYPES[language];
  if (!types.includes(node.type)) return false;
  // An f-string or template literal WITH a substitution is not a literal.
  return !containsType(node, INTERPOLATION_TYPES, 6);
}

function containsType(node: Node, types: Set<string>, maxDepth: number): boolean {
  if (maxDepth <= 0) return false;
  for (const child of node.namedChildren) {
    if (!child) continue;
    if (types.has(child.type)) return true;
    if (containsType(child, types, maxDepth - 1)) return true;
  }
  return false;
}

/** Remove surrounding quotes, backticks and prefixes (f"", b'', @"", `` ). */
export function unquote(raw: string): string {
  return raw
    .replace(/^[a-zA-Z]{0,2}(["'`])((?:.|\n)*)\1$/, '$2')
    .replace(/^"""|"""$/g, '')
    .replace(/^'''|'''$/g, '');
}

/**
 * Read an expression and describe how its text was assembled.
 *
 * The walk is deliberately shallow (depth-limited) and deliberately simple: it
 * collects three things - fixed text chunks, evidence of splicing, and the
 * spliced expressions - and infers the mechanism from what it found. It does
 * NOT try to evaluate the expression. A scanner that guesses at runtime values
 * is a scanner that lies.
 */
export function analyzeStringExpression(
  node: Node,
  language: LanguageId,
  maxDepth = 10,
): StringExpression {
  const literalChunks: string[] = [];
  const dynamicParts: string[] = [];
  let sawInterpolation = false;
  let sawConcatenation = false;
  let sawFormatCall = false;
  let sawOpaqueRef = false;

  const visit = (current: Node, depth: number): void => {
    if (depth > maxDepth) return;

    // A string literal: harvest its fixed text and stop (unless it interpolates).
    if (STRING_LITERAL_TYPES[language].includes(current.type)) {
      const contents = current.namedChildren.filter(
        (c): c is Node => c !== null && STRING_CONTENT_TYPES.has(c.type),
      );
      if (contents.length > 0) {
        for (const chunk of contents) literalChunks.push(chunk.text ?? '');
      } else if (!containsType(current, INTERPOLATION_TYPES, 4)) {
        literalChunks.push(unquote(current.text ?? ''));
      }
      // Still descend, because a template string can hold substitutions.
      for (const child of current.namedChildren) {
        if (child && INTERPOLATION_TYPES.has(child.type)) visit(child, depth + 1);
      }
      return;
    }

    if (INTERPOLATION_TYPES.has(current.type)) {
      sawInterpolation = true;
      const inner = (current.text ?? '').replace(/^\$?\{|\}$/g, '').trim();
      if (inner) dynamicParts.push(inner);
      return;
    }

    // Concatenation. JS/Java/Go call it binary_expression, Python binary_operator.
    if (current.type === 'binary_expression' || current.type === 'binary_operator') {
      const operator = current.childForFieldName('operator')?.text ?? '';
      if (operator === '+' || operator === '%') {
        sawConcatenation = true;
        for (const child of current.namedChildren) if (child) visit(child, depth + 1);
        return;
      }
    }

    // A call: is it a formatter, or just an opaque value?
    if (
      current.type === 'call' ||
      current.type === 'call_expression' ||
      current.type === 'method_invocation'
    ) {
      const nameNode =
        current.childForFieldName('name') ??
        current.childForFieldName('function') ??
        current.childForFieldName('constructor');
      const nameText = nameNode?.text ?? '';
      const lastSegment = nameText.split(/[.:]/).pop() ?? nameText;
      if (FORMAT_FUNCTIONS.has(lastSegment)) {
        sawFormatCall = true;
        for (const child of current.namedChildren) if (child) visit(child, depth + 1);
        return;
      }
      sawOpaqueRef = true;
      dynamicParts.push((current.text ?? '').replace(/\s+/g, ' ').trim().slice(0, 60));
      return;
    }

    if (
      current.type === 'identifier' ||
      current.type === 'member_expression' ||
      current.type === 'attribute' ||
      current.type === 'selector_expression' ||
      current.type === 'field_access' ||
      current.type === 'subscript' ||
      current.type === 'subscript_expression' ||
      current.type === 'index_expression'
    ) {
      sawOpaqueRef = true;
      dynamicParts.push((current.text ?? '').replace(/\s+/g, ' ').trim().slice(0, 60));
      return;
    }

    for (const child of current.namedChildren) if (child) visit(child, depth + 1);
  };

  visit(node, 0);

  const literalText = literalChunks.join('');
  let mechanism: BuildMechanism = 'literal';
  if (sawInterpolation) mechanism = 'interpolation';
  else if (sawConcatenation && dynamicParts.length > 0) mechanism = 'concatenation';
  else if (sawFormatCall) mechanism = 'format-call';
  else if (sawOpaqueRef && literalChunks.length === 0) mechanism = 'opaque';
  else if (sawOpaqueRef) mechanism = 'concatenation';

  return {
    isDynamic: mechanism !== 'literal',
    mechanism,
    literalText,
    dynamicParts,
  };
}

/* ---------------------------------------------------------------------------
 * "Does this text look like X?" helpers.
 *
 * These are intentionally conservative. Their job is to stop the scanner
 * shouting about `"Hello " + name`, which is not a SQL query and never was.
 * ------------------------------------------------------------------------ */

/* ---------------------------------------------------------------------------
 * DOES THIS TEXT LOOK LIKE SQL?
 *
 * The first version of this asked three independent questions of the text:
 * is there a SQL verb ANYWHERE, a clause keyword ANYWHERE, and a general SQL
 * keyword ANYWHERE. Three yesses meant "this is a query".
 *
 * Pointing the scanner at its own source found the flaw. This paragraph -
 * the honesty disclaimer printed under every flow-verified finding - is built
 * from eight string chunks joined with `+`. `analyzeStringExpression` merges
 * them into one 638-character blob, and the blob contains:
 *
 *     verb   "call"  from ... a CALL into a third-party package ...
 *     clause "into"  from ... a call INTO a third-party package ...
 *     clause "where" from ... - WHERE imports resolve - ...
 *
 * Three matches, drawn from two unrelated sentences, and the scanner reported
 * its own disclaimer as a SQL injection. Proximity alone would not have saved
 * it either: `call ... into` are adjacent words.
 *
 * The fix is to stop asking "are these words present?" and start asking
 * "is this the SHAPE of a statement?". Real SQL is not a bag of keywords, it
 * is a grammar: SELECT is followed by FROM, INSERT is followed by INTO,
 * UPDATE is followed by SET. English prose containing the same words almost
 * never puts them in that order, in that span, without a full stop between.
 *
 * This is the same lesson as the STRING_EXPRESSION_TYPES gate above, one level
 * down: there the scope was wrong, here the test was too weak for the scope.
 * ------------------------------------------------------------------------ */

/**
 * The canonical statement shapes. Each one pairs a verb with the clause the
 * SQL grammar REQUIRES to follow it, within a bounded window - so the two
 * halves have to belong to the same statement, not the same paragraph.
 */
const SQL_STATEMENT_SHAPES: readonly RegExp[] = [
  /\bselect\b[\s\S]{0,300}?\bfrom\b/i,
  /\binsert\s+(?:ignore\s+|or\s+\w+\s+)?into\b/i,
  /\bupdate\b[\s\S]{0,200}?\bset\b/i,
  /\bdelete\s+from\b/i,
  /\bmerge\s+into\b/i,
  /\breplace\s+into\b/i,
  /\bunion(?:\s+all)?\s+select\b/i,
  /\bwith\b[\s\S]{0,200}?\bas\s*\(/i, // common table expression
  /\bcall\s+[\w.]+\s*\(/i, // stored procedure
  /\bexec(?:ute)?\s+(?:sp_|dbo\.|[\w.]+\s*[('@])/i,
  /\b(?:drop|alter|create|truncate)\s+(?:table|index|view|database|schema)\b/i,
  // Query FRAGMENTS: a lot of real injection is ` WHERE id = ` + x, appended
  // to a query built elsewhere. A clause keyword sitting at the very start of
  // the fragment is the tell, and prose does not open that way.
  /^\s*(?:and|or|where|from|order\s+by|group\s+by|having|limit|offset|values)\b/i,
];

/**
 * A full stop followed by a capital letter, or a comma followed by a
 * conjunction, means the window crossed a sentence boundary - so the verb and
 * the clause came from different thoughts, not from one statement.
 * SQL has no sentences; prose has little else.
 */
const SENTENCE_BREAK = /[.!?]\s+[A-Z(]|[,;:]\s+(?:and|or|but|so|which|because|then)\b/;

/**
 * SQL needs the SHAPE of a statement, not a scattering of keywords.
 * Conservative on purpose: a fragment we cannot recognise is reported as
 * "not SQL", which loses a finding rather than inventing one.
 */
export function looksLikeSql(text: string): boolean {
  if (text.length < 8) return false;
  for (const shape of SQL_STATEMENT_SHAPES) {
    const match = shape.exec(text);
    if (!match) continue;
    if (SENTENCE_BREAK.test(match[0])) continue;
    return true;
  }
  return false;
}

export function looksLikeHtml(text: string): boolean {
  return /<\s*[a-zA-Z][a-zA-Z0-9-]*(\s|>|\/)/.test(text) || /&(lt|gt|amp|quot);/.test(text);
}

const SHELL_HINTS =
  /(^|[\s;&|])(rm|ls|cat|cp|mv|curl|wget|sh|bash|zsh|ping|tar|zip|unzip|chmod|chown|kill|git|npm|pip|docker|ssh|scp|echo|grep|find|awk|sed|systemctl|service)\b|[;&|`]|\$\(/;

export function looksLikeShellCommand(text: string): boolean {
  return text.length > 1 && SHELL_HINTS.test(text);
}

/**
 * Shannon entropy: a number for "how random does this look?".
 * Roughly - English prose scores ~2.5-3.5 bits/char, a base64 API key ~4.5-6.
 * It is a hint, never a verdict, and we say so in the finding.
 */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Strings that are obviously not real credentials. Keeps the noise down. */
const PLACEHOLDER_PATTERNS: readonly RegExp[] = [
  /^$/,
  /^(x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,})$/i,
  /^(none|null|nil|undefined|true|false|test|todo|fixme|example|sample|dummy|placeholder|changeme|change_me|your[-_ ]?\w*|my[-_ ]?\w*|insert[-_ ]?\w*|redacted|secret|password|passwd|pwd|key|token|value|string|foo|bar|baz|abc123?|123456?)$/i,
  /^\$\{?[\w.]+\}?$/, // ${ENV_VAR} or $VAR - a reference, not a value
  /^%[\ws]$/, // printf placeholder
  /^\{\{?[\w.]+\}?\}$/, // {{ template }}
  /^<[^>]+>$/, // <your-key-here>
  /^(process\.env|os\.environ|System\.getenv|os\.Getenv)/,
  // Values that announce themselves as not-real anywhere inside the string.
  // Added after scanning real repositories, where `'faketoken'`, `'Bearer ...'`
  // and `'s00pers3cret'`-style fixtures dominated the results.
  /(fake|dummy|sample|example|placeholder|redacted|changeme|notreal|xxxx|\.\.\.)/i,
];

/*
 * Values that are SETTINGS, not secrets.
 *
 * `credentials` matches the credential naming pattern, so this line
 *
 *     fetch(url, { credentials: "same-origin" })
 *
 * read as a hardcoded credential - twice, inside the vendored tree-sitter
 * runtime, on a self-scan. It is a fixed enum from the fetch specification and
 * there is no possible value of it that is a secret.
 *
 * The whole set is listed rather than just the three `credentials` values,
 * because the neighbouring RequestInit fields (`mode`, `cache`, `redirect`)
 * are one rename away from the same problem. These are exact, whole-string
 * matches against a closed vocabulary defined by the web platform - not a
 * guess about what looks secret-ish.
 */
const WEB_PLATFORM_ENUMS: ReadonlySet<string> = new Set([
  // RequestInit.credentials
  'same-origin',
  'include',
  'omit',
  // RequestInit.mode
  'cors',
  'no-cors',
  'navigate',
  // RequestInit.cache
  'default',
  'no-store',
  'reload',
  'no-cache',
  'force-cache',
  'only-if-cached',
  // RequestInit.redirect
  'follow',
  'manual',
  'error',
]);

export function isLikelyPlaceholder(text: string): boolean {
  const trimmed = text.trim();
  if (WEB_PLATFORM_ENUMS.has(trimmed.toLowerCase())) return true;
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(trimmed));
}

/**
 * "Could this string plausibly BE a credential?" - a structural gate we apply
 * before the entropy heuristic.
 *
 * This function exists because of measurement, not theory. Running the entropy
 * check alone against five real open-source repositories produced 80 findings,
 * and the top offenders were things like:
 *
 *     'application/x-www-form-urlencoded'   a MIME type
 *     'abcdefghijklmnopqrstuvwxyz'          a literal alphabet
 *     'https://images.opencollective.com/…' a URL
 *
 * All three score high on randomness and none of them is a secret. Real tokens
 * share a shape: no spaces, no slashes, and a MIX of character classes. Testing
 * for that shape first removes the whole category of noise above without
 * weakening detection of anything that actually looks like a key.
 */
export function looksLikeToken(value: string): boolean {
  if (/[\s/\\@]/.test(value)) return false; // URLs, paths, MIME types, sentences
  if (/^[a-z.\-_]+$/.test(value)) return false; // lowercase words / kebab / dotted names
  if (/^[A-Z.\-_]+$/.test(value)) return false; // SCREAMING_CONSTANT names
  if (/^\d+$/.test(value)) return false; // pure numbers, timestamps, ids

  const classes =
    (/[a-z]/.test(value) ? 1 : 0) + (/[A-Z]/.test(value) ? 1 : 0) + (/[0-9]/.test(value) ? 1 : 0);
  return classes >= 2;
}

/**
 * Paths that mean "this is a fixture, not production configuration".
 * A credential in a test file is still a credential in git history, so we do
 * not drop these findings - we lower their severity and say why.
 */
export function isTestPath(filePath: string): boolean {
  return /(^|[/\\])(tests?|spec|specs|__tests__|__mocks__|fixtures?|examples?|e2e|benchmarks?|mocks?)([/\\]|$)|\.(test|spec)\.[a-z]+$|_test\.[a-z]+$|Test\.java$/i.test(
    filePath,
  );
}

/** Well-known credential formats. A hit here is far stronger than entropy alone. */
export interface KnownSecretFormat {
  readonly label: string;
  readonly pattern: RegExp;
}

export const KNOWN_SECRET_FORMATS: readonly KnownSecretFormat[] = [
  { label: 'AWS access key id', pattern: /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/ },
  { label: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/ },
  { label: 'Slack token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'Stripe secret key', pattern: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b/ },
  { label: 'Google API key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'OpenAI API key', pattern: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { label: 'JSON Web Token', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { label: 'private key block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: 'Twilio account SID', pattern: /\bAC[0-9a-fA-F]{32}\b/ },
  { label: 'SendGrid API key', pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/ },
  { label: 'connection string with password', pattern: /:\/\/[^\s:@/]+:[^\s:@/]{3,}@/ },
];

/* ---------------------------------------------------------------------------
 * VENDOR DOCUMENTATION EXAMPLES
 *
 * `AKIAIOSFODNN7EXAMPLE` is not an AWS access key. It is the string AWS
 * itself prints in its own documentation, chosen so that it matches the key
 * FORMAT while being guaranteed never to authenticate anything. It appears in
 * README files, tutorials and UI demos everywhere, and the scanner found one
 * in this project's own demo panel and called it a hardcoded credential.
 *
 * That finding was not merely noisy, it was FALSE: nothing was hardcoded and
 * nothing needs rotating. So this is not a severity downgrade like the
 * test-path rule - the claim itself does not hold, and the finding is dropped.
 *
 * The allowlist is deliberately narrow. Vendors mark their examples by ending
 * them in EXAMPLE (AWS's convention, used consistently across its docs) or by
 * filling the random portion with an obvious run of digits. A real key landing
 * on one of these by chance is a 1-in-10^12 event; a real key that a developer
 * has deliberately named EXAMPLE is not a case this tool can help with.
 *
 * Anything dropped here is listed in the rule's `limitations` text, so the gap
 * is documented rather than silent.
 * ------------------------------------------------------------------------ */
const VENDOR_DOC_EXAMPLES: readonly RegExp[] = [
  /EXAMPLE(KEY|SECRET)?$/, // AWS: AKIAIOSFODNN7EXAMPLE, ...bPxRfiCYEXAMPLEKEY
  /\b(AKIA|ASIA|ABIA|ACCA)(?:0{6,}|1234567890|X{6,})/i, // filler-digit stand-ins
  /^(?:sk|rk|pk)_(?:live|test)_(?:example|1234567890|abcdef|0000)/i,
  /\bAIza(?:SyExample|0{10,})/i,
  /\bxox[abprs]-(?:example|0000|1234567890)/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----\s*(?:\.\.\.|EXAMPLE|YOUR)/i,
];

/**
 * True when a value matches a vendor key format but is a published,
 * deliberately non-functional documentation example rather than a credential.
 *
 * Pass the MATCHED KEY, not the string it was found in. The first version of
 * this tested the whole enclosing string, so a demo code sample containing
 * `AKIAIOSFODNN7EXAMPLE` in the middle of two hundred other characters never
 * matched the `...EXAMPLE$` anchor and was still reported as a live key. The
 * question is about the credential, so it has to be asked of the credential.
 */
export function isVendorDocExample(matchedKey: string): boolean {
  return VENDOR_DOC_EXAMPLES.some((pattern) => pattern.test(matchedKey));
}

export function matchKnownSecret(text: string): KnownSecretFormat | null {
  for (const format of KNOWN_SECRET_FORMATS) {
    const match = format.pattern.exec(text);
    if (!match) continue;
    if (isVendorDocExample(match[0])) continue;
    return format;
  }
  return null;
}

/* -------------------------------------------------------------------------- *
 * PROVABLY-CONSTANT INTERPOLATION
 *
 * A tester handed the scanner this, expecting silence:
 *
 *     def get_admin_table():
 *         table_name = "admin_users"          # hardcoded, no external input
 *         query = f"SELECT * FROM {table_name}"
 *         return conn.execute(query)
 *
 * It flagged the f-string. The label was correct - `signature-based`, data flow
 * NOT traced - but the finding was still noise: the only spliced-in value is a
 * string literal written on the line above. A scanner that reports that teaches
 * people to skim past it, and this project's own test suite treats a false
 * positive as a failure for exactly that reason.
 *
 * So: if EVERY spliced-in part is a plain name bound only to literal constants
 * in the enclosing scope, the string is not dynamic in any sense a reader cares
 * about, and the rule stays quiet.
 *
 * Deliberately conservative in three ways, because losing a real finding is a
 * worse trade than printing a weak one:
 *   - a part that is not a bare identifier (a call, an index, an attribute)
 *     is never treated as constant;
 *   - a name with NO visible binding - a parameter, an import, a global from
 *     another file - is never treated as constant;
 *   - a name bound more than once is constant only if EVERY binding is a
 *     literal, so `t = "x"` followed later by `t = request.args.get(...)`
 *     still flags.
 * -------------------------------------------------------------------------- */

/** Nodes that introduce a scope worth searching for bindings. */
const SCOPE_NODES = new Set([
  'function_declaration', 'function_expression', 'arrow_function', 'method_definition',
  'function_definition', 'lambda',
  'method_declaration', 'constructor_declaration',
  'func_literal', 'program', 'module', 'source_file', 'compilation_unit',
]);

/** Nodes that bind a name to a value, and the fields that hold each side. */
const BINDING_NODES: Record<string, { name: string; value: string }> = {
  assignment: { name: 'left', value: 'right' }, // Python
  assignment_expression: { name: 'left', value: 'right' }, // JS/TS/Java
  variable_declarator: { name: 'name', value: 'value' }, // JS/TS/Java
  short_var_declaration: { name: 'left', value: 'right' }, // Go
  assignment_statement: { name: 'left', value: 'right' }, // Go
};

/** A literal with no spliced-in parts: a genuinely fixed value. */
function isPlainLiteral(node: Node | null, language: LanguageId): boolean {
  if (!node) return false;
  if (node.type === 'number' || node.type === 'integer' || node.type === 'float') return true;
  if (!STRING_LITERAL_TYPES[language].includes(node.type)) return false;
  return !containsType(node, INTERPOLATION_TYPES, 4);
}

function enclosingScopes(node: Node): Node[] {
  const scopes: Node[] = [];
  let current: Node | null = node.parent;
  while (current) {
    if (SCOPE_NODES.has(current.type)) scopes.push(current);
    current = current.parent;
  }
  return scopes;
}

/** Names bound by the parameter list of a function. Never constant. */
function parameterNames(scope: Node): Set<string> {
  const names = new Set<string>();
  const params = scope.childForFieldName('parameters');
  if (!params) return names;
  const walk = (n: Node | null): void => {
    if (!n) return;
    if (n.type === 'identifier') names.add(n.text ?? '');
    for (const child of n.namedChildren) walk(child ?? null);
  };
  walk(params);
  return names;
}

export function partsAreProvablyConstant(
  node: Node,
  dynamicParts: readonly string[],
  language: LanguageId,
): boolean {
  if (dynamicParts.length === 0) return false;

  const scopes = enclosingScopes(node);
  if (scopes.length === 0) return false;

  for (const raw of dynamicParts) {
    const part = raw.trim();
    // Only a bare name can be resolved this cheaply. Anything with a call, an
    // index or an attribute access is left alone.
    if (!/^[A-Za-z_$][\w$]*$/.test(part)) return false;

    let bindings = 0;
    let allLiteral = true;

    for (const scope of scopes) {
      if (parameterNames(scope).has(part)) return false; // a parameter is input
      const walk = (n: Node | null): void => {
        if (!n) return;
        // Do NOT descend into a nested scope. Searching the module body walked
        // straight into sibling functions, so an unrelated `t = request.args...`
        // three functions away made a genuinely constant `t` here look tainted.
        // The check still worked in a one-function test file and silently did
        // nothing in any real one - the direction of error was safe, but the fix
        // was useless the moment a common name like `query` appeared twice.
        if (n !== scope && SCOPE_NODES.has(n.type)) return;
        const fields = BINDING_NODES[n.type];
        if (fields) {
          const target = n.childForFieldName(fields.name);
          if ((target?.text ?? '').trim() === part) {
            bindings++;
            if (!isPlainLiteral(n.childForFieldName(fields.value), language)) allLiteral = false;
          }
        }
        for (const child of n.namedChildren) walk(child ?? null);
      };
      walk(scope);
    }

    // No binding found means we cannot see where it comes from - so we do not
    // get to call it constant.
    if (bindings === 0 || !allLiteral) return false;
  }
  return true;
}
