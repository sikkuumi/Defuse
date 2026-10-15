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
import { SWITCH_NODES, createFolder, type Folder } from '../../taint/fold.js';
import type { StaticMethodLookup } from '../contract.js';
import { declaredImmutable, enclosingMethod, resolveContainerRead } from '../../taint/local-map.js';
import {
  boundElsewhere,
  enclosingClassLikes,
  hasModifier,
  isClassLike,
  supertypesOf,
  usedOnlyAsQualifier,
} from '../../taint/java-scope.js';
import { declarationVisibility, hidesCodeFromParser } from '../../taint/visibility.js';

/** Node types that ARE a string literal, per language. */
const STRING_LITERAL_TYPES: Record<LanguageId, readonly string[]> = {
  javascript: ['string', 'template_string'],
  typescript: ['string', 'template_string'],
  python: ['string', 'concatenated_string'],
  java: ['string_literal', 'text_block'],
  go: ['interpreted_string_literal', 'raw_string_literal'],
  // C has one string node type and no interpolation at all, which is why every
  // dangerous C string is BUILT - by sprintf, strcat or std::string's operator+
  // - rather than interpolated in place. `concatenated_string` is adjacent
  // literals ("a" "b"), which C joins at compile time.
  c: ['string_literal', 'concatenated_string', 'char_literal'],
  cpp: ['string_literal', 'concatenated_string', 'char_literal', 'raw_string_literal'],
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
  // In C a "string expression" is nearly always a CALL - sprintf or strcat -
  // rather than an operator, because char arrays do not concatenate with `+`.
  c: ['string_literal', 'concatenated_string', 'binary_expression', 'call_expression'],
  // C++ gets the operator back via std::string, so binary_expression matters
  // here in a way it does not in C.
  cpp: [
    'string_literal',
    'concatenated_string',
    'raw_string_literal',
    'binary_expression',
    'call_expression',
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
      current.type === 'method_invocation' ||
      /*
       * PHP'S CALL NODES WERE MISSING, AND THAT COST 2,547 FINDINGS.
       *
       * Without these three types the walker fell through to "recurse into
       * every child" and descended INSIDE the call, so
       *
       *     echo esc_html( $user->user_login );
       *
       * was described as "interpolation splicing in `$user`". The escaper was
       * walked straight past and its argument reported as if it had been
       * concatenated in raw - which is both a wrong description and the reason
       * every WordPress escaping call looked like an unescaped one.
       *
       * A call is opaque: its RESULT is what gets spliced, and the arguments
       * are not that result. Naming the node types makes PHP behave like the
       * other five languages, which had them all along.
       */
      current.type === 'function_call_expression' ||
      current.type === 'member_call_expression' ||
      current.type === 'scoped_call_expression'
    ) {
      const nameNode =
        current.childForFieldName('name') ??
        current.childForFieldName('function') ??
        current.childForFieldName('constructor');
      const nameText = nameNode?.text ?? '';
      const lastSegment = nameText.split(/[.:]/).pop() ?? nameText;
      if (FORMAT_FUNCTIONS.has(lastSegment)) {
        sawFormatCall = true;
        /*
         * SKIP THE FUNCTION'S OWN NAME.
         *
         * `fmt.Sprintf` is a selector_expression, so recursing into every child
         * walked into the callee and recorded it as a spliced-in value. Every
         * format-call finding therefore opened with "It splices in
         * `fmt.Sprintf`, ..." - a sentence about the mechanism presented as a
         * sentence about the data, and simply untrue.
         *
         * It also broke a real proof: a Go escape hatch whose arguments were
         * ALL escaped still had `fmt.Sprintf` sitting in its parts list, so
         * "is every part escaped?" answered no about the function's own name.
         */
        // Compared by POSITION, not identity: web-tree-sitter hands back a new
        // wrapper object on every access, so `child !== nameNode` is always true.
        for (const child of current.namedChildren) {
          if (!child) continue;
          if (nameNode && child.startIndex === nameNode.startIndex && child.endIndex === nameNode.endIndex) {
            continue;
          }
          visit(child, depth + 1);
        }
        /*
         * BUT NOT THE THING IT IS CALLED ON. In JavaScript and Python the
         * callee is `dir.concat` or `template.format` as one node, so skipping
         * "the function's name" skipped `dir` and `template` with it - and they
         * are the very strings being built on (tests/probes/s09b, p01). Their
         * receiver is visited like any other part. Go's receiver here is a
         * package (`fmt`), and Java's call keeps its receiver in a field of its
         * own, which the loop above already visited.
         */
        if (nameNode && (nameNode.type === 'member_expression' || nameNode.type === 'attribute')) {
          const receiver = nameNode.childForFieldName('object');
          if (receiver) visit(receiver, depth + 1);
        }
        return;
      }
      sawOpaqueRef = true;
      dynamicParts.push((current.text ?? '').replace(/\s+/g, ' ').trim().slice(0, 60));
      return;
    }

    /*
     * VALUES THAT ARE NOT WHAT THEY SPELL. `(yield prompt)` is whatever the
     * caller sends back in, not `prompt` (tests/probes/s08). And `"ls " + obj`
     * in Java or JavaScript calls obj's toString(), which can return anything:
     * `new Arg(name)` is not `name` (j08), and `this` is not nothing (j14).
     * Each is one opaque part - never descended into.
     */
    if (
      current.type === 'yield_expression' ||
      current.type === 'yield' ||
      ((language === 'java' || language === 'javascript' || language === 'typescript') && current.type === 'this') ||
      (language === 'java' && current.type === 'object_creation_expression') ||
      ((language === 'javascript' || language === 'typescript') && current.type === 'new_expression')
    ) {
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
  /^\s*(?:where|from|order\s+by|group\s+by|having|limit|offset)\b/i,
  /*
   * VALUES AND AND ARE ALSO ENGLISH, so these two need the rest of the clause.
   *
   * An f-string's literal parts ARE fragments in the sense above - the text
   * between two interpolations is exactly a string appended to something else -
   * which is why the fragment rule reads them. Scanning pandas turned up four
   * assertion messages that way:
   *
   *     f"{obj} values are different ({pct} %)"     -> " values are different ("
   *     f"{a} and {b} were approximately equal"     -> " and "
   *
   * Both open with a clause keyword and neither continues into anything a
   * database could parse. SQL's VALUES is always followed by a parenthesis, and
   * a WHERE clause continued by AND or OR always reaches a comparison. Asking
   * for the second half of the clause keeps ` AND id = ` and ` VALUES (` - the
   * shapes the rule was written for - and drops the English.
   */
  /^\s*values\s*\(/i,
  /^\s*(?:and|or)\b[\s\S]{0,80}?(?:[=<>]|\b(?:like|ilike|in|is|between)\b)/i,
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
  /*
   * THE VALUE NAMES THE KIND OF CREDENTIAL IT IS STANDING IN FOR.
   *
   *     accessToken:  'exact-token'      'wrong-token'   'notion-token'
   *     clientSecret: 'notion-client-secret'
   *     apiKey:       'new-api-key'      connectionToken: 'test-token'
   *
   * Ninety-six of the 191 hardcoded-secret findings on a VS Code scan were this
   * shape, all from test files. A real credential does not contain the word
   * "secret" - the whole point of one is that it carries no information about
   * itself. A lowercase hyphenated phrase with `token`, `secret` or `key` as one
   * of its words is a label a person wrote so a failing assertion would be
   * readable.
   *
   * DELIBERATELY NARROW. An earlier attempt rejected short lowercase words
   * outright and had to be reverted: it took `password = 'configpass'` and
   * `SECRET_KEY = 'config'` with it, and those are weak credentials but they
   * are credentials. Neither has a separator or names itself, so neither
   * matches this. A passphrase like `correct-horse-battery-staple` does not
   * match either - it has the separators but names nothing.
   */
  /^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*[-_](token|secret|key|password|passwd|pwd|auth|credential|creds?|apikey|pat|jwt|salt|nonce|otp)$/i,
  /^(token|secret|key|password|passwd|pwd|auth|credential|creds?|apikey|pat|jwt|salt|nonce|otp)[-_][a-z0-9]+(?:[-_][a-z0-9]+)*$/i,
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

/**
 * Is this value STRUCTURALLY incapable of being a credential, whatever the
 * variable holding it is called?
 *
 * The name-based signal ("the variable is called `token`") never asked this,
 * and VS Code's editor package showed why: 151 of its 163 high-severity secret
 * findings were Monaco's syntax-highlighting tokens.
 *
 *     token: 'delimiter.curly'
 *     token: 'variable.predefined'
 *     token: 'comment'
 *
 * The variable really is called `token`. The value is a theme scope name. No
 * amount of suspicion about the NAME should survive looking at the VALUE.
 *
 * Two shapes, both decidable:
 *   - a dotted namespace (`delimiter.curly`, `com.example.thing`) - no key
 *     format contains dots, except a JWT, which starts `eyJ`;
 *   - a single lowercase dictionary-shaped word (`comment`, `invalid`) - real
 *     credentials mix character classes, because they are generated.
 */
export function isStructuralIdentifier(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return false;
  // The trailing dot is not a typo. A dotted name used as a STORAGE PREFIX is
  // written with the separator still attached, because the caller appends to it:
  //     SECRET_KEY_PREFIX = 'chat.lm.secret.'
  //     STORAGE_PREFIX    = 'chat.modelFeedbackSurvey.'
  // Both were reported as credentials on a VS Code scan, the first at HIGH
  // because its name contains SECRET and KEY. It is a namespace, and the value
  // in it is whatever gets appended - which is not in the file.
  if (/^[\w$-]+(?:\.[\w$-]+)+\.?$/.test(trimmed) && !/^eyJ/.test(trimmed)) return true;
  /*
   * A value carrying a URI SCHEME is an address or a standard identifier, not
   * a key. VS Code's OAuth constants are the clean example:
   *
   *     TOKEN_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token'
   *     token_endpoint = 'http://localhost:8080/token'
   *
   * Every one of those variable names screams credential, and every value is
   * published in an RFC. The name cannot be trusted over the shape.
   */
  if (/^(urn|https?|ftp|file|ws{1,2}|mailto|data|vscode[\w-]*):/i.test(trimmed)) return true;
  /*
   * A COLON-NAMESPACED PERMISSION IS A SCOPE, NOT A CREDENTIAL.
   *
   *     AccessTokenScopeReadAdmin AccessTokenScope = "read:admin"
   *     AccessTokenScopeWriteRepoHook              = "write:repo_hook"
   *
   * 106 of gitea's 359 findings were high-severity "hardcoded secret" and this
   * block is most of them. The constant NAME contains "Token", which is exactly
   * what the name signal is for - but the value is an OAuth scope printed in
   * gitea's own public API documentation.
   *
   * LETTERS ONLY, deliberately. `admin:password123` keeps its digits and still
   * reports, and so does anything with mixed case; generated credentials
   * essentially always carry one or the other. What is left - a lowercase
   * colon-namespaced phrase - is how every permission system in the world
   * spells a scope. A bare `user:pass` is lost to this, which is a placeholder
   * anyway, and a real one inside a URL is caught earlier by the
   * connection-string format.
   */
  if (/^[a-z]+(?:[_-][a-z]+)*(?::[a-z]+(?:[_-][a-z]+)*)+$/.test(trimmed)) return true;
  /*
   * A Subresource Integrity hash is published in the HTML that loads the
   * script. It is the opposite of a secret - its whole job is to be public so
   * a browser can check the file was not tampered with.
   *
   *     webWorkerExtensionHostIframeScriptSHA = 'sha256-daEgfo2VIXpx2Np71Kq...'
   */
  if (/^sha(256|384|512)-/.test(trimmed)) return true;
  /*
   * A SCREAMING_SNAKE value is a constant or an environment VARIABLE NAME, not
   * its value. VS Code names the variable after what it holds and gets caught
   * by both halves:
   *
   *     agentHostBridgeConnectionTokenEnvironmentVariable =
   *       'VSCODE_AGENT_HOST_BRIDGE_CONNECTION_TOKEN'
   */
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(trimmed)) return true;
  /*
   * A single lowercase word is NOT on this list, and the first version of it
   * was. `token: 'comment'` and `token: 'invalid'` in Monaco are exactly that
   * shape - but so are
   *
   *     password: 'configpass'
   *     password: 'exfil'
   *     SECRET_KEY = 'config'
   *
   * and rejecting the shape took the library corpus from 48 findings to 32.
   * Weak human-chosen passwords ARE lowercase words; that is what makes them
   * weak. Trading sixteen real hardcoded credentials for a dozen theme scope
   * names is the wrong direction, so the dotted check stands alone and the
   * remaining Monaco tokens are accepted noise.
   */
  return false;
}

/**
 * Does this spliced-in expression produce nothing but SQL PLACEHOLDERS?
 *
 * VS Code builds a bulk insert the correct way:
 *
 *     `INSERT INTO ItemTable VALUES ${new Array(n).fill('(?,?)').join(',')} ...`
 *     stmt.run(keysValuesChunk)
 *
 * The interpolation expands to `(?,?),(?,?),(?,?)`. Not one byte of data is in
 * that string - the values go to the driver separately, which is exactly what
 * parameterisation means. And the rule reported it as SQL injection.
 *
 * That is the worst mistake an injection rule can make. Flagging the CORRECT
 * form teaches people that doing it properly does not help, and this is the
 * third time today the same failure has turned up in a different rule -
 * unserialize with allowed_classes, yaml with a SafeLoader, and now this.
 *
 * The test is narrow on purpose. Every string literal inside the expression
 * must be placeholder punctuation, AND at least one must contain an actual
 * placeholder marker (`?`, `$1`, `%s`). That second half is what stops
 * `rows.map(r => `'${r}'`).join(',')` - which builds real quoted DATA and is a
 * genuine injection - from slipping through on its commas.
 */
export function expandsOnlyPlaceholders(expressionText: string): boolean {
  const literals = [...expressionText.matchAll(/(['"`])((?:\\.|(?!\1)[^\\])*)\1/g)].map(
    (m) => m[2] ?? '',
  );
  if (literals.length === 0) return false;
  const hasMarker = literals.some((lit) => /\?|\$\d|%s/.test(lit));
  if (!hasMarker) return false;
  return literals.every((lit) => /^[\s?,()$%sd\d]*$/.test(lit));
}

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
  /*
   * STRUCTURAL PUNCTUATION IS NOT IN ANY CREDENTIAL ALPHABET.
   *
   * Every real key format draws from a narrow set of characters: base64 uses
   * A-Za-z0-9+/=, hex uses 0-9a-f, and vendor keys (AKIA..., ghp_..., sk_live_)
   * use A-Za-z0-9_-. None of them contains a brace, a bracket, a quote, a
   * colon or a semicolon.
   *
   * Auditing this tool's findings across five real libraries found NINE
   * entropy-only false positives and every one was killed by this single line:
   *
   *     json = "{field1:'abc',field2:'def'}"        a JSON test fixture
   *     systemProperty = "gson.allowCapturing..."   a property name
   *     dataURI = "data:;charset=UTF-8,hello"       a data URI
   *
   * Entropy alone cannot tell a key from a small structured document - both
   * score above 4 bits per character. Shape can, and shape is not a guess.
   */
  if (/[{}[\]<>(),;:'"`|!?*&^%$#~]/.test(value)) return false;
  if (/^[a-z.\-_]+$/.test(value)) return false; // lowercase words / kebab / dotted names
  if (/^[A-Z.\-_]+$/.test(value)) return false; // SCREAMING_CONSTANT names
  if (/^\d+$/.test(value)) return false; // pure numbers, timestamps, ids
  /*
   * NAMESPACED IDENTIFIERS ARE NOT KEYS.
   *
   *     workbench.action.focusCommentsPanel
   *     workbench.contrib.viewsExtensionHandler
   *     editor.action.formatDocument
   *
   * Scanning VS Code produced 1,369 hardcoded-secret findings and 1,246 were
   * entropy-only hits on strings exactly like these - command ids, context
   * keys, extension ids. They score above 4 bits per character because they mix
   * case and use many distinct letters, which is precisely what the entropy
   * heuristic was built to notice, and precisely why entropy alone is not
   * evidence of anything.
   *
   * A dotted name is the single most common long string in a large application,
   * and no credential format is shaped like one. The exception is a JWT, which
   * is also dot-separated - so a value that opens with the base64 of `{"` is
   * kept. That is the standard JWT header prefix and nothing else starts that
   * way by accident.
   */
  if (/^[\w$-]+(?:\.[\w$-]+)+$/.test(value) && !/^eyJ/.test(value)) return false;
  // The alphabet itself, and any run of consecutive letters. `letterBytes =
  // "abcdefghijklmnopqrstuvwxyzABCDEF..."` in gin scores 4.7 bits/char and is
  // the least random string it is possible to write.
  if (/abcdefghij/i.test(value)) return false;
  /*
   * A CAMELCASE RUN OF PURE LETTERS IS AN IDENTIFIER, NOT A KEY.
   *
   *     enablePreviewFromQuickOpen        a settings key
   *     ChatToolsEligibleForAutoApproval  an experiment name
   *     didNotEnableEditSessionsWhenPrompted   a telemetry outcome
   *     historyItemChangeViewModel        a view-model type tag
   *
   * The dotted-name rule above catches `workbench.action.focus...`; these are
   * the same thing with the dots removed, and they were the next 35 findings on
   * a VS Code scan once the dotted ones were gone. They score above 4 bits per
   * character for the same reason - many distinct letters, mixed case - which
   * is again a fact about English identifiers rather than about randomness.
   *
   * The discriminator is what is ABSENT. Every generated credential draws on
   * digits or punctuation somewhere: base64 has digits and +/=, hex is digits
   * and a-f, vendor keys carry a prefix and an underscore. Twenty-nine letters
   * and nothing else is a name a person typed.
   *
   * This gate is on the ENTROPY path only, which matters: `password =
   * 'MySecretPassword'` has this exact shape and is a genuine bad credential,
   * but it is caught by the variable NAME (Signal 2), which never consults this
   * function. Weak alphabetic passwords therefore still report.
   */
  if (value.length >= 12 && /^[A-Za-z]+$/.test(value)) {
    const humps = value.match(/[a-z][A-Z]/g)?.length ?? 0;
    if (humps >= 2) return false;
  }

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
  return TEST_DIRECTORY.test(filePath) || TEST_FILENAME.test(filePath);
}

/*
 * TEST-PATH CONVENTIONS ARE PER-ECOSYSTEM, and this list was built from the
 * repositories I had happened to be shown.
 *
 * Scanning cal.com - 3,941 TypeScript files - produced 196 findings, 138 of
 * them hardcoded-secret. The ones still ranked HIGH were led by
 *
 *     apps/web/playwright/payment-apps.e2e.ts   access_token: "sk_test_randomString"
 *     packages/testing/src/lib/bookingScenario/bookingScenario.ts
 *
 * Both are unambiguously test code, and this function said neither was. The
 * reasons were boring and specific: `e2e` was recognised only as a whole
 * DIRECTORY segment, never as the `.e2e.ts` filename suffix that Playwright
 * actually uses; and `tests?` matches `test` and `tests` but not `testing`.
 *
 * That is the third time this exact class has cost real precision. Scanning
 * elasticsearch proved SOURCES are per-framework rather than per-language;
 * scanning Jenkins proved ESCAPERS are too. The lesson generalises past both:
 * ANY list of conventions in this engine is a list of the conventions I have
 * been shown, and it looks complete right up until a codebase with different
 * habits arrives.
 *
 * WHY THIS IS TWO NARROW PATTERNS AND NOT ONE WIDE ONE. Downranking is a
 * silencing mechanism, so the failure mode is a real credential in application
 * source ranked as test noise. `latest.ts`, `contest/`, `testimonials.tsx`,
 * `protester.js` and `attestation/` all contain the letters "test". Every one
 * of them is asserted as NOT a test path in the suite, which is what stops a
 * future widening from quietly eating them.
 */

/** A whole path SEGMENT that names a test area. Anchored both sides. */
const TEST_DIRECTORY =
  /(^|[/\\])(tests?|testing|spec|specs|__tests__|__mocks__|fixtures?|examples?|e2e|benchmarks?|mocks?|playwright|cypress|testdata)([/\\]|$)/i;

/**
 * A FILENAME that names itself a test. Kept separate from the directory rule
 * because these are suffixes, not segments - `login.e2e.ts` has no `e2e`
 * segment anywhere in it, which is exactly what cal.com exposed.
 */
const TEST_FILENAME =
  /\.(test|spec|e2e|cy|e2e-spec|int-spec)\.[a-z]+$|[._-]test\.[a-z]+$|Tests?\.(java|cs|kt|scala)$/i;


/**
 * Is this value just a restatement of the NAME it is stored under?
 *
 *     PRIVATE_KEY_KEY   = "privateKey"          Keycloak, 4,000 Java files
 *     KEYSTORE_PASSWORD_KEY = "keystorePassword"
 *     MANAGE_OAUTH      = "manage_oauth"        Mattermost, TypeScript
 *     TOKEN_CREATING    = "creating"
 *     SECTION_TOKENS    = "tokens"
 *
 * These are the strings a program uses to LOOK UP a secret in a config map, and
 * they are dense in exactly the codebases that handle credentials for a living
 * - which is why an identity server produced 152 findings and most were this.
 *
 * The test is a subset check on words, which is what makes it safe: a real
 * credential shares no vocabulary with its own variable name. `password =
 * "Tr0ub4dor3xK"`, `SECRET_KEY = "config"` and `password = "configpass"` all
 * survive it, and all three are asserted elsewhere in the suite.
 *
 * Requires at least one word on each side, so an empty or punctuation-only
 * value cannot vacuously qualify.
 */
export function echoesItsOwnName(name: string, value: string): boolean {
  const words = (text: string): string[] =>
    text
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .split(/[^A-Za-z0-9]+/)
      .map((w) => w.toLowerCase())
      .filter((w) => w.length > 1);
  const nameWords = new Set(words(name));
  const valueWords = words(value);
  if (nameWords.size === 0 || valueWords.length === 0) return false;
  return valueWords.every((w) => nameWords.has(w));
}

/**
 * Does this value read as an English SENTENCE rather than as a credential?
 *
 *     encryption_key_missing: "CALENDSO_ENCRYPTION_KEY is not set"
 *
 * From cal.com's OAuthService. The NAME matches the credential pattern - it
 * contains `key` - and a name-based guess is allowed to be wrong. What it is
 * not allowed to do is ignore a value that could not possibly be a credential.
 *
 * THE TRAP THIS IS SHAPED AROUND: passphrases contain spaces and are real
 * secrets. `password = "correct horse battery staple"` must still report.
 *
 * THE FIRST VERSION OF THIS FUNCTION WAS NOT SAFE, and the corpus caught it -
 * for the third time in this project's life, after the lowercase-word rejection
 * that dropped the corpus 48 to 32 and the mathjs.eval regression that showed
 * up only as dvna's flow count falling 3 to 2.
 *
 * Requiring "several words plus an English function word" looked airtight
 * against a DICEWARE passphrase, whose wordlist is concrete nouns and verbs.
 * It is not airtight against a HUMAN-CHOSEN one. Express ships
 *
 *     secret: 'manny is cool'        examples/cookie-sessions/index.js
 *
 * a genuine session secret, silenced by the word `is`. One good suppression
 * (dvna's `'A2: Broken Authentication'` label) and one real miss.
 *
 * So the value's shape is no longer the whole test. The NAME has to say the
 * slot holds a message - `encryption_key_missing`, `api_key_invalid` - which is
 * what cal.com's error table actually looks like and what `secret` never does.
 * Both halves are asserted: the express string is now a fixture that must fire.
 */
const PROSE_WORDS = new Set([
  'is', 'are', 'was', 'were', 'be', 'been', 'not', 'no', 'the', 'a', 'an',
  'this', 'that', 'these', 'those', 'your', 'you', 'must', 'should',
  'cannot', 'could', 'would', 'please', 'try', 'again', 'invalid', 'missing',
  'expired', 'required', 'failed', 'error', 'unable', 'least', 'provided',
  'for', 'to', 'of', 'in', 'at', 'with', 'and', 'or', 'but', 'if', 'set',
]);

export function looksLikeProse(name: string, value: string): boolean {
  // The NAME has to say this slot holds a message. Prose-ness alone is not
  // enough - see the express regression in the note above.
  if (!MESSAGE_NAME.test(name)) return false;
  const words = value.trim().split(/\s+/);
  if (words.length < 3) return false;
  const lowered = words.map((w) => w.replace(/[^A-Za-z]/g, '').toLowerCase());
  return lowered.some((w) => PROSE_WORDS.has(w));
}

/**
 * Names that describe a STATE or a MESSAGE rather than a stored credential.
 * `encryption_key_missing` is not a key; it is what you print when the key is
 * absent. The word that matters is the suffix.
 */
const MESSAGE_NAME =
  /(_|\b)(missing|invalid|expired|required|failed|error|errors|message|messages|msg|description|hint|warning|notice|reason|too_short|too_long|not_found|unauthorized|denied)$/i;

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
  /*
   * OpenAI's CURRENT key format, which the line above cannot match.
   *
   * The legacy shape was `sk-` followed by one unbroken run of alphanumerics.
   * Project and service-account keys put named segments in between -
   * `sk-proj-...`, `sk-svcacct-...` - and the hyphen ends the `[A-Za-z0-9]{20,}`
   * run, so a live project key scored only "high-entropy literal, possible
   * secret" at medium severity instead of being identified outright.
   *
   * Found by checking that a placeholder this rule had just started ignoring
   * (`apiKey: 'sk-secret-internal-key'`) had not taken a real format with it.
   * It had not - it had exposed one that was already missing. The named segment
   * is required precisely so that the placeholder stays ignored: "secret" is
   * not "proj".
   */
  { label: 'OpenAI project key', pattern: /\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b/ },
  { label: 'JSON Web Token', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  {
    label: 'private key block',
    /*
     * The delimiter has to be followed by KEY MATERIAL. Keycloak defines
     * `BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----"` as a constant so it
     * can assemble and parse PEM files; the string IS the delimiter and there
     * is no key in it. Requiring base64 after the header keeps every real
     * embedded key and drops the label on its own.
     */
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?[A-Za-z0-9+/]{40}/,
  },
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
  'generator_function_declaration', 'generator_function', 'class_static_block',
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
  // Java's `null` is a fixed value too - `String command = null;` before the
  // branches that set it is how BenchmarkJava's command helper begins.
  if (language === 'java' && node.type === 'null_literal') return true;
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
  const walk = (n: Node | null): void => {
    if (!n) return;
    if (n.type === 'identifier') names.add(n.text ?? '');
    for (const child of n.namedChildren) walk(child ?? null);
  };
  /*
   * Not only `parameters`: a JavaScript arrow with one bare parameter keeps it
   * in `parameter` (tests/probes/s07), and a Go method's receiver and named
   * results are input too (g02).
   */
  for (const field of ['parameters', 'parameter', 'receiver', 'result']) walk(scope.childForFieldName(field));
  return names;
}

/** Why a string built from pieces is still provably fixed - or null when it is not. */
export interface ConstantProof {
  /**
   * True when the proof needed control-flow reasoning - a branch that cannot
   * run, a condition decided at compile time, a ternary whose every arm is a
   * literal - rather than "every binding is a plain literal". Only reasoned
   * proofs leave a receipt, because only reasoning can be wrong.
   */
  readonly reasoned: boolean;
  /** One sentence per name, written so a reader can check it against the code. */
  readonly reason: string;
}

const TERNARY_NODES = new Set(['ternary_expression', 'conditional_expression']);
/*
 * Go binds a NEW variable in two places the write survey does not collect:
 * `switch t := v.(type)` and `case t := <-ch`. Inside them, `t` is not the
 * one declared outside (tests/probes/g03, g06).
 */
function goBindsOtherwise(root: Node, name: string): boolean {
  const word = new RegExp(`(^|[^\\w])${name}(?![\\w])`);
  for (const n of root.descendantsOfType(['type_switch_statement', 'receive_statement'])) {
    if (!n) continue;
    const bound = n.type === 'type_switch_statement' ? n.childForFieldName('alias') : n.childForFieldName('left');
    if (bound && word.test(bound.text ?? '')) return true;
  }
  return false;
}

function rootOf(n: Node): Node {
  let root = n;
  while (root.parent) root = root.parent;
  return root;
}

/** Nodes that declare a variable: Java and JavaScript declarators, Go's `var` and `:=`. */
const DECLARATION_NODES = new Set(['variable_declarator', 'var_spec', 'short_var_declaration']);

/** Languages whose `+` joins two strings, and the node that holds it. */
const CONCATENATING: ReadonlySet<LanguageId> = new Set(['java', 'javascript', 'typescript', 'python', 'go']);
const CONCAT_NODES = new Set(['binary_expression', 'binary_operator']);


/*
 * PROVABLY CONSTANT, NOW WITH THE FOLDER.
 *
 * This used to accept a name only if EVERY binding of it was a plain literal.
 * That is sound, and it missed the single most common false positive left in
 * BenchmarkJava - 65 of them:
 *
 *     String bar;
 *     int num = 86;
 *     if ((7 * 42) - num > 200) bar = "This_should_always_happen";
 *     else bar = param;
 *     String sql = "SELECT ... PASSWORD='" + bar + "'";
 *
 * Three bindings. `String bar;` binds no value at all. `bar = param` sits in an
 * arm that cannot run, because 294 - 86 is 208. The only write that can reach
 * the string is a literal - and the rule could not see any of that, because the
 * only code that knew how to decide a condition was sealed inside the tracer.
 * src/taint/fold.ts is that same code, moved out and shared.
 *
 * What changed, exactly:
 *   - a declaration that binds no value is not a write, and is skipped;
 *   - a write inside an arm the folder proves cannot run is set aside;
 *   - a ternary contributes the side that runs when its condition is decided,
 *     and BOTH sides when it is not - so `flag ? "asc" : "desc"` is constant;
 *   - there must still be at least one live write, and every live value must
 *     be a plain literal. A parameter is still disqualifying, full stop.
 *
 * Every doubt resolves toward reporting. An undecidable condition keeps both
 * arms live; a value the folder cannot see into is not a literal; a name with
 * no live write is not provable. ConstantProofFence.java is the list of shapes
 * that look withdrawable and must not be withdrawn.
 */
export interface ConstantProofOptions {
  /** RuleContext.staticMethod. Absent: no helper in another file is read. */
  readonly staticMethod?: StaticMethodLookup | undefined;
  /** RuleContext.javaTypeInScan. Absent: every supertype is assumed to be in the scan. */
  readonly javaTypeInScan?: ((simpleName: string) => boolean) | undefined;
}

export function constantProof(
  node: Node,
  dynamicParts: readonly string[],
  language: LanguageId,
  options: ConstantProofOptions = {},
): ConstantProof | null {
  if (dynamicParts.length === 0) return null;
  // A comment the compiler ends where the parser does not - see
  // taint/visibility.ts. Such a file is one this proof cannot read.
  if (hidesCodeFromParser(node, language)) return null;

  /*
   * A fresh folder per question AND PER FILE: a folder's caches are keyed by
   * source span, and a span is only meaningful inside one tree. Once a helper
   * in another file can be read, one folder for both would answer a question
   * about bytes 400-980 of Utils.java with what it learned about bytes
   * 400-980 of the caller.
   */
  const folders = new Map<unknown, Folder>();
  const folderOf = (n: Node): Folder => {
    let folder = folders.get(n.tree);
    if (!folder) {
      folder = createFolder(language);
      folders.set(n.tree, folder);
    }
    return folder;
  };
  const treeIds = new Map<unknown, number>();
  /** A key for a node that is unique across files, not just within one. */
  const spanKey = (n: Node): string => {
    let id = treeIds.get(n.tree);
    if (id === undefined) {
      id = treeIds.size;
      treeIds.set(n.tree, id);
    }
    return `${id}:${n.startIndex}:${n.endIndex}`;
  };

  const lineOf = (n: Node): number => n.startPosition.row + 1;
  const contains = (outer: Node, inner: Node): boolean =>
    inner.startIndex >= outer.startIndex && inner.endIndex <= outer.endIndex;
  const sameSpan = (a: Node, b: Node): boolean =>
    a.startIndex === b.startIndex && a.endIndex === b.endIndex;

  /*
   * The arm of an enclosing `if`, or the case of an enclosing switch, that
   * cannot run - if `n` sits in one. Returned with the sentence the receipt
   * uses, so the reader is told which decision made the write irrelevant.
   */
  const deadArmHolding = (n: Node, scope: Node, body: Node): { at: Node; why: string } | null => {
    let current: Node | null = n.parent;
    while (current && contains(scope, current)) {
      if (current.type === 'if_statement') {
        const dead = folderOf(current).deadBranchOf(current, body);
        if (dead && contains(dead, n)) {
          return { at: current, why: `is in a branch that cannot run (line ${lineOf(current)})` };
        }
      }
      if (SWITCH_NODES.has(current.type)) {
        const decision = folderOf(current).switchDecision(current, body);
        if (decision?.dead.some((group) => contains(group, n))) {
          return { at: current, why: `is in a case that cannot run: ${decision.note}` };
        }
      }
      if (sameSpan(current, scope)) break;
      current = current.parent;
    }
    return null;
  };

  /** Every value an expression can take, as nodes - or null if that cannot be bounded. */
  const liveValues = (value: Node, body: Node, depth: number): { nodes: Node[]; note: string | null } | null => {
    let v: Node = value;
    /*
     * Go wraps EVERY assigned value in an expression_list, even a single one,
     * because `a, b := 1, 2` is legal. So `q := "x"` never looked like a literal
     * to this check - not after the folder arrived, and not before it either:
     * Go had no constant proof at all until constant-branch.go asked for one.
     * A one-element list is unwrapped like parentheses; a real multi-value
     * assignment is left alone, and reads as "not a literal", which is safe.
     */
    while (
      (v.type === 'parenthesized_expression' || v.type === 'expression_list') &&
      v.namedChildren.length === 1
    ) {
      v = v.namedChildren[0] ?? v;
    }
    if (!TERNARY_NODES.has(v.type) || depth > 4) return { nodes: [v], note: null };
    const parts = folderOf(v).ternaryParts(v);
    const truth = folderOf(v).conditionTruth(parts.condition, body);
    if (truth !== undefined) {
      const live = truth ? parts.consequence : parts.alternative;
      if (!live) return null;
      const inner = liveValues(live, body, depth + 1);
      return inner && {
        nodes: inner.nodes,
        note: `the condition on line ${lineOf(v)} is fixed at compile time, and the side that runs is a literal`,
      };
    }
    if (!parts.consequence || !parts.alternative) return null;
    const a = liveValues(parts.consequence, body, depth + 1);
    const b = liveValues(parts.alternative, body, depth + 1);
    if (!a || !b) return null;
    return { nodes: [...a.nodes, ...b.nodes], note: `both sides of the condition on line ${lineOf(v)} are literals` };
  };

  /*
   * ONE LEVEL INTO A HELPER. See HelperConstantProof.java and
   * StaticHelperCommand.java for the fences.
   *
   * 46 of BenchmarkJava's surviving SQL false positives had their decoy inside
   * a helper: `String bar = new Test().doSomething(request, param)`. The tracer
   * follows that call; this proof stopped at it. It follows three shapes, each
   * chosen because the method that runs is not in doubt:
   *
   *   `new X(...).m(...)`, X declared in this file, X declaring ONE method m;
   *   `m(...)` in this class, when m is private, static or final;
   *   `Utils.m(...)` or `a.b.Utils.m(...)` - a static method, which may live
   *   in ANOTHER file; taint/project.ts, staticMethod(), says when that file
   *   and that method are the only candidates.
   *
   * Every `return` in m must be provable by the same rules as everything else
   * here, with one addition: a parameter of m is as fixed as the argument this
   * call passes for it - when that argument is provably fixed itself, the
   * counts line up with no varargs, and m never writes to the parameter. That
   * is what makes `getOSCommandString("echo")` fixed: it wraps literals around
   * `append`, and `append` is "echo".
   *
   * Java only. A receiver that is a variable could be any subclass; an
   * overload depends on argument types this proof does not read; a helper
   * returning another helper is a second level, and there is no second level.
   * Other languages' helpers are not followed yet, and the SQL rule's
   * limitations say so rather than letting "constant" imply they are.
   */
  const bindings = new Map<string, Map<string, () => string[] | null>>();

  /*
   * THE `new` A LOCAL CERTAINLY HOLDS, if it holds one.
   *
   *     SeparateClassRequest scr = new SeparateClassRequest(request);
   *     String param = scr.getTheValue("BenchmarkTest00930");
   *
   * A variable could hold any subclass - unless it is a local declared once,
   * in view of the call, with `= new X(...)`, and never written again anywhere
   * in the method (closures included). Then it holds that X and nothing else.
   * Not a parameter, not a field, not a name a lambda or a pattern also binds,
   * and not read from inside a class that could inherit a field of that name
   * (LocalObjectHelper.java has each).
   *
   * And the object must never leave the method's hands: every use of the name
   * is as the receiver of a call, `h.m(...)`. Passed as an argument, it can be
   * changed by whatever receives it - reflection rewrites a private field
   * (tests/probes/r3-b07) - and `h.f = ...` writes a field directly.
   */
  const heldCreation = (name: string, call: Node): Node | null => {
    if (language !== 'java' || !name) return null;
    const fn = enclosingScopes(call)[0];
    if (!fn || parameterNames(fn).has(name) || boundElsewhere(rootOf(call), name)) return null;
    const declarators = fn
      .descendantsOfType('variable_declarator')
      .filter((d): d is Node => !!d && d.childForFieldName('name')?.text === name);
    const declarator = declarators.length === 1 ? declarators[0] : undefined;
    const value = declarator?.childForFieldName('value');
    if (!declarator || value?.type !== 'object_creation_expression') return null;
    if (declarator.parent?.type !== 'local_variable_declaration') return null;
    const visible = declarationVisibility(declarator, language);
    if (!visible || !contains(visible.region, call) || call.startIndex < visible.from) return null;
    const f = folderOf(fn);
    if (f.writtenOtherwise(name, fn) || f.plainWriteCount(name, fn) !== 1) return null;
    if (enclosingClassLikes(call).some((c) => contains(visible.region, c) && supertypesOf(c).length > 0)) return null;
    const nameNode = declarator.childForFieldName('name');
    const onlyReceiver = fn.descendantsOfType('identifier').every((id) => {
      if (!id || id.text !== name || (nameNode && sameSpan(id, nameNode))) return true;
      const p = id.parent;
      return p?.type === 'method_invocation' && !!p.childForFieldName('object') && sameSpan(p.childForFieldName('object')!, id);
    });
    if (!onlyReceiver) return null;
    return value;
  };

  const helperReturnsConstant = (call: Node, depth: number): string[] | null => {
    if (depth > 0 || language !== 'java' || call.type !== 'method_invocation') return null;
    const receiver = call.childForFieldName('object');
    const methodName = call.childForFieldName('name')?.text ?? '';
    if (!methodName) return null;

    const methodsNamed = (klass: Node): Node[] =>
      (klass.childForFieldName('body')?.namedChildren ?? []).filter(
        (m): m is Node => m !== null && m.type === 'method_declaration' && m.childForFieldName('name')?.text === methodName,
      );
    let root: Node = call;
    while (root.parent) root = root.parent;

    let method: Node | null = null;
    let typeName = '';
    let where = '';
    /** Could a supertype declared in the scan supply a member we did not look at? */
    const inherits = (classLike: Node): boolean =>
      supertypesOf(classLike).some((t) =>
        t.split('.').some((part) => (options.javaTypeInScan ? options.javaTypeInScan(part) : true)),
      );
    /*
     * `h.m(...)` where `h` is a local that certainly holds a `new X(...)` - see
     * heldCreation below. The object is exactly an X, so it is read like
     * `new X(...).m(...)`.
     */
    const created =
      receiver?.type === 'object_creation_expression'
        ? receiver
        : receiver?.type === 'identifier'
          ? heldCreation(receiver.text ?? '', call)
          : null;
    if (created) {
      /*
       * `new X(...).m(...)`: the type is exact, so X's own m is the one that
       * runs - when X is the class in scope here. Not with a body attached
       * (`new X() { ... }` is an anonymous subclass that can override m, p25),
       * not when X is a class nested somewhere the call cannot see (p26), and
       * not when X inherits from anything - a superclass or an interface's
       * default method - since an inherited overload can be the one chosen
       * (p34, j03). X may live in another file, found the way a static
       * helper's class is (staticMethod), with an instance method allowed.
       */
      if (isClassLike(created)) return null;
      // `o.new X()` creates o's member class X - not the X this name finds
      // from here (tests/probes/r3-a06, r3-a08, r3-d01).
      if (created.child(0)?.type !== 'new') return null;
      typeName = (created.childForFieldName('type')?.text ?? '').replace(/\s+/g, '');
      if (!/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(typeName)) return null; // generic: not read
      // A class around the call can inherit a member class named X, and then
      // that is the X created here (tests/probes/j04).
      if (enclosingClassLikes(call).some(inherits)) return null;
      const declared: Node[] = [];
      const findTypes = (n: Node): void => {
        if (n.type !== 'object_creation_expression' && isClassLike(n) && n.childForFieldName('name')?.text === typeName) {
          declared.push(n);
        }
        for (const child of n.namedChildren) if (child) findTypes(child);
      };
      if (!typeName.includes('.')) findTypes(root);
      if (declared.length > 0) {
        const klass = declared.length === 1 ? declared[0] : undefined;
        if (!klass || klass.type !== 'class_declaration' || supertypesOf(klass).length > 0) return null;
        const owner = klass.parent?.parent ?? null;
        const inScope =
          klass.parent?.type === 'program' ||
          (klass.parent?.type === 'class_body' && !!owner && contains(owner, call) && isClassLike(owner));
        if (!inScope) return null;
        const candidates = methodsNamed(klass);
        if (candidates.length !== 1) return null;
        method = candidates[0]!;
      } else {
        const first = typeName.split('.')[0] ?? '';
        if (!options.staticMethod || !first || !usedOnlyAsQualifier(root, first)) return null;
        const supertypes = enclosingClassLikes(call).flatMap((c) => supertypesOf(c));
        const found = options.staticMethod(typeName, methodName, supertypes, true);
        if (!found || hidesCodeFromParser(found.method, 'java')) return null;
        method = found.method;
        where = ` in ${found.path}`;
      }
      typeName = typeName.split('.').pop() ?? typeName;
    } else if (!receiver) {
      /*
       * A bare call, `doSomething(request, param)`. It binds to this class's
       * method only if no subclass can replace it - so only when that method
       * is private, static or final, read from the modifier tokens (p29).
       * BenchmarkJava declares its helpers `private static`, and 27 of the
       * survivors were exactly this shape. The
       * class is the INNERMOST class-like around the call: inside an anonymous
       * class or an enum, `m()` means theirs (p27, p28), and those are not
       * read. A superclass declared in the scan can supply a more specific
       * overload (p30); one from outside it - BenchmarkJava's HttpServlet - is
       * not read, and the SQL rule's limitations say so.
       */
      const klass = enclosingClassLikes(call)[0];
      if (!klass || klass.type !== 'class_declaration' || inherits(klass)) return null;
      typeName = klass.childForFieldName('name')?.text ?? '';
      const candidates = methodsNamed(klass);
      if (candidates.length !== 1) return null;
      const candidate = candidates[0]!;
      if (!['private', 'static', 'final'].some((k) => hasModifier(candidate, k))) return null;
      method = candidate;
    } else if ((receiver.type === 'identifier' || receiver.type === 'field_access') && options.staticMethod) {
      /*
       * `Utils.m(...)`. In Java a variable named `Utils` - or `a` for
       * `a.b.Utils` - hides the class or package of that name, and so does a
       * type, a pattern variable, an enum constant, a lambda parameter... So
       * EVERY appearance of that name in this file must be as a qualifier,
       * like the one here (p10, p11, p12). Names that arrive without appearing
       * - static imports, inherited members - are checked by the lookup.
       */
      const dotted = (receiver.text ?? '').replace(/\s+/g, '');
      const first = dotted.split('.')[0] ?? '';
      if (!first || !usedOnlyAsQualifier(root, first)) return null;
      const supertypes = enclosingClassLikes(call).flatMap((c) => supertypesOf(c));
      const found = options.staticMethod(dotted, methodName, supertypes);
      if (!found || hidesCodeFromParser(found.method, 'java')) return null;
      method = found.method;
      typeName = dotted.split('.').pop() ?? dotted;
      where = ` in ${found.path}`;
    }
    if (!method) return null; // a receiver that is a variable: it could be any subclass
    /*
     * A method calling itself. Its parameters are bound to what this call
     * passes - and the arguments are the CALLER's parameters, the same names in
     * the same method, which would then read their own binding: `m(b, "x")`
     * inside m makes the caller's `b` look like "x" (tests/probes/r3-a07,
     * r3-z-scope-recursive-static). Not read.
     */
    if (spanKey(rootOf(method)) === spanKey(rootOf(call)) && contains(method, call)) return null;

    /* ---- the parameters, bound to what this call passes ---- */
    const formal = (method.childForFieldName('parameters')?.namedChildren ?? []).filter(
      (p): p is Node => p !== null && (p.type === 'formal_parameter' || p.type === 'spread_parameter'),
    );
    const args = (call.childForFieldName('arguments')?.namedChildren ?? []).filter(
      (a): a is Node => a !== null && a.type !== 'line_comment' && a.type !== 'block_comment',
    );
    // The count must match with no varargs, whatever is read: a call that
    // passes more or fewer arguments than this method takes is calling
    // another one (p02).
    if (formal.length !== args.length || formal.some((p) => p.type !== 'formal_parameter')) return null;
    const callerBody = enclosingScopes(call)[0];
    const bound = new Map<string, () => string[] | null>();
    const used: string[] = [];
    if (callerBody) {
      formal.forEach((p, i) => {
        const name = p.childForFieldName('name')?.text ?? '';
        const arg = args[i];
        if (!name || !arg) return;
        let memo: string[] | null | undefined;
        bound.set(name, () => {
          if (memo === undefined) {
            const why = valueIsConstant(arg, callerBody, depth);
            memo = why && [
              ...why,
              `\`${name}\` is \`${arg.text.replace(/\s+/g, ' ')}\`, passed on line ${lineOf(arg)}`,
            ];
            if (memo) used.push(name);
          }
          return memo;
        });
      });
    }

    const returns: Node[] = [];
    const findReturns = (n: Node): void => {
      if (n.type === 'return_statement') returns.push(n);
      // A return inside a nested class or lambda belongs to that, not to m.
      if (n.type === 'class_body' || n.type === 'lambda_expression') return;
      for (const child of n.namedChildren) if (child) findReturns(child);
    };
    const methodBody = method.childForFieldName('body');
    if (!methodBody) return null;
    findReturns(methodBody);
    if (returns.length === 0) return null;

    const key = spanKey(method);
    bindings.set(key, bound);
    const notes: string[] = [];
    try {
      for (const ret of returns) {
        const expr = ret.namedChildren.find((c): c is Node => c !== null) ?? null;
        if (!expr) return null;
        const why = valueIsConstant(expr, method, depth + 1);
        if (!why) return null;
        notes.push(...why);
      }
    } finally {
      bindings.delete(key);
    }
    if (used.length === 0) {
      return [`the helper ${typeName}.${methodName}()${where} on line ${lineOf(method)} returns a fixed literal on every path`];
    }
    return [
      `the helper ${typeName}.${methodName}()${where} on line ${lineOf(method)} returns only literals and ` +
        `its parameter${used.length === 1 ? '' : 's'} ${used.map((u) => `\`${u}\``).join(', ')}, never written inside it`,
      ...notes,
    ];
  };

  /** Is this one live value fixed? Returns the notes that justify it, or null. */
  const valueIsConstant = (v: Node, body: Node, depth: number): string[] | null => {
    const values = liveValues(v, body, 0);
    if (!values) return null;
    const notes: string[] = values.note ? [values.note] : [];
    for (const raw of values.nodes) {
      if (isPlainLiteral(raw, language)) continue;
      /*
       * `(String) map.get("keyA")` or `list.get(1)` - a read from a local map or
       * list whose every write is on the page (taint/local-map.ts) is the value
       * stored there. The cast is looked through first; it changes the type,
       * not the value.
       */
      let each = raw;
      while (each.type === 'cast_expression' || each.type === 'parenthesized_expression') {
        each = each.childForFieldName('value') ?? each.namedChildren[each.namedChildren.length - 1] ?? each;
        if (each === raw) break;
      }
      const read = resolveContainerRead(each, language);
      if (read) {
        const where =
          `\`${each.text.replace(/\s+/g, ' ')}\` on line ${lineOf(each)} returns what was stored at ` +
          `${read.selector} on line ${lineOf(read.write)} - the collection is local, handed to nothing, ` +
          `and written only by straight-line statements`;
        if (isPlainLiteral(read.value, language)) {
          notes.push(where.replace('returns what was stored', 'returns the literal stored'));
          continue;
        }
        /*
         * A NAME was stored - `map.put("keyB", param)`. Its value is judged
         * where it was stored, not where it is read: the map holds what the
         * name held then (ContainerHeldValue.java). Only for a type that cannot
         * change in place, or an alias could change the stored object later.
         */
        const fn = enclosingMethod(each);
        const stored = read.value.text ?? '';
        if (read.value.type !== 'identifier' || !fn || !declaredImmutable(fn, stored)) return null;
        const inner = nameIsConstant(stored, read.value, depth);
        if (!inner) return null;
        notes.push(...inner, `${where}, and \`${stored}\` was fixed when stored`);
        continue;
      }
      /*
       * `"cmd.exe /c " + append + " "` - pieces joined with `+` are as fixed as
       * the pieces. Only `+`, only where it joins strings (C's is pointer
       * arithmetic, PHP's is `.`), and every piece judged by these same rules.
       */
      if (CONCATENATING.has(language) && CONCAT_NODES.has(each.type) && each.childForFieldName('operator')?.text === '+') {
        const left = each.childForFieldName('left');
        const right = each.childForFieldName('right');
        const l = left ? valueIsConstant(left, body, depth) : null;
        const r = l && right ? valueIsConstant(right, body, depth) : null;
        if (!l || !r) return null;
        notes.push(...l, ...r);
        continue;
      }
      if (/^[A-Za-z_$][\w$]*$/.test((each.text ?? '').trim()) && each.namedChildren.length === 0) {
        const inner = nameIsConstant((each.text ?? '').trim(), each, depth);
        if (!inner) return null;
        notes.push(...inner);
        continue;
      }
      const helper = helperReturnsConstant(each, depth);
      if (!helper) return null;
      notes.push(...helper);
    }
    return notes;
  };

  /*
   * THE CYCLE GUARD, BECAUSE THIS PROJECT HAS ALREADY PAID FOR NOT HAVING ONE.
   *
   * A value can be another name - `bar = baz` - so resolving a name can land on
   * a name, and `a = b; b = a` is a loop. The tracer's folder had exactly this
   * shape with no guard, and DVWA's packed sha256 turned it into an
   * out-of-memory on a 10KB file. A name already being resolved answers "not
   * provable", which is the direction that keeps the finding.
   */
  const resolving = new Set<string>();

  /** Is every live write to `part`, as seen from `anchor`, a fixed value? */
  const nameIsConstant = (part: string, anchor: Node, depth: number): string[] | null => {
    const scopes = enclosingScopes(anchor);
    const body = scopes[0];
    if (!body) return null;
    const key = `${spanKey(body)}#${part}`;
    if (resolving.has(key) || resolving.size > 24) return null;
    resolving.add(key);
    try {
      return resolveName(part, scopes, body, depth, anchor);
    } finally {
      resolving.delete(key);
    }
  };

  /** Node types that hold a plain sequence of statements, each run once, in order. */
  const STATEMENT_LISTS = new Set([
    'block', 'statement_block', 'compound_statement', 'constructor_body', 'statement_list',
    'program', 'module', 'source_file',
  ]);
  /** Wrappers between a write and the statement that holds it. */
  const STATEMENT_WRAPPERS = new Set([
    'expression_statement', 'local_variable_declaration', 'lexical_declaration', 'variable_declaration',
  ]);

  /** The write that certainly decides the value at `anchor`, if one does. See resolveName. */
  const certainLastWrite = (
    writes: ReadonlyArray<{ node: Node; value: Node; scope: Node }>,
    anchor: Node,
  ): { node: Node; value: Node } | null => {
    if (language === 'c' || language === 'cpp' || writes.length === 0) return null;
    const innermost = enclosingScopes(anchor)[0];
    if (!innermost || writes.some((w) => !sameSpan(w.scope, innermost))) return null;
    const last = [...writes].sort((a, b) => a.node.startIndex - b.node.startIndex)[writes.length - 1];
    if (!last || last.node.endIndex > anchor.startIndex) return null;
    let statement: Node = last.node;
    while (statement.parent && STATEMENT_WRAPPERS.has(statement.parent.type)) statement = statement.parent;
    const holder = statement.parent;
    if (!holder || !STATEMENT_LISTS.has(holder.type) || !contains(holder, anchor)) return null;
    return last;
  };

  const resolveName = (
    part: string,
    scopes: Node[],
    body: Node,
    depth: number,
    anchor: Node,
  ): string[] | null => {

    let live = 0;
    let fixed = true;
    const notes: string[] = [];

    /* Every plain write, in every scope, before any value is judged. */
    const writes: Array<{ node: Node; value: Node; scope: Node }> = [];
    /* Every declaration of the name the same walk passes - with a value or without. */
    const declarations: Array<{ node: Node; scope: Node }> = [];
    for (const scope of scopes) {
      if (parameterNames(scope).has(part)) {
        /*
         * A parameter is input - unless this is a helper being read for one
         * particular call (helperReturnsConstant), and then it is whatever that
         * call passes. Only if the helper never writes to it: `a = b;` would
         * make the literal passed for `a` irrelevant.
         */
        const bound = bindings.get(spanKey(scope))?.get(part);
        if (!bound) return null;
        const f = folderOf(scope);
        if (f.writtenOtherwise(part, scope) || f.plainWriteCount(part, scope) > 0) return null;
        return bound();
      }
      /*
       * A write this walk does not recognise - `bar, err := f()`, `[bar] = x`,
       * `bar += param` in Python, `for bar in ...` - would leave only the literal
       * writes visible, and the proof would call a tainted value constant. The
       * folder's survey sees every form of write; any irregular one ends this.
       */
      if (folderOf(scope).writtenOtherwise(part, scope)) return null;
      const collect = (n: Node | null): void => {
        if (!n) return;
        if (n !== scope && SCOPE_NODES.has(n.type)) return;
        const fields = BINDING_NODES[n.type];
        if (fields && (n.childForFieldName(fields.name)?.text ?? '').trim() === part) {
          const value = n.childForFieldName(fields.value);
          if (value) writes.push({ node: n, value, scope });
        }
        if (DECLARATION_NODES.has(n.type) && (n.childForFieldName(n.type === 'short_var_declaration' ? 'left' : 'name')?.text ?? '').trim() === part) {
          declarations.push({ node: n, scope });
        }
        for (const child of n.namedChildren) collect(child ?? null);
      };
      collect(scope);
    }
    /*
     * A WRITE INSIDE A CLOSURE is a write this walk does not see - it stops at
     * nested functions on purpose - and `let bar = "x"; const set = () => {
     * bar = req.query.q; }; set();` would read as constant. The folder's survey
     * walks nested functions too; if it counts more writes here than this walk
     * did, one of them is hidden in a closure, and nothing is proved.
     */
    const innermost = scopes[0];
    if (innermost && folderOf(innermost).plainWriteCount(part, innermost) > writes.filter((w) => w.scope === innermost).length) {
      return null;
    }

    let outerBound = writes.some((w) => innermost && !sameSpan(w.scope, innermost));

    /*
     * JAVA SCOPING. The walk above collects every declaration of the name in
     * the scopes around the read - and Java's scopes are smaller than that.
     * Each probe in tests/probes/p15-p24 was a constant declaration the read
     * could not see, standing in for one it could:
     *
     *   - a local is visible from its declaration to the end of its block, so
     *     one in another block (p17), one declared after the read (p18), one
     *     inside a lambda (p22) and a field of a nested or local class (p19,
     *     p23, p24) are somebody else's - and any of those ends the proof;
     *   - a lambda parameter or a pattern variable of the same name can shadow
     *     the declaration found, and the walk does not collect them (p15, p16);
     *   - a class between the declaration and the read that inherits from
     *     anything can inherit a field of the same name, which then wins (p20,
     *     p21);
     *   - a field counts only if it is private or final, read from the
     *     modifier TOKENS - the word in `@SuppressWarnings("private")`, or a
     *     `final` inside a comment, is not a modifier (p13, p14) - since any
     *     other class can assign one that is neither;
     *   - no declaration in view at all - an inherited field, a static import -
     *     is nothing this proof can read.
     */
    if (language === 'java') {
      if (boundElsewhere(rootOf(anchor), part)) return null;
      if (declarations.length === 0) return null;
      let local = false;
      for (const { node: declarator } of declarations) {
        const visible = declarationVisibility(declarator, language);
        if (!visible || !contains(visible.region, anchor) || anchor.startIndex < visible.from) return null;
        if (enclosingClassLikes(anchor).some((c) => contains(visible.region, c) && supertypesOf(c).length > 0)) {
          return null;
        }
        const holder = declarator.parent;
        if (holder?.type === 'local_variable_declaration') local = true;
        else if (holder?.type === 'field_declaration' && !hasModifier(holder, 'private') && !hasModifier(holder, 'final')) {
          return null;
        }
      }
      /*
       * A write inside a class nested in this code - a local or anonymous
       * class, a record's constructor, an initializer block - runs as THAT
       * class's code, where every name around it may mean something else:
       * `if (dbg) cmd = ...` inside a record reads the record's own `dbg`
       * (tests/probes/j09, j10). Its branches cannot be decided from here, so
       * such a write ends the proof.
       */
      if (writes.some((w) => enclosingClassLikes(w.node).some((c) => !contains(c, anchor)))) return null;
      if (!local) outerBound = true;
    } else if (language === 'javascript' || language === 'typescript' || language === 'go') {
      /*
       * The same visibility rule as Java's, by these languages' own scoping:
       * every declaration found must be one the read can see (a block's
       * `let`, a `for` header's, a Go block's `:=` - s02, s03, s05, s06, g05),
       * and there must be one: a name declared nowhere in view is an import,
       * another script's global or another file's package variable (s04, g04).
       */
      if (language === 'go' && goBindsOtherwise(rootOf(anchor), part)) return null;
      if (declarations.length === 0) return null;
      for (const { node: declarator } of declarations) {
        const visible = declarationVisibility(declarator, language);
        if (!visible || !contains(visible.region, anchor) || anchor.startIndex < visible.from) return null;
      }
      // Not declared in the reading function: it belongs to a scope outside,
      // where any other function can assign it - with or without a write of
      // its own in view.
      if (!declarations.some((d) => innermost && sameSpan(d.scope, innermost))) outerBound = true;
    }

    /*
     * A NAME BOUND OUTSIDE THIS FUNCTION CAN BE WRITTEN BY ANY OTHER ONE.
     *
     *     static String table = "users";
     *     void setTable(HttpServletRequest r) { table = r.getParameter("t"); }
     *     void list(Statement s) { s.execute("SELECT * FROM " + table); }
     *
     * The walk above does not enter other functions - on purpose, because a
     * sibling's OWN local of the same name is irrelevant (const-interp.py). But
     * `table` here is not anybody's local: it is a field, and setTable writes
     * it. The walk saw only "users" and called the query constant. So for a
     * name bound outside the reading function, every function inside the scope
     * that holds it is searched too, and any write not already judged ends the
     * proof - a sibling's same-named local included, which costs a little
     * precision and never a finding. OuterWriteFence.* has each shape.
     *
     * Python and PHP are left out on purpose: a plain assignment inside a
     * function makes a NEW local there, and reaching the outer name takes a
     * `global` (or `nonlocal`) statement - which the survey above already
     * treats as an irregular write.
     */
    if (outerBound && language !== 'python' && language !== 'php') {
      const holding = [...declarations.map((d) => d.scope), ...writes.map((w) => w.scope)];
      const declaring =
        (holding.length > 0 && innermost && holding.every((h) => sameSpan(h, innermost))
          ? scopes[scopes.length - 1]
          : [...scopes].reverse().find((s) => holding.some((h) => sameSpan(h, s)))) ?? scopes[scopes.length - 1];
      if (!declaring) return null;
      const folder = folderOf(declaring);
      if (folder.writtenOtherwise(part, declaring) || folder.plainWriteCount(part, declaring) > writes.length) return null;
    }

    /*
     * THE LAST CERTAIN WRITE.
     *
     *     bar = (String) map.get("keyB");   // the request parameter
     *     bar = (String) map.get("keyA");   // a literal
     *     sql = "... " + bar;
     *
     * Every write to `bar` used to have to be a literal, so the dirty one above
     * - overwritten one line later - sank the proof. When one write is certain
     * to run after all the others and before the read, it is the only one that
     * matters. Certain means: it is a statement directly in a block that holds
     * the read, it comes before the read, and NO write to the name comes after
     * it anywhere in the function - so no loop can bring an earlier or later
     * value round again. Not attempted in C or C++, where a declaration in an
     * inner block can shadow the name without this walk seeing a write.
     */
    // Only for a name local to the reading function: a call between the last
    // write and the read can change a field, or a variable another function
    // shares.
    // A `goto` can jump over the last write (tests/probes/g01).
    const jumps = !!innermost && innermost.descendantsOfType('goto_statement').length > 0;
    const last = outerBound || jumps ? null : certainLastWrite(writes, anchor);
    if (last) {
      const why = valueIsConstant(last.value, body, depth);
      if (!why) return null;
      return [
        ...why,
        `the value at line ${lineOf(anchor)} is the one written on line ${lineOf(last.node)}, which ` +
          `overwrites every earlier write and is never overwritten itself`,
      ];
    }

    /*
     * A FIELD OUTLIVES THE CALL. Inside a helper read for one call, a parameter
     * means what THAT call passes - but a field written from a parameter, `f =
     * v`, holds what whichever call ran LAST passed: `swap(tainted);
     * swap("x")` returns the tainted value, and a lazy cache keeps the first
     * call's (tests/probes/r3-a04, r3-a05, r3-a09, r3-z-scope-static-swap). So
     * a name bound outside the reading function is judged with no parameter
     * bound, and a parameter written into it is input.
     */
    const suspended = outerBound && bindings.size > 0 ? new Map(bindings) : null;
    if (suspended) bindings.clear();
    try {
      for (const scope of scopes) {
        const walk = (n: Node | null): void => {
          if (!n || !fixed) return;
          // Do NOT descend into a nested scope. Searching the module body walked
          // straight into sibling functions, so an unrelated `t = request.args...`
          // three functions away made a genuinely constant `t` here look tainted.
          if (n !== scope && SCOPE_NODES.has(n.type)) return;
          const fields = BINDING_NODES[n.type];
          if (fields) {
            const target = n.childForFieldName(fields.name);
            if ((target?.text ?? '').trim() === part) {
              const value = n.childForFieldName(fields.value);
              if (value) {
                const deadIf = deadArmHolding(n, scope, body);
                if (deadIf) {
                  notes.push(`the write on line ${lineOf(n)} ${deadIf.why}`);
                } else {
                  live++;
                  const why = valueIsConstant(value, body, depth);
                  if (!why) fixed = false;
                  else notes.push(...why);
                }
              }
            }
          }
          for (const child of n.namedChildren) walk(child ?? null);
        };
        walk(scope);
      }
    } finally {
      if (suspended) for (const [k, v] of suspended) bindings.set(k, v);
    }

    // No live write means we cannot see where it comes from - so we do not get
    // to call it constant.
    if (live === 0 || !fixed) return null;
    return notes;
  };

  let reasoned = false;
  const reasons: string[] = [];
  for (const raw of dynamicParts) {
    const part = raw.trim();
    // Only a bare name can be resolved this cheaply. Anything with a call, an
    // index or an attribute access is left alone.
    if (!/^[A-Za-z_$][\w$]*$/.test(part)) return null;
    const notes = nameIsConstant(part, node, 0);
    if (!notes) return null;
    if (notes.length > 0) {
      reasoned = true;
      reasons.push(`\`${part}\`: ${[...new Set(notes)].join('; ')}`);
    }
  }

  return {
    reasoned,
    reason: reasoned
      ? `Every value that can be spliced in is a fixed literal on every path that runs. ${reasons.join('. ')}.`
      : 'Every value spliced in is bound only to plain literals.',
  };
}

/** The boolean form, for callers that only need a yes or a no. */
export function partsAreProvablyConstant(
  node: Node,
  dynamicParts: readonly string[],
  language: LanguageId,
): boolean {
  return constantProof(node, dynamicParts, language) !== null;
}
