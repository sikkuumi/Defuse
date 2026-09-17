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
